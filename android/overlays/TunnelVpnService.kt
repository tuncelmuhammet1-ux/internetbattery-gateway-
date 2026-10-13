package com.internetbattery

import android.app.Notification
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.IpPrefix
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.net.Inet4Address
import java.net.InetAddress
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/** Experimental client-side VPN: starts only after gateway HTTPS preflight succeeds. */
class TunnelVpnService : VpnService() {
    private val scope=CoroutineScope(Dispatchers.IO+Job())
    private var tunnelFd: ParcelFileDescriptor?=null
    private var native: HevEngine?=null
    private var bridge: WssSocksBridge?=null
    override fun onBind(intent: Intent?) = super.onBind(intent)

    override fun onStartCommand(intent: Intent?, flags:Int, startId:Int): Int {
        if (intent?.action==ACTION_STOP) { stopSelf();return START_NOT_STICKY }
        if (intent?.action!=ACTION_START) return START_NOT_STICKY
        startForeground(3002, notice("HTTPS ön kontrolü yapılıyor"))
        RuntimeStatus.update { it.copy(vpnHttpsVerified=false,vpnEngineActive=false,
            vpnIpv6RouteConfigured=false, vpnMessage="SOCKS ve VPN testi başlatılıyor") }
        val ip=intent.getStringExtra(EXTRA_HOST).orEmpty()
        val secret=intent.getStringExtra(EXTRA_SECRET).orEmpty()
        val username=intent.getStringExtra(EXTRA_USER).orEmpty().ifBlank { "ib" }
        val voucher=intent.getStringExtra(EXTRA_VOUCHER).orEmpty()
        if(ip.startsWith("wss://")) {
            beginRemoteWss(ip,secret,username,voucher)
            return START_NOT_STICKY
        }
        val address=runCatching { InetAddress.getByName(ip) }.getOrNull()
        if (address !is Inet4Address || ip!=address.hostAddress || secret.length<16) {
            RuntimeStatus.update { it.copy(vpnMessage="Geçersiz gateway IP/şifre") }
            stopSelf();return START_NOT_STICKY
        }
        scope.launch {
            val checked=ProxyConnectivityProbe.test(ip,8888,secret,username)
            if (checked.isFailure) {
                RuntimeStatus.update { it.copy(vpnMessage="Proxy HTTPS testi geçmedi: ${checked.exceptionOrNull()?.message}") }
                stopSelf();return@launch
            }
            RuntimeStatus.update { it.copy(vpnMessage="Gateway HTTPS kontrolü geçti; TUN başlatılıyor") }
            try {
                // Full-tunnel routes for BOTH address families: native tun2socks
                // supports IPv4/IPv6; UDP carries DNS and QUIC if upstream supports it.
                // Do NOT let IPv6 bypass the VPN to cellular when the gateway lacks v6.
                val builder=Builder().setSession("Internet Battery (deneysel)")
                    .setMtu(1500)
                    .addAddress(FullTunnelRoutes.CLIENT_IPV4,FullTunnelRoutes.IPV4_CIDR)
                    .addRoute(FullTunnelRoutes.ROUTE_IPV4,FullTunnelRoutes.IPV4_DEFAULT_PREFIX)
                    .addAddress(FullTunnelRoutes.CLIENT_IPV6,FullTunnelRoutes.IPV6_CIDR)
                    .addRoute(FullTunnelRoutes.ROUTE_IPV6,FullTunnelRoutes.IPV6_DEFAULT_PREFIX)
                    .addDnsServer(FullTunnelRoutes.DNS_IPV4)
                    .addDnsServer(FullTunnelRoutes.DNS_IPV6)
                    .setBlocking(true)
                // Explicit route exclusion prevents the native proxy socket from looping
                // into the VPN. On Android 13+ excludeRoute is available (minSdk=33).
                builder.excludeRoute(IpPrefix(address,32))
                tunnelFd=builder.establish() ?: error("VPN kullanıcı izni veya TUN kurulumu başarısız")
                RuntimeStatus.update { it.copy(vpnIpv6RouteConfigured=true) }
                native=HevEngine(this@TunnelVpnService) { msg -> RuntimeStatus.update { it.copy(vpnMessage=msg) } }
                native!!.start(tunnelFd!!.fd,ip,8888,secret,username)
                var tries=0
                while (tries++<12 && native?.isRunning()!=true) delay(500)
                if (native?.isRunning()!=true) error("Native motor çalışmıyor; AAR sınıfı/API doğrulanmalı")
                RuntimeStatus.update { it.copy(vpnEngineActive=true,vpnMessage="Native VPN aktif; HTTPS doğrulanıyor...") }
                val initial=native?.stats()
                // REQUIRE the Android VPN Network for the validation request.
                // A default URL.openConnection() could succeed over cellular or
                // another Wi-Fi, falsely reporting that this VPN carries traffic.
                val connectivity = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val vpnNetwork = connectivity.allNetworks.firstOrNull { candidate ->
                    connectivity.getNetworkCapabilities(candidate)
                        ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
                }
                val httpsStatus = if (vpnNetwork == null) null else runCatching {
                    val c=vpnNetwork.openConnection(URL("https://example.com/")) as HttpsURLConnection
                    c.connectTimeout=8000;c.readTimeout=8000
                    try { c.responseCode } finally { c.disconnect() }
                }.getOrNull()
                val final=native?.stats()
                val verified=TunnelEvidence.isVerified(vpnNetwork != null, httpsStatus, initial, final)
                RuntimeStatus.update { it.copy(vpnHttpsVerified=verified,
                    vpnMessage=if(verified) "VPN ağı üzerinden HTTPS yanıtı ve çift yönlü trafik sayaçları doğrulandı"
                    else "VPN ağına bağlı HTTPS + çift yönlü sayaç doğrulanamadı; gerçek erişim ilan edilmiyor") }
                while (native?.isRunning()==true) {
                    val stats=native?.stats()
                    if (stats != null && stats.size >= 4) {
                        RuntimeStatus.update { it.copy(vpnUpBytes=stats[1],vpnDownBytes=stats[3]) }
                    }
                    delay(2000)
                }
                RuntimeStatus.update { it.copy(vpnEngineActive=false,vpnHttpsVerified=false,vpnMessage="Native motor durdu") }
                stopSelf()
            } catch (e:Throwable) {
                RuntimeStatus.update { it.copy(vpnMessage="VPN hatası: ${e.message}",vpnEngineActive=false,vpnHttpsVerified=false) }
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }


    /** LAB PILOT: only this app uses VPN while we verify native TCP/WSS/HTTPS.
     * Remove the app allowlist only after full-device traffic tests pass.
     * HTTPS preflight and VPN evidence remain separate gates. */
    private fun beginRemoteWss(url:String,key:String,deviceId:String,voucher:String) {
        scope.launch {
            try {
                val cm=getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val underlying=cm.activeNetwork ?: error("Mobil veya Wi-Fi erişim ağı yok")
                val localPassword=ByteArray(24).also { java.security.SecureRandom().nextBytes(it) }
                    .joinToString(""){"%02x".format(it.toInt() and 255)}
                if(voucher.isNotBlank()) Ib1VoucherInput.decode(voucher,deviceId)
                val relay=WssSocksBridge(
                    this@TunnelVpnService,underlying,url,deviceId,key,localPassword,
                    onStatus={ msg->RuntimeStatus.update { state->state.copy(vpnMessage=msg) } },
                    voucher=voucher
                )
                bridge=relay
                relay.start()
                RuntimeStatus.update { it.copy(vpnMessage="Uzak WSS geçidi doğrulanıyor; bu VPN testi değildir") }
                if(!relay.probe())error("Uzak geçit DNS/kimlik doğrulaması başarısız")
                val builder=Builder().setSession("Internet Battery WSS (laboratuvar)")
                    .setMtu(1500)
                    .addAddress(FullTunnelRoutes.CLIENT_IPV4,FullTunnelRoutes.IPV4_CIDR)
                    .addRoute(FullTunnelRoutes.ROUTE_IPV4,FullTunnelRoutes.IPV4_DEFAULT_PREFIX)
                    .addAddress(FullTunnelRoutes.CLIENT_IPV6,FullTunnelRoutes.IPV6_CIDR)
                    .addRoute(FullTunnelRoutes.ROUTE_IPV6,FullTunnelRoutes.IPV6_DEFAULT_PREFIX)
                    .addDnsServer(FullTunnelRoutes.DNS_IPV4)
                    .addDnsServer(FullTunnelRoutes.DNS_IPV6)
                    .setBlocking(true)
                    .setUnderlyingNetworks(arrayOf(underlying))
                    // LAB PILOT ONLY: isolate unrelated apps until full-device traffic is verified.
                    .addAllowedApplication(packageName)
                // Loopback SOCKS5 remains local. Android rejects loopback route exclusions.
                tunnelFd=builder.establish()?:error("VPN kullanıcı izni veya TUN kurulumu başarısız")
                RuntimeStatus.update { it.copy(vpnIpv6RouteConfigured=true) }
                native=HevEngine(this@TunnelVpnService){msg->
                    RuntimeStatus.update { it.copy(vpnMessage=msg) }
                }
                native!!.start(tunnelFd!!.fd,"127.0.0.1",relay.port,localPassword,"ib")
                var count=0
                while(count++<14 && native?.isRunning()!=true)delay(500)
                if(native?.isRunning()!=true)error("Native TUN motoru başlatılamadı")
                RuntimeStatus.update { it.copy(vpnEngineActive=true,
                    vpnMessage="WSS üzerinden VPN açıldı; HTTP/UDP/DNS ve çift yönlü trafik doğrulanıyor") }
                val initial=native?.stats()
                val vpnNetwork=cm.allNetworks.firstOrNull { candidate->
                    cm.getNetworkCapabilities(candidate)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)==true
                }
                val code=if(vpnNetwork==null)null else runCatching {
                    val c=vpnNetwork.openConnection(URL("https://example.com/")) as HttpsURLConnection
                    c.connectTimeout=10000;c.readTimeout=10000
                    try{c.responseCode}finally{c.disconnect()}
                }.getOrNull()
                val after=native?.stats()
                val verified=TunnelEvidence.isVerified(vpnNetwork!=null,code,initial,after)
                RuntimeStatus.update { it.copy(vpnHttpsVerified=verified,
                    vpnMessage=if(verified)
                        "Uzak WSS VPN üzerinden gerçek HTTPS + çift yönlü sayaç doğrulandı; UDP/QUIC ve tüm uygulamalar ayrıca test edilmeli"
                    else
                        "Uzak WSS erişimi veya VPN çift yönlü HTTPS kanıtı yok; internet çalışıyor ilan edilmiyor") }
                if(!verified) {
                    // Avoid trapping the user's phone in an unverified tunnel.
                    delay(1000)
                    stopSelf()
                    return@launch
                }
                while(native?.isRunning()==true){
                    val stats=native?.stats()
                    if(stats!=null && stats.size>=4) {
                        RuntimeStatus.update { it.copy(vpnUpBytes=stats[1],vpnDownBytes=stats[3]) }
                    }
                    delay(2000)
                }
                RuntimeStatus.update { it.copy(vpnEngineActive=false,vpnHttpsVerified=false,
                    vpnMessage="Uzak WSS VPN motoru durdu") }
                stopSelf()
            }catch(e:Exception){
                RuntimeStatus.update { it.copy(vpnMessage="Uzak WSS VPN hatası: "+e.message,
                    vpnEngineActive=false,vpnHttpsVerified=false) }
                stopSelf()
            }
        }
    }
    private fun notice(text:String):Notification {
        val pi=PendingIntent.getActivity(this,0,Intent(this,MainActivity::class.java),PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this,InternetBatteryApplication.CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .setContentTitle("Internet Battery — VPN")
            .setContentText(text).setContentIntent(pi).setOngoing(true).build()
    }
    override fun onRevoke() { stopSelf();super.onRevoke() }
    override fun onDestroy() {
        native?.stop();native=null
        bridge?.close();bridge=null
        tunnelFd?.close();tunnelFd=null
        scope.cancel()
        RuntimeStatus.update { it.copy(vpnEngineActive=false,vpnHttpsVerified=false,
            vpnIpv6RouteConfigured=false) }
        super.onDestroy()
    }
    companion object {
        private const val ACTION_START="com.internetbattery.VPN_START"
        private const val ACTION_STOP="com.internetbattery.VPN_STOP"
        private const val EXTRA_HOST="proxy_ip"
        private const val EXTRA_SECRET="proxy_token"
        private const val EXTRA_USER="proxy_username"
        private const val EXTRA_VOUCHER="roam_ib1_token"
        fun start(context:Context,host:String,secret:String,username:String="ib",voucher:String="") {
            val i=Intent(context,TunnelVpnService::class.java).apply {
                action=ACTION_START;putExtra(EXTRA_HOST,host);putExtra(EXTRA_SECRET,secret)
                putExtra(EXTRA_USER,username)
                putExtra(EXTRA_VOUCHER,voucher)
            }
            ContextCompat.startForegroundService(context,i)
        }
        fun stop(context:Context) {
            context.startService(Intent(context,TunnelVpnService::class.java).apply {action=ACTION_STOP})
        }
    }
}
