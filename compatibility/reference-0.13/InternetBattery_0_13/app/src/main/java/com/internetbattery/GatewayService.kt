package com.internetbattery

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.internetbattery.gateway.Socks5Gateway
import com.internetbattery.gateway.SessionAuthorizer
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket

/** Foreground gateway; only binds to the P2P group-owner IPv4 address. */
class GatewayService : Service() {
    private var gateway: Socks5Gateway? = null
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) { stopSelf(); return START_NOT_STICKY }
        if (intent?.action != ACTION_START) return START_NOT_STICKY
        startForeground(3001, notice("Ağ geçidi başlatılıyor"))
        val host = intent.getStringExtra(EXTRA_HOST).orEmpty()
        val secret = intent.getStringExtra(EXTRA_SECRET).orEmpty()
        val bindAddress = runCatching { InetAddress.getByName(host) }.getOrNull()
        if (bindAddress == null || secret.length < 16) {
            RuntimeStatus.update { it.copy(gatewayMessage="IP/şifre geçersiz") }
            stopSelf(); return START_NOT_STICKY
        }
        val network = outboundNetwork()
        if (network == null) {
            RuntimeStatus.update { it.copy(gatewayMessage="Doğrulanmış internet bağlantısı yok") }
            stopSelf(); return START_NOT_STICKY
        }
        val gatewayId=intent.getStringExtra(EXTRA_GATEWAY_ID).orEmpty()
        val issuerKey=intent.getStringExtra(EXTRA_ISSUER_KEY).orEmpty()
        val voucherMode=gatewayId.isNotBlank() || issuerKey.isNotBlank()
        val signedAuthorizer: SessionAuthorizer?=if (voucherMode) {
            val authorized=runCatching { VoucherGatewayProvision.authorize(this,gatewayId,issuerKey) }
            if (authorized.isFailure) {
                RuntimeStatus.update { it.copy(gatewayMessage="Voucher yapılandırması reddedildi: ${authorized.exceptionOrNull()?.message}") }
                stopSelf();return START_NOT_STICKY
            }
            authorized.getOrNull()
        } else null
        gateway?.close()
        RuntimeStatus.update { it.copy(upstreamBytes=0,downstreamBytes=0,lastSessionBytes=0) }
        gateway = Socks5Gateway(
            listenAddress=bindAddress, password=secret,
            sessionAuthorizer=signedAuthorizer,
            tcpFactory={ network.socketFactory.createSocket() },
            udpFactory={ DatagramSocket().also { network.bindSocket(it) } },
            resolveHost={ name -> network.getAllByName(name) },
            onLog={ msg -> RuntimeStatus.update { it.copy(gatewayMessage=msg) } },
            onBytes={ _, _ -> gateway?.let { g ->
                RuntimeStatus.update { it.copy(upstreamBytes=g.upstreamBytes.get(),downstreamBytes=g.downstreamBytes.get()) }
            } },
            onSessionCompleted={ session ->
                // Actual completed relay bytes, NOT redeemable credit until independently verified.
                RuntimeStatus.update { it.copy(lastSessionBytes=session.upstreamBytes+session.downstreamBytes) }
            }
        )
        if (gateway?.start() != true) { stopSelf(); return START_NOT_STICKY }
        RuntimeStatus.update { it.copy(gatewayActive=true,gatewayIp=host,gatewaySecret=if(voucherMode) "" else secret,
            gatewayMessage=if(voucherMode) "İmzalı kota zorunlu: $host:8888 ($gatewayId)" else "Gateway çalışıyor: $host:8888") }
        return START_NOT_STICKY
    }

    private fun outboundNetwork(): Network? {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val usable = cm.allNetworks.filter { n ->
            cm.getNetworkCapabilities(n)?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        }
        return usable.firstOrNull { n -> cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)==true }
            ?: usable.firstOrNull { n -> cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)==true }
    }

    private fun notice(text: String): Notification {
        val pi = PendingIntent.getActivity(this,0,Intent(this,MainActivity::class.java),PendingIntent.FLAG_IMMUTABLE)
        return NotificationCompat.Builder(this,InternetBatteryApplication.CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setContentTitle("Internet Battery — Gateway")
            .setContentText(text).setContentIntent(pi).setOngoing(true).build()
    }

    override fun onDestroy() {
        gateway?.close(); gateway = null
        RuntimeStatus.update { it.copy(gatewayActive=false,gatewaySecret="",gatewayMessage="Gateway durduruldu") }
        super.onDestroy()
    }

    companion object {
        private const val ACTION_START="com.internetbattery.GATEWAY_START"
        private const val ACTION_STOP="com.internetbattery.GATEWAY_STOP"
        private const val EXTRA_HOST="gateway_host"
        private const val EXTRA_SECRET="gateway_secret"
        private const val EXTRA_GATEWAY_ID="voucher_gateway_id"
        private const val EXTRA_ISSUER_KEY="voucher_issuer_pub"
        fun start(context:Context,host:String,secret:String,gatewayId:String="",issuerKey:String="") {
            val i=Intent(context,GatewayService::class.java).apply {
                action=ACTION_START;putExtra(EXTRA_HOST,host);putExtra(EXTRA_SECRET,secret)
                putExtra(EXTRA_GATEWAY_ID,gatewayId);putExtra(EXTRA_ISSUER_KEY,issuerKey)
            }
            ContextCompat.startForegroundService(context,i)
        }
        fun stop(context:Context) { context.startService(Intent(context,GatewayService::class.java).apply {action=ACTION_STOP}) }
    }
}
