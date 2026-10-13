package com.internetbattery

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.viewinterop.AndroidView
import android.webkit.WebView
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.security.SecureRandom
import java.util.Locale

class MainActivity : ComponentActivity() {
    private lateinit var p2p: WifiP2pController
    private var vpnPendingHost=""
    private var vpnPendingSecret=""
    private var vpnPendingUser="ib"
    private var vpnPendingVoucher=""
    private val permissions=registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { }
    private val vpnConsent=registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode==Activity.RESULT_OK) TunnelVpnService.start(this,vpnPendingHost,vpnPendingSecret,vpnPendingUser,vpnPendingVoucher)
        else RuntimeStatus.update { it.copy(vpnMessage="VPN izni verilmedi") }
    }

    override fun onCreate(savedInstanceState:Bundle?) {
        super.onCreate(savedInstanceState)
        p2p=WifiP2pController(applicationContext)
        askPermissions()
        setContent {
            MaterialTheme(colorScheme=darkColorScheme()) {
                BatteryUi(
                    p2p=p2p,
                    vault=remember { OfflineVault(applicationContext) },
                    onVpnStart={host,secret,user,voucher -> beginVpn(host,secret,user,voucher)},
                    onGatewayStart={ip,secret,gatewayId,issuerKey -> GatewayService.start(this,ip,secret,gatewayId,issuerKey)},
                    onGatewayStop={GatewayService.stop(this)},
                    onVpnStop={TunnelVpnService.stop(this)},
                )
            }
        }
    }

    private fun askPermissions() {
        permissions.launch(arrayOf(
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.NEARBY_WIFI_DEVICES,
            Manifest.permission.POST_NOTIFICATIONS
        ))
    }

    private fun beginVpn(host:String,secret:String,user:String,voucher:String) {
        if (secret.length !in 16..255 || host.isBlank() || user.isBlank()) {
            RuntimeStatus.update { it.copy(vpnMessage="Önce gateway IP ve 16+ karakter eşleştirme kodu gir") }
            return
        }
        vpnPendingHost=host;vpnPendingSecret=secret;vpnPendingUser=user;vpnPendingVoucher=voucher
        val intent=VpnService.prepare(this)
        if (intent==null) TunnelVpnService.start(this,host,secret,user,voucher) else vpnConsent.launch(intent)
    }

    override fun onDestroy() { p2p.close();super.onDestroy() }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun BatteryUi(
    p2p: WifiP2pController,
    vault: OfflineVault,
    onVpnStart:(String,String,String,String)->Unit,
    onGatewayStart:(String,String,String,String)->Unit,
    onGatewayStop:()->Unit,
    onVpnStop:()->Unit,
) {
    val peer by p2p.state.collectAsState()
    val live by RuntimeStatus.state.collectAsState()
    var screen by remember { mutableIntStateOf(0) }
    val scope= rememberCoroutineScope()
    val ctx=androidx.compose.ui.platform.LocalContext.current
    var online by remember { mutableStateOf(false) }
    var wifiOnline by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) {
        while (true) {
            val cm=ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val networks=cm.allNetworks.mapNotNull { cm.getNetworkCapabilities(it) }
            online=networks.any { it.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) }
            wifiOnline=networks.any { it.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) && it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) }
            delay(2000)
        }
    }
    Scaffold(
        topBar={ CenterAlignedTopAppBar(title={Text("🔋 INTERNET BATTERY 0.13",fontWeight=FontWeight.Black)}) },
        bottomBar={ NavigationBar {
            listOf("Bağlantı","Çevrimdışı","Testler").forEachIndexed { index,name ->
                NavigationBarItem(selected=screen==index,onClick={screen=index},
                    icon={Text(listOf("📡","📚","🧪")[index])},label={Text(name)})
            }
        } }
    ) { pad ->
        Column(Modifier.fillMaxSize().padding(pad).padding(14.dp)) {
            when(screen) {
                0 -> ConnectionsUi(peer,live,p2p,online,onVpnStart,onGatewayStart,onGatewayStop,onVpnStop)
                1 -> OfflineUi(vault,wifiOnline,scope)
                else -> TestsUi(live,peer,online,scope)
            }
        }
    }
}

@Composable
private fun ConnectionsUi(
    peer: PeerState, live: RuntimeState, p2p: WifiP2pController, online:Boolean,
    onVpnStart:(String,String,String,String)->Unit,onGatewayStart:(String,String,String,String)->Unit,
    onGatewayStop:()->Unit,onVpnStop:()->Unit
) {
    val scope=rememberCoroutineScope()
    val clipboard=LocalClipboardManager.current
    val context=LocalContext.current
    var secret by remember { mutableStateOf(secureSecret()) }
    var clientSecret by remember { mutableStateOf("") }
    var clientUser by remember { mutableStateOf("ib") }
    var ib1Voucher by remember { mutableStateOf("") }
    var voucherMode by remember { mutableStateOf(false) }
    var gatewayId by remember { mutableStateOf("") }
    var issuerPublicKey by remember { mutableStateOf("") }
    var singlePhoneMode by rememberSaveable { mutableStateOf(true) }
    var proxyIp by remember { mutableStateOf("") }
    var probeResult by remember { mutableStateOf("") }
    var dnsProbeResult by remember { mutableStateOf("") }
    var remotePreflightPassed by remember { mutableStateOf(false) }
    LaunchedEffect(peer.ownerIp, singlePhoneMode) {
        // Wi-Fi Direct IP (e.g. a printer 192.168.49.1) is NOT an internet gateway.
        if (SinglePhoneRules.usePeerOwnerIp(singlePhoneMode,peer.ownerIp)) proxyIp=peer.ownerIp
    }
    LaunchedEffect(singlePhoneMode) {
        if (singlePhoneMode && proxyIp == "192.168.49.1") proxyIp=""
    }
    LaunchedEffect(proxyIp) { if(proxyIp.startsWith("wss://") && clientUser=="ib") clientUser="ib-pilot" }
    LaunchedEffect(proxyIp, clientUser, clientSecret, ib1Voucher, singlePhoneMode) {
        remotePreflightPassed=false
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()),verticalArrangement=Arrangement.spacedBy(10.dp)) {
        Text("Bağlantı yöntemi",fontWeight=FontWeight.Bold)
        Row(verticalAlignment=Alignment.CenterVertically) {
            RadioButton(selected=singlePhoneMode,onClick={singlePhoneMode=true})
            Text("Tek telefon · Uzak WSS ağ geçidi")
        }
        Row(verticalAlignment=Alignment.CenterVertically) {
            RadioButton(selected=!singlePhoneMode,onClick={singlePhoneMode=false})
            Text("İki telefon · Wi-Fi Direct (ayrı test)")
        }
        if (singlePhoneMode) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(14.dp),verticalArrangement=Arrangement.spacedBy(8.dp)) {
                    Text("Bu modda yazıcı veya ikinci telefon aramana gerek yok. Gerçek bir WSS sunucusu ve cihaza özel eşleştirme anahtarı gerekiyor.")
                    if (peer.connected) {
                        Text("Eski Wi-Fi Direct grubu aktif görünüyor. Bu, internet aküsü bağlantısı değildir.")
                        OutlinedButton(onClick={p2p.disconnect()},modifier=Modifier.fillMaxWidth()) {
                            Text("Eski Wi-Fi Direct grubundan ayrıl")
                        }
                    }
                }
            }
        }

        Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(14.dp)) {
            Text("Bağlantı durumu",fontWeight=FontWeight.Bold)
            Info("Dış internet doğrulaması", if(online) "İnternet var" else "Bağlantı yok")
            if (singlePhoneMode) {
                Info("Erişim modeli","Tek telefon / uzak ağ geçidi")
                Info("Wi-Fi Direct","Bu modda kullanılmıyor")
            } else {
                Info("Wi-Fi Direct",peer.status)
                Info("Grup sahibi IP",peer.ownerIp.ifBlank { "Henüz yok" })
            }
            Info("Gateway",if(live.gatewayActive) "Çalışıyor" else "Kapalı")
            Info("VPN motoru",if(live.vpnEngineActive) "Açık" else "Kapalı")
            Info("VPN HTTPS doğrulaması",if(live.vpnHttpsVerified) "Tünel test edildi" else "Doğrulanmadı")
            Info("IPv6 VPN rotası",if(live.vpnIpv6RouteConfigured) "Kuruldu (erişim testi gerekli)" else "Kapalı")
        } }
        if (SinglePhoneRules.showPeerDiscovery(singlePhoneMode)) {
        Text("1 • Yakındaki cihazları bağla",fontWeight=FontWeight.Bold)
        Row(horizontalArrangement=Arrangement.spacedBy(8.dp)) {
            Button(onClick={p2p.discover()},modifier=Modifier.weight(1f)) { Text("Cihaz ara") }
            OutlinedButton(onClick={p2p.createGroup()},modifier=Modifier.weight(1f)) { Text("Grup oluştur") }
        }
        peer.peers.filterNot { SinglePhoneRules.isPrinter(it.deviceName,it.primaryDeviceType) }.forEach { device ->
            OutlinedButton(onClick={p2p.connect(device)},modifier=Modifier.fillMaxWidth()) {
                Text("Bağlan: ${device.deviceName.ifBlank { device.deviceAddress }}",maxLines=1,overflow=TextOverflow.Ellipsis)
            }
        }
        Text("2 • İnterneti olan telefon: Gateway",fontWeight=FontWeight.Bold)
        Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(12.dp),verticalArrangement=Arrangement.spacedBy(8.dp)) {
            Text("Bu telefon grup sahibi ve internet bağlantılı olmalı.",style=MaterialTheme.typography.bodySmall)
            Info("Paylaşılacak yerel IP",peer.ownerIp.ifBlank { "Önce grup oluştur" })
            Row(verticalAlignment=Alignment.CenterVertically) {
                Checkbox(checked=voucherMode,onCheckedChange={voucherMode=it})
                Text("İmzalı belgeyle kullanım (deneysel)")
            }
            if (voucherMode) {
                OutlinedTextField(value=gatewayId,onValueChange={gatewayId=it.trim()},
                    label={Text("Bu gateway'in ID'si")},singleLine=true,modifier=Modifier.fillMaxWidth())
                OutlinedTextField(value=issuerPublicKey,onValueChange={issuerPublicKey=it.trim()},
                    label={Text("Güvenilir sağlayıcının Ed25519 açık anahtarı (Base64URL)")},
                    modifier=Modifier.fillMaxWidth())
                Text("Sadece güvendiğiniz sağlayıcının açık anahtarını girin. İmzasız ve kotası biten belgeler reddedilir.",
                    style=MaterialTheme.typography.bodySmall)
            }
            if (live.gatewayActive) {
                if(live.gatewaySecret.isNotBlank()) {
                    Text("Eşleştirme kodu: ${live.gatewaySecret}",style=MaterialTheme.typography.bodySmall)
                    OutlinedButton(onClick={clipboard.setText(AnnotatedString(live.gatewaySecret))}) { Text("Kodu kopyala") }
                }
                Button(onClick=onGatewayStop,modifier=Modifier.fillMaxWidth()) { Text("Gateway kapat") }
            } else {
                Button(
                    onClick={onGatewayStart(peer.ownerIp,secret,
                        if(voucherMode) gatewayId else "",if(voucherMode) issuerPublicKey else "")},
                    enabled=peer.connected && peer.groupOwner && peer.ownerIp.isNotBlank() && online &&
                        (!voucherMode || (gatewayId.matches(Regex("[A-Za-z0-9_-]{1,100}")) && issuerPublicKey.isNotBlank())),
                    modifier=Modifier.fillMaxWidth()
                ) { Text("Gateway ol (izinli paylaş)") }
            }
            Text(live.gatewayMessage,style=MaterialTheme.typography.bodySmall)
        } }
        }
        Text(if(singlePhoneMode) "1 • Uzak ağ geçidine bağlan (tek telefon)" else "3 • İnternetsiz telefon: İstemci",fontWeight=FontWeight.Bold)
        OutlinedTextField(value=proxyIp,onValueChange={proxyIp=it.trim()},label={Text(if(singlePhoneMode) "WSS adresi (wss://.../tunnel)" else "Gateway IPv4 veya wss://.../tunnel")},singleLine=true,modifier=Modifier.fillMaxWidth())
        OutlinedTextField(value=clientUser,onValueChange={clientUser=it.trim()},
            label={Text("Kullanıcı ID (WSS: ib-pilot; yerel: ib)")},singleLine=true,modifier=Modifier.fillMaxWidth())
        OutlinedTextField(value=clientSecret,onValueChange={clientSecret=it.trim()},
            visualTransformation=PasswordVisualTransformation(),
            label={Text("Eşleştirme kodu veya WSS cihaz anahtarı (64 hex)")},modifier=Modifier.fillMaxWidth())
        if (singlePhoneMode || proxyIp.startsWith("wss://")) {
            OutlinedTextField(
                value=ib1Voucher,onValueChange={ib1Voucher=it.trim()},
                visualTransformation=PasswordVisualTransformation(),
                label={Text("IB1 kullanım hakkı (imzalı; isteğe bağlı)")},
                modifier=Modifier.fillMaxWidth()
            )
            Text("Bu belge yalnızca katılımcı ağ geçidinin gerçekten kabul ettiği kadar kullanılabilir. Mobil operatör GB paketi değildir.",style=MaterialTheme.typography.bodySmall)
        }
        Text("İmzalı belge bir erişim yetkisidir, mobil operatör paketi değildir; gizli tutun.",style=MaterialTheme.typography.bodySmall)
        if(singlePhoneMode || proxyIp.startsWith("wss://")) {
            Text("UZAK WSS LAB: VPN'i başlatmadan kimlik ve DNS bağlantısını test et. Yalnızca TCP 80/443 ve UDP 53 desteklenir. Bu depolanmış internet değildir.",style=MaterialTheme.typography.bodySmall)
        }

        Button(onClick={scope.launch {
            probeResult=if(proxyIp.startsWith("wss://")) "Uzak WSS kimlik ve DNS doğrulaması yapılıyor..." else "Yerel Gateway HTTPS deneniyor..."
            val result=if(proxyIp.startsWith("wss://")) runCatching {
                RemoteWssProbe.run(context,proxyIp,clientUser,clientSecret,ib1Voucher)
            } else ProxyConnectivityProbe.test(proxyIp,8888,clientSecret,clientUser)
            if (singlePhoneMode || proxyIp.startsWith("wss://")) {
                remotePreflightPassed=result.isSuccess
            }
            probeResult=result.fold({"Başarılı: $it"},{"Başarısız: ${it.message}"})
        }},modifier=Modifier.fillMaxWidth()) { Text(if(singlePhoneMode || proxyIp.startsWith("wss://")) "WSS kimliğini ve DNS yanıtını test et" else "Gateway HTTPS test et") }
        if (probeResult.isNotBlank()) Text(probeResult,style=MaterialTheme.typography.bodySmall)
        if (!singlePhoneMode) OutlinedButton(onClick={scope.launch {
            dnsProbeResult="UDP üzerinden gerçek DNS yanıtı bekleniyor..."
            val result=if(proxyIp.startsWith("wss://")) Result.failure<String>(IllegalStateException("Uzak UDP/DNS testi VPN kurulumu sırasında yapılır")) else ProxyConnectivityProbe.testDns(proxyIp,8888,clientSecret,clientUser)
            dnsProbeResult=result.fold({"Başarılı: $it"},{"Başarısız: ${it.message}"})
        }},modifier=Modifier.fillMaxWidth()) { Text("Gateway UDP / DNS test et") }
        if (dnsProbeResult.isNotBlank()) Text(dnsProbeResult,style=MaterialTheme.typography.bodySmall)
        if (singlePhoneMode) Text(
            "VPN butonu WSS kimlik/DNS ön testi başarılı olunca açılır. 192.168.49.1 internet gateway değildir.",
            style=MaterialTheme.typography.bodySmall
        )
        Button(onClick={onVpnStart(proxyIp,clientSecret,clientUser,ib1Voucher)},modifier=Modifier.fillMaxWidth(),
            enabled=!live.vpnEngineActive && (if(singlePhoneMode)
                SinglePhoneRules.canStartRemote(proxyIp,clientUser,clientSecret,remotePreflightPassed) &&
                    (ib1Voucher.isBlank() || runCatching { Ib1VoucherInput.decode(ib1Voucher,clientUser);true }.getOrDefault(false))
                else proxyIp.isNotBlank() && clientSecret.length in 16..255 && clientUser.isNotBlank())) {
            Text("VPN tünelini başlat (deneysel)")
        }
        if (live.vpnEngineActive) OutlinedButton(onClick=onVpnStop,modifier=Modifier.fillMaxWidth()) { Text("VPN kapat") }
        Text(live.vpnMessage,style=MaterialTheme.typography.bodySmall)
        HorizontalDivider()
        Text("Gerçek yönlendirilen veri",fontWeight=FontWeight.Bold)
        Info("Gateway yükleme",readable(live.upstreamBytes))
        Info("Gateway indirme",readable(live.downstreamBytes))
        Info("Son doğrulanmış oturum verisi",readable(live.lastSessionBytes))
        Info("İstemci VPN yükleme",readable(live.vpnUpBytes))
        Info("İstemci VPN indirme",readable(live.vpnDownBytes))
        Text("Bu ölçümler internet kredisi değildir. İnternet erişimi yalnızca izin verilen ve aktif ağ geçidiyle mümkündür.",style=MaterialTheme.typography.bodySmall)
    }
}

@Composable private fun Info(label:String,value:String) {
    Row(Modifier.fillMaxWidth().padding(vertical=3.dp),horizontalArrangement=Arrangement.SpaceBetween) {
        Text(label,style=MaterialTheme.typography.bodySmall,modifier=Modifier.weight(1f))
        Text(value,style=MaterialTheme.typography.bodySmall,fontWeight=FontWeight.SemiBold)
    }
}

@Composable
private fun OfflineUi(vault:OfflineVault,wifi:Boolean,scope:kotlinx.coroutines.CoroutineScope) {
    var url by remember { mutableStateOf("https://www.wikipedia.org/") }
    var message by remember { mutableStateOf("") }
    var pages by remember { mutableStateOf(vault.list()) }
    var selected by remember { mutableStateOf<OfflinePage?>(null) }
    var html by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize(),verticalArrangement=Arrangement.spacedBy(8.dp)) {
        Text("Önceden kaydedilen içerikler",fontWeight=FontWeight.Bold)
        Text("İnternet paketi değil: Wi-Fi üzerinden seçtiğin HTML sayfalarını telefona saklar.",style=MaterialTheme.typography.bodySmall)
        OutlinedTextField(value=url,onValueChange={url=it},label={Text("HTTPS sayfa adresi")},singleLine=true,modifier=Modifier.fillMaxWidth())
        Button(onClick={scope.launch {
            message="İndiriliyor..."
            val result=runCatching { vault.save(url) }
            message=result.fold({page ->
                val preview=OfflineHtmlReader.inspect(vault.content(page))
                if (preview.likelyDynamicShell || preview.text.isBlank())
                    "HTML kaydedildi: ${readable(page.size.toLong())}. Sayfa dinamik/oturum gerektiriyor olabilir; çevrimdışı içerik bulunamayabilir."
                else "Kaydedildi: ${readable(page.size.toLong())}. Metin önizlemesi hazır."
            },{"Hata: ${it.message}"})
            pages=vault.list()
        }},enabled=wifi,modifier=Modifier.fillMaxWidth()) { Text("Wi-Fi ile sayfayı kaydet") }
        Text(message,style=MaterialTheme.typography.bodySmall)
        Text("Kaydedilen ${pages.size} sayfa",fontWeight=FontWeight.Bold)
        LazyColumn(verticalArrangement=Arrangement.spacedBy(7.dp)) {
            items(pages) { page ->
                OutlinedButton(onClick={scope.launch { html=vault.content(page);selected=page }},modifier=Modifier.fillMaxWidth()) {
                    Text("${page.url} (${readable(page.size.toLong())})",maxLines=2,overflow=TextOverflow.Ellipsis)
                }
            }
        }
    }
    if (selected!=null) {
        val savedPage=selected!!
        val preview=remember(html) { OfflineHtmlReader.inspect(html) }
        var renderHtml by remember(savedPage.filename) { mutableStateOf(false) }
        Dialog(onDismissRequest={selected=null}) {
            Card(Modifier.fillMaxWidth().fillMaxHeight(.84f)) {
                Column(Modifier.padding(12.dp),verticalArrangement=Arrangement.spacedBy(8.dp)) {
                    Text("Çevrimdışı kayıt: ${preview.title.ifBlank { "Başlık bulunamadı" }}",fontWeight=FontWeight.Bold)
                    Text("Kaydedilen: ${readable(savedPage.size.toLong())} · Yalnızca HTML yanıtı saklandı.",style=MaterialTheme.typography.bodySmall)
                    if (preview.hasJavaScript || preview.hasExternalAssets) {
                        Text("Bu sayfa JavaScript veya dış dosyalar kullanıyor. Tam görünümü ve formları çevrimdışı çalışmayabilir.",style=MaterialTheme.typography.bodySmall)
                    }
                    if (preview.likelyDynamicShell || preview.text.isBlank()) {
                        Text("Kaydedilen HTML içinde görüntülenecek yeterli statik metin bulunamadı. Oturum gerektiren/dinamik ekranlar yalnızca HTML kaydıyla çalışmaz.",style=MaterialTheme.typography.bodySmall)
                    }
                    Row(horizontalArrangement=Arrangement.spacedBy(6.dp)) {
                        OutlinedButton(onClick={renderHtml=false},enabled=renderHtml) { Text("Metin") }
                        OutlinedButton(onClick={renderHtml=true},enabled=!renderHtml) { Text("HTML") }
                        OutlinedButton(onClick={selected=null}) { Text("Kapat") }
                    }
                    if (renderHtml) {
                        // The HTML preview is isolated: scripts, network, file and content access remain blocked.
                        AndroidView(factory={c -> WebView(c).apply {
                            settings.javaScriptEnabled=false
                            settings.blockNetworkLoads=true
                            settings.allowFileAccess=false
                            settings.allowContentAccess=false
                        }},update={it.loadDataWithBaseURL(null,html,"text/html","UTF-8",null)},modifier=Modifier.fillMaxSize())
                    } else {
                        Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())) {
                            if (preview.text.isBlank()) {
                                Text("Bu kayıtta çevrimdışı okunabilir içerik yok. Daha basit ve herkese açık bir HTML sayfasıyla dene: https://example.com/",style=MaterialTheme.typography.bodyMedium)
                            } else {
                                Text(preview.text,style=MaterialTheme.typography.bodyMedium)
                            }
                        }
                    }
                }
            }
        }
    }

}

@Composable
private fun TestsUi(live:RuntimeState,peer:PeerState,online:Boolean,scope:kotlinx.coroutines.CoroutineScope) {
    var result by remember { mutableStateOf("Test başlatılmadı") }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()),verticalArrangement=Arrangement.spacedBy(12.dp)) {
        Text("Bağlantı doğrulaması",fontWeight=FontWeight.Bold)
        Info("Telefonun aktif internet durumu",if(online) "Android doğruladı" else "Doğrulanmadı")
        Info("Wi-Fi Direct eşleşmesi",if(peer.connected) "Grup kuruldu" else "Bağlantı yok")
        Info("VPN yerel motoru",if(live.vpnEngineActive) "Açık" else "Kapalı")
        Info("Tünelden HTTPS",if(live.vpnHttpsVerified) "HTTPS ve TUN sayacı testi geçti" else "Test geçmedi/çalışmadı")
        Info("IPv6 yolu",if(live.vpnIpv6RouteConfigured) "VPN'e yönlendiriliyor; internet doğrulanmadı" else "Kapalı")
        Button(onClick={scope.launch {
            result="HTTPS sunucu testi yapılıyor..."
            val tested=kotlinx.coroutines.withContext(Dispatchers.IO) {
                runCatching {
                    val conn=java.net.URL("https://example.com").openConnection() as javax.net.ssl.HttpsURLConnection
                    conn.connectTimeout=7000;conn.readTimeout=7000
                    try { "Gerçek HTTPS HTTP ${conn.responseCode}" } finally { conn.disconnect() }
                }
            }
            result=tested.fold({it},{"Başarısız: ${it.message}"})
        }},modifier=Modifier.fillMaxWidth()) { Text("Gerçek HTTPS isteği gönder") }
        Text(result,style=MaterialTheme.typography.bodySmall)
        Text("Bu test, VPN açık ve başka erişim kanalı kapalı olduğunda tünel geçişini doğrulamaya yardımcı olur. Sadece bu testin geçmesi, WhatsApp'ın çalıştığını kanıtlamaz.",style=MaterialTheme.typography.bodySmall)
    }
}

private fun secureSecret():String {
    val data=ByteArray(24).also { SecureRandom().nextBytes(it) }
    return data.joinToString("") { "%02x".format(it) }
}
private fun readable(n:Long):String = when {
    n>=1_073_741_824 -> "%.2f GB".format(Locale.US,n/1_073_741_824.0)
    n>=1_048_576 -> "%.2f MB".format(Locale.US,n/1_048_576.0)
    n>=1024 -> "%.2f KB".format(Locale.US,n/1024.0)
    else -> "$n B"
}
