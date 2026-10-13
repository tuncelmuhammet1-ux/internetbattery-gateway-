package com.internetbattery

import android.Manifest
import android.annotation.SuppressLint
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.wifi.p2p.WifiP2pConfig
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pManager
import android.os.Looper
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update

/** Android API 33+ Wi-Fi Direct discovery and group ownership. */
data class PeerState(
    val supported: Boolean = true,
    val enabled: Boolean = false,
    val peers: List<WifiP2pDevice> = emptyList(),
    val connected: Boolean = false,
    val groupOwner: Boolean = false,
    val ownerIp: String = "",
    val status: String = "Cihaz araması başlamadı"
)

class WifiP2pController(private val context: Context) : AutoCloseable {
    val state = MutableStateFlow(PeerState())
    private val manager = context.getSystemService(Context.WIFI_P2P_SERVICE) as? WifiP2pManager
    private val channel = manager?.initialize(context, Looper.getMainLooper()) {
        state.update { it.copy(connected = false, status = "P2P kanalı kapandı") }
    }
    private val filter = IntentFilter().apply {
        addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION)
        addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION)
        addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION)
    }
    private var registered = false
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context, intent: Intent) {
            when (intent.action) {
                WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION -> {
                    val on = intent.getIntExtra(WifiP2pManager.EXTRA_WIFI_STATE, 0) == WifiP2pManager.WIFI_P2P_STATE_ENABLED
                    state.update { it.copy(enabled = on, status = if (on) "Wi-Fi Direct hazır" else "Wi-Fi Direct kapalı") }
                }
                WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION -> requestPeers()
                WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION -> refreshConnection()
            }
        }
    }

    init {
        state.update { it.copy(supported = manager != null && channel != null) }
        // Wi-Fi P2P broadcasts are system broadcasts. An exported runtime receiver
        // is required on devices where these broadcasts originate in privileged components.
        context.registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
        registered = true
    }

    private fun allowed() = context.checkSelfPermission(Manifest.permission.NEARBY_WIFI_DEVICES) == PackageManager.PERMISSION_GRANTED &&
        context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED

    @SuppressLint("MissingPermission")
    fun discover() {
        if (!allowed()) { state.update { it.copy(status = "Wi-Fi/konum izinlerini ver") }; return }
        val m = manager ?: return
        val c = channel ?: return
        m.discoverPeers(c, object: WifiP2pManager.ActionListener {
            override fun onSuccess() { state.update { it.copy(status = "Cihazlar aranıyor...") }; requestPeers() }
            override fun onFailure(reason: Int) { state.update { it.copy(status = "Keşif hatası: $reason") } }
        })
    }

    @SuppressLint("MissingPermission")
    fun createGroup() {
        if (!allowed()) { state.update { it.copy(status = "Wi-Fi/konum izinlerini ver") }; return }
        val m = manager ?: return; val c = channel ?: return
        m.createGroup(c, object: WifiP2pManager.ActionListener {
            override fun onSuccess() { state.update { it.copy(status = "Grup oluşturuluyor...") }; refreshConnection() }
            override fun onFailure(reason: Int) { state.update { it.copy(status = "Grup açılamadı: $reason") } }
        })
    }

    @SuppressLint("MissingPermission")
    fun connect(device: WifiP2pDevice) {
        if (!allowed()) { state.update { it.copy(status = "Wi-Fi/konum izinlerini ver") }; return }
        val m = manager ?: return; val c = channel ?: return
        // Use the classic config: these are public fields, unlike the Builder API.
        val config = WifiP2pConfig().apply {
            deviceAddress = device.deviceAddress
            groupOwnerIntent = WifiP2pConfig.GROUP_OWNER_INTENT_MIN
        }
        m.connect(c, config, object: WifiP2pManager.ActionListener {
            override fun onSuccess() { state.update { it.copy(status = "${device.deviceName} bağlanıyor...") } }
            override fun onFailure(reason: Int) { state.update { it.copy(status = "Bağlanılamadı: $reason") } }
        })
    }

    @SuppressLint("MissingPermission")
    private fun requestPeers() {
        if (!allowed()) return
        val m = manager ?: return; val c = channel ?: return
        m.requestPeers(c) { list -> state.update { it.copy(peers = list.deviceList.toList()) } }
    }

    @SuppressLint("MissingPermission")
    fun refreshConnection() {
        if (!allowed()) return
        val m = manager ?: return; val c = channel ?: return
        m.requestConnectionInfo(c) { info ->
            state.update { it.copy(
                connected = info?.groupFormed == true,
                groupOwner = info?.isGroupOwner == true,
                ownerIp = if (info?.groupFormed == true) (info.groupOwnerAddress?.hostAddress ?: "") else "",
                status = when {
                    info?.groupFormed != true -> "Henüz eşleşmedi"
                    info.isGroupOwner -> "Grup sahibi / Gateway cihazı"
                    else -> "Gruba bağlı / İstemci cihazı"
                }
            ) }
        }
    }

    @SuppressLint("MissingPermission")
    fun disconnect() {
        val m = manager ?: return; val c = channel ?: return
        if (!allowed()) return
        m.removeGroup(c, object: WifiP2pManager.ActionListener {
            override fun onSuccess() { state.update { it.copy(connected=false,ownerIp="",status="Grup kapatıldı") } }
            override fun onFailure(reason: Int) { state.update { it.copy(status="Grup kapatılamadı: $reason") } }
        })
    }

    override fun close() {
        if (registered) { runCatching { context.unregisterReceiver(receiver) }; registered = false }
    }
}
