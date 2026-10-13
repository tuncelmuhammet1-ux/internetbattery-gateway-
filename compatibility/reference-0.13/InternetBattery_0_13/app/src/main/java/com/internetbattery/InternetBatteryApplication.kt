package com.internetbattery

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update

class InternetBatteryApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        val channel = NotificationChannel(CHANNEL, "Internet Battery bağlantısı", NotificationManager.IMPORTANCE_LOW)
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }
    companion object { const val CHANNEL = "internet_battery_connection" }
}

data class RuntimeState(
    val gatewayActive: Boolean = false,
    val gatewayIp: String = "",
    val gatewaySecret: String = "",
    val gatewayMessage: String = "Henüz başlatılmadı",
    val vpnEngineActive: Boolean = false,
    val vpnHttpsVerified: Boolean = false,
    // The OS has accepted an IPv6 default route into the TUN; NOT a reachability proof.
    val vpnIpv6RouteConfigured: Boolean = false,
    val vpnMessage: String = "VPN kapalı",
    val upstreamBytes: Long = 0,
    val downstreamBytes: Long = 0,
    val lastSessionBytes: Long = 0,
    val vpnUpBytes: Long = 0,
    val vpnDownBytes: Long = 0,
)

object RuntimeStatus {
    val state = MutableStateFlow(RuntimeState())
    fun update(transform: (RuntimeState) -> RuntimeState) { state.update(transform) }
}
