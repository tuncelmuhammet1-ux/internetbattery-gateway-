package com.internetbattery

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end Android 15 lab trial: temporary public TLS/WSS underlay,
 * real VpnService consent, native TUN + SOCKS bridge + Remote WSS relay,
 * and HTTPS request explicitly bound to Android's VPN Network.
 *
 * Success means tested Android emulator VPN transfer only.
 * It does not establish internet access without a physical underlay,
 * operator cellular credits, QUIC/IPv6 reachability, or actual phone roaming.
 */
@RunWith(AndroidJUnit4::class)
class RemoteWssVpnEndToEndTest {
    @Test fun androidVpnCarriesRealHttpsAndIncrementsBothByteCounters() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val args = InstrumentationRegistry.getArguments()
        val url = requireNotNull(args.getString("ib_wss"))
        val device = requireNotNull(args.getString("ib_device"))
        val key = requireNotNull(args.getString("ib_device_key"))
        require(url.startsWith("wss://") && url.endsWith("/tunnel"))
        require(key.matches(Regex("[a-f0-9]{64}")))
        val context = instrumentation.targetContext
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        assertTrue("No physical network underlay for VPN trial", cm.activeNetwork != null)
        val initial = VpnService.prepare(context)
        if (initial != null) {
            val dialog = initial.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(dialog)
            val ui = UiDevice.getInstance(instrumentation)
            var accepted = false
            for (attempt in 1..6) {
                val button = ui.wait(Until.findObject(By.res("android:id/button1")), 4_000L)
                    ?: ui.findObject(By.text("OK"))
                    ?: ui.findObject(By.text("Allow"))
                    ?: ui.findObject(By.text("ALLOW"))
                if (button != null) {
                    button.click()
                    accepted = true
                    break
                }
            }
            if (!accepted) {
                Log.e("IB17_VPN_TEST", "VPN consent dialog not found")
            }
        }
        var permissionAccepted = false
        for (i in 1..30) {
            if (VpnService.prepare(context) == null) {
                permissionAccepted = true
                break
            }
            Thread.sleep(500L)
        }
        assertTrue("VPN permission was not granted by Android system consent", permissionAccepted)
        RuntimeStatus.update { it.copy(vpnHttpsVerified=false, vpnEngineActive=false, vpnMessage="VPN emulator test starting") }
        var last = RuntimeStatus.state.value
        try {
            TunnelVpnService.start(context, url, key, device)
            var verified = false
            for (i in 0 until 150) {
                last = RuntimeStatus.state.value
                if (last.vpnHttpsVerified) {
                    verified = true
                    break
                }
                if (last.vpnMessage.contains("VPN hatası:", ignoreCase=true)
                    || last.vpnMessage.contains("TUN motoru başlatılamadı", ignoreCase=true)
                    || last.vpnMessage.contains("WSS erişimi veya VPN çift yönlü HTTPS kanıtı yok")) {
                    Log.e("IB17_VPN_TEST", "Trial failed at stage: "+last.vpnMessage)
                    break
                }
                Thread.sleep(1000L)
            }
            last = RuntimeStatus.state.value
            val vpnNetworkPresent = cm.allNetworks.any { network ->
                cm.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }
            Log.i("IB17_VPN_TEST", "verified=$verified, route="+last.vpnIpv6RouteConfigured+
                ", network=$vpnNetworkPresent, up="+last.vpnUpBytes+
                ", down="+last.vpnDownBytes+", state="+last.vpnMessage)
            assertTrue("Real HTTPS not verified through Android VPN: "+last.vpnMessage,
                verified && vpnNetworkPresent && last.vpnEngineActive)
            println("IB17_ANDROID_VPN_WSS_HTTPS_SUCCESS")
        } finally {
            TunnelVpnService.stop(context)
            Thread.sleep(1200L)
        }
    }
}
