package com.internetbattery

import android.content.Intent
import android.net.VpnService
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * End-to-end Android TUN -> native tun2socks -> loopback SOCKS5
 * -> authenticated WSS -> isolated gateway -> real TCP/443 -> HTTPS.
 *
 * Android VPN consent is granted interactively by headless emulator
 * UI automation, never bypassed in product code.
 *
 * IB1 voucher/account charging and physical roaming are intentionally not
 * tested here. The ephemeral gateway uses a 1 MiB trial transport cap.
 */
@RunWith(AndroidJUnit4::class)
class RemoteVpnRealNetworkTest {
    @Test
    fun httpsTrafficTraversesAndroidVpnAndWssGateway() {
        val args = InstrumentationRegistry.getArguments()
        val wss = requireNotNull(args.getString("ib_wss"))
        val device = requireNotNull(args.getString("ib_device"))
        val key = requireNotNull(args.getString("ib_device_key"))
        require(wss.startsWith("wss://") && wss.endsWith("/tunnel"))
        require(key.matches(Regex("[a-f0-9]{64}")))
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        val cm = app.getSystemService(android.content.Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
        val underlayReady = runBlocking {
            var connected = false
            for (i in 0 until 100) {
                val network = cm.activeNetwork
                if (network != null &&
                    cm.getNetworkCapabilities(network)?.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET) == true) {
                    connected = true
                    break
                }
                delay(500)
            }
            connected
        }
        assertTrue("Android emulator network not ready after 50s", underlayReady)
        val consent = VpnService.prepare(app)
        if (consent != null) {
            consent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            app.startActivity(consent)
        }
        val isPrepared = runBlocking {
            var prepared = false
            for (i in 0 until 80) {
                if (VpnService.prepare(app) == null) {
                    prepared = true
                    break
                }
                delay(500)
            }
            prepared
        }
        assertTrue("Android system VPN consent was not granted", isPrepared)
        var details = ""
        try {
            TunnelVpnService.start(app, wss, key, device, "")
            val verified = runBlocking {
                var ok = false
                for (i in 0 until 120) {
                    delay(500)
                    val state = RuntimeStatus.state.value
                    details = state.vpnMessage
                    if (state.vpnHttpsVerified) {
                        ok = true
                        break
                    }
                    if (details.startsWith("Uzak WSS VPN hatası:") ||
                        details.startsWith("Uzak WSS erişimi veya VPN çift yönlü HTTPS kanıtı yok")) {
                        break
                    }
                }
                ok
            }
            if (!verified) {
                Log.e("IB17_VPN_TEST", "Android VPN did not verify HTTPS: $details")
                val nativeLog = java.io.File(app.filesDir, "ib-native-engine.log")
                if (nativeLog.isFile) {
                    runCatching {
                        for (entry in nativeLog.readLines().takeLast(90)) {
                            val lowered = entry.lowercase()
                            if (listOf("password", "username", "secret", "authorization", "token", "key=").none { lowered.contains(it) }) {
                                Log.e("IB17_NATIVE_LOG", entry.take(230))
                            }
                        }
                    }.onFailure { Log.e("IB17_NATIVE_LOG", "Failed to read native diagnostic: "+it.javaClass.simpleName) }
                } else Log.e("IB17_NATIVE_LOG", "No native diagnostic file produced")
            }
            assertTrue("VPN tunnel failed HTTPS proof. Last status: $details", verified)
            Log.i("IB17_VPN_TEST", "IB17_ANDROID_VPN_WSS_HTTPS_VERIFIED")
            println("IB17_ANDROID_VPN_WSS_HTTPS_VERIFIED")
        } finally {
            TunnelVpnService.stop(app)
        }
    }
}
