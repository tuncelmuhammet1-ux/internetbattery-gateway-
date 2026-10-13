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
        val consent = VpnService.prepare(app)
        if (consent != null) {
            consent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            app.startActivity(consent)
        }
        val isPrepared = runBlocking {
            var prepared = false
            repeat(80) {
                if (VpnService.prepare(app) == null) {
                    prepared = true
                    return@repeat
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
                repeat(90) {
                    delay(500)
                    val state = RuntimeStatus.state.value
                    details = state.vpnMessage
                    if (state.vpnHttpsVerified) {
                        ok = true
                        return@repeat
                    }
                    if (details.startsWith("Uzak WSS VPN hatası:") ||
                        details.startsWith("Uzak WSS erişimi veya VPN çift yönlü HTTPS kanıtı yok")) {
                        return@repeat
                    }
                }
                ok
            }
            if (!verified) Log.e("IB17_VPN_TEST", "Android VPN did not verify HTTPS: $details")
            assertTrue("VPN tunnel failed HTTPS proof. Last status: $details", verified)
            Log.i("IB17_VPN_TEST", "IB17_ANDROID_VPN_WSS_HTTPS_VERIFIED")
            println("IB17_ANDROID_VPN_WSS_HTTPS_VERIFIED")
        } finally {
            TunnelVpnService.stop(app)
        }
    }
}
