package com.internetbattery

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * True Android 15 runtime test of production RemoteWssProbe against a
 * short-lived, HMAC-protected external WSS/TLS laboratory gateway.
 *
 * Does NOT claim VPN or physical roaming. Credential values are supplied by
 * ephemeral CI instrumentation parameters, not hardcoded into any APK.
 */
@RunWith(AndroidJUnit4::class)
class RemoteWssRealNetworkTest {
    @Test
    fun canAuthenticateAndResolvePublicDnsOverWss() {
        val args = InstrumentationRegistry.getArguments()
        val wss = requireNotNull(args.getString("ib_wss")) { "Missing test WSS URL" }
        val device = requireNotNull(args.getString("ib_device")) { "Missing test device" }
        val key = requireNotNull(args.getString("ib_device_key")) { "Missing test device key" }
        require(wss.startsWith("wss://") && wss.endsWith("/tunnel"))
        require(key.matches(Regex("[a-f0-9]{64}")))
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val result = runBlocking {
            withTimeout(75_000L) {
                RemoteWssProbe.run(context, wss, device, key, "")
            }
        }
        assertTrue("Android real WSS DNS preflight failed: $result",
            result.contains("Kimlik ve WSS DNS yanıtı doğrulandı"))
        Log.i("IB17_WSS_TEST", "IB17_ANDROID_REAL_WSS_PREFLIGHT_SUCCESS")
        println("IB17_ANDROID_REAL_WSS_PREFLIGHT_SUCCESS")
    }
}
