package com.internetbattery

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Minimal real Android-runtime smoke: APK installation, package, class loading.
 * DOES NOT prove that Wi-Fi Direct, TUN, or the outside Internet works. */
@RunWith(AndroidJUnit4::class)
class AndroidInstallSmokeTest {
    @Test fun canInstallAndLoadCoreClasses() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("com.internetbattery", context.packageName)
        assertNotNull(context.applicationContext)
        assertFalse(TunnelEvidence.isVerified(false, 200, longArrayOf(1,2,3,4), longArrayOf(5,6,7,8)))
    }
}
