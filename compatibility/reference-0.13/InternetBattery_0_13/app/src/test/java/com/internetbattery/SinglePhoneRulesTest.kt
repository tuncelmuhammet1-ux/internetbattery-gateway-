package com.internetbattery

import org.junit.Assert.*
import org.junit.Test

class SinglePhoneRulesTest {
    private val validUrl="wss://relay.example.com/tunnel"
    private val goodKey="b9".repeat(32)

    @Test fun singlePhoneDoesNotScanPeers() {
        assertFalse(SinglePhoneRules.showPeerDiscovery(true))
        assertTrue(SinglePhoneRules.showPeerDiscovery(false))
    }

    @Test fun printerGroupOwnerIpMustNotBecomeRemoteProxy() {
        assertFalse(SinglePhoneRules.usePeerOwnerIp(true,"192.168.49.1"))
        assertTrue(SinglePhoneRules.usePeerOwnerIp(false,"192.168.49.1"))
        assertFalse(SinglePhoneRules.usePeerOwnerIp(false,""))
    }

    @Test fun noCredentialsCannotStartRemote() {
        assertFalse(SinglePhoneRules.canStartRemote("","ib-pilot","",false))
        assertFalse(SinglePhoneRules.canStartRemote(validUrl,"ib-pilot",goodKey,false))
    }

    @Test fun validatedRemoteCredentialsCanStart() {
        assertTrue(SinglePhoneRules.canStartRemote(validUrl,"ib-pilot",goodKey,true))
    }

    @Test fun localPrinterAddressNeverAcceptedAsWss() {
        assertFalse(SinglePhoneRules.canStartRemote("192.168.49.1","ib-pilot",goodKey,true))
    }

    @Test fun malformedDeviceKeyRejected() {
        assertFalse(SinglePhoneRules.canStartRemote(validUrl,"ib-pilot","short",true))
    }

    @Test fun printerDetectionFromUserScreenshot() {
        assertTrue(SinglePhoneRules.isPrinter("DIRECT-A6-HP Smart Tank 580-590","7-0050F204-1"))
        assertTrue(SinglePhoneRules.isPrinter("DIRECT-A6-HP Smart Tank 580-590",""))
        assertFalse(SinglePhoneRules.isPrinter("My Android Phone","10-0050F204-5"))
    }
}
