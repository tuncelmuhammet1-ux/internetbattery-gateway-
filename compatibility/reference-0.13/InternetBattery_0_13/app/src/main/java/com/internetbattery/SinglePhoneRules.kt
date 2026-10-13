package com.internetbattery

/**
 * Decision rules for single-phone remote tunnel mode.
 * Never mistake Wi-Fi Direct group owner 192.168.49.1 for an off-site gateway.
 */
object SinglePhoneRules {
    fun showPeerDiscovery(singlePhoneMode:Boolean)=!singlePhoneMode
    fun usePeerOwnerIp(singlePhoneMode:Boolean,ownerIp:String)=
        !singlePhoneMode && ownerIp.isNotBlank()

    fun canStartRemote(url:String,deviceId:String,keyHex:String,preflightPassed:Boolean):Boolean {
        if (!preflightPassed) return false
        return runCatching {
            WssCredentials.validateAddress(url)
            WssCredentials.validateDeviceId(deviceId)
            WssCredentials.hexKey(keyHex)
            true
        }.getOrDefault(false)
    }

    fun isPrinter(name:String,primaryDeviceType:String):Boolean {
        val n=name.lowercase()
        return primaryDeviceType.trim().startsWith("7-") ||
            (n.startsWith("direct-") && (n.contains("smart tank") || n.contains("laserjet") ||
                n.contains("deskjet") || n.contains("officejet") || n.contains("printer"))) ||
            (n.contains("hp smart tank") || n.contains("epson printer"))
    }
}
