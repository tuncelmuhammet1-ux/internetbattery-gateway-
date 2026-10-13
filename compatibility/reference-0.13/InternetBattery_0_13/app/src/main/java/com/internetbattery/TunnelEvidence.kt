package com.internetbattery

/**
 * Fail-closed decision for a *specific VPN-network-bound* HTTPS request.
 * Counter growth alone can be unrelated background traffic; HTTPS success alone
 * may be a cellular/Wi-Fi bypass. Both need to coincide on the VPN Network.
 * No assertion here can substitute for on-device network/packet evidence.
 */
object TunnelEvidence {
    fun isVerified(vpnNetworkObserved: Boolean, httpsStatus: Int?, before: LongArray?, after: LongArray?): Boolean {
        if (!vpnNetworkObserved || httpsStatus == null || httpsStatus !in 200..399) return false
        if (before == null || after == null || before.size < 4 || after.size < 4) return false
        val tx = after[1] - before[1]
        val rx = after[3] - before[3]
        // A counter reset should not make an apparent success.
        return after[1] >= before[1] && after[3] >= before[3] && tx > 0L && rx > 0L
    }
}
