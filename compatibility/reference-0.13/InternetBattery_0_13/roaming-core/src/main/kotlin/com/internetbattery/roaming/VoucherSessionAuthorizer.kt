package com.internetbattery.roaming

import com.internetbattery.capacity.LocalGatewayVoucherVerifier
import com.internetbattery.capacity.VoucherCredential
import com.internetbattery.gateway.SessionAdmission
import com.internetbattery.gateway.SessionAuthorizer

/** Authenticates an RFC1929 holder + Ed25519 voucher as one session. No static
 * password fallback. All TCP/UDP forwarding debits a gateway-local durable journal. */
class VoucherSessionAuthorizer(private val verifier: LocalGatewayVoucherVerifier) : SessionAuthorizer {
    override fun authenticate(username: String, secret: String): SessionAdmission? {
        val voucher = VoucherCredential.decode(secret) ?: return null
        if (!verifier.canSpend(voucher, username)) return null
        return SessionAdmission(VoucherTransferAllowance(voucher, username, verifier))
    }
}
