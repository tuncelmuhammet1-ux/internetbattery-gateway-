package com.internetbattery.roaming

import com.internetbattery.capacity.LocalGatewayVoucherVerifier
import com.internetbattery.capacity.PortableVoucher
import com.internetbattery.gateway.TransferAllowance
import kotlin.math.min

/**
 * Adapter between signed, gateway-bound vouchers and ACTUAL SOCKS relay bytes.
 * Only run this on a consenting gateway that was explicitly provisioned with
 * an issuer public key and a authenticated holder identity.
 *
 * Reserve-before-forward accounting prevents quota overspend even with concurrent
 * TCP and UDP sockets. An unsuccessful write can overcharge until reconciliation.
 * This is a lab adapter, NOT a carrier/eSIM plan or remote entitlement issuer.
 */
class VoucherTransferAllowance(
    private val voucher: PortableVoucher,
    private val authenticatedHolder: String,
    private val verifier: LocalGatewayVoucherVerifier
) : TransferAllowance {
    override fun mayOpen(): Boolean = verifier.canSpend(voucher, authenticatedHolder)

    override fun grant(requestedBytes: Int, datagram: Boolean): Int = synchronized(verifier) {
        if (requestedBytes <= 0) return@synchronized 0
        val remaining = voucher.quotaBytes - verifier.spentBytes(voucher.voucherId)
        if (remaining <= 0L) return@synchronized 0
        val permitted = if (datagram) {
            if (requestedBytes.toLong() > remaining) 0 else requestedBytes
        } else min(requestedBytes.toLong(), remaining).toInt()
        if (permitted <= 0) return@synchronized 0
        // Signature, gateway, holder, expiry and quota are checked on EACH grant.
        // LocalGatewayVoucherVerifier forces the journal to disk before approval.
        if (verifier.spend(voucher, permitted.toLong(), authenticatedHolder)) permitted else 0
    }
}
