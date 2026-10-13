package com.internetbattery.broker

import com.internetbattery.capacity.CapacityLedger
import com.internetbattery.capacity.PortableVoucher
import com.internetbattery.capacity.ProofCrypto
import com.internetbattery.capacity.UsageReceipt
import com.internetbattery.capacity.VoucherIssuer
import java.security.PrivateKey

/**
 * Laboratory reciprocal access clearinghouse. A gateway MAC by itself is insufficient:
 * the consumer also signs the SAME provider-reported byte counters. This is evidence
 * of both parties' consent, NOT an independent packet measurement or carrier data plan.
 * All issued vouchers still require a participating physical gateway with internet.
 */
class MutualReceiptBroker(
    private val ledger: CapacityLedger,
    private val issuerPrivateKey: PrivateKey,
    consumerSecrets: Map<String, ByteArray>,
    registeredDestinationGateways: Set<String>
) {
    private val secrets = consumerSecrets.mapValues { (_, key) -> key.copyOf().also { require(it.size >= 32) } }
    private val issuer = VoucherIssuer(ledger, issuerPrivateKey)
    private val allowedDestinations = registeredDestinationGateways.toSet().also { require(it.isNotEmpty()) }

    fun settle(receipt: UsageReceipt, consumerApproval: String): Boolean {
        val key = secrets[receipt.consumerId] ?: return false
        // The consumer signs the exact gateway statement, including its signature.
        // Any changing of data or signed gateway identity invalidates the approval.
        if (!ProofCrypto.verify(key, consumerPayload(receipt), consumerApproval)) return false
        return ledger.settle(receipt) // trusted gateway MAC, timestamp, replay, credit and journal checks
    }

    fun issueVoucher(
        holder: String,
        voucherId: String,
        targetGateway: String,
        quotaBytes: Long,
        authorization: String,
        validityMinutes: Long = 30
    ): PortableVoucher? {
        if (targetGateway !in allowedDestinations) return null // no credits burned for fictional gateways
        val key = secrets[holder] ?: return null
        if (!ProofCrypto.verify(key, issuePayload(holder, voucherId, targetGateway, quotaBytes, validityMinutes), authorization)) return null
        return runCatching { issuer.issue(holder, voucherId, targetGateway, quotaBytes, validityMinutes) }.getOrNull()
    }

    fun balance(owner: String): Long = ledger.balance(owner)

    companion object {
        fun consumerPayload(receipt: UsageReceipt): String =
            "IB_CONSUMER_APPROVAL_V1|${receipt.payload()}|${receipt.signature}"

        fun issuePayload(holder: String, id: String, gateway: String, bytes: Long, minutes: Long): String =
            "IB_VOUCHER_REQUEST_V1|$holder|$id|$gateway|$bytes|$minutes"

        /** A consumer-only tool, never used by an untrusted gateway or public server. */
        fun signConsumerApproval(consumerKey: ByteArray, receipt: UsageReceipt): String =
            ProofCrypto.mac(consumerKey, consumerPayload(receipt))

        fun signIssueRequest(holderKey: ByteArray, holder: String, id: String, gateway: String, bytes: Long, minutes: Long = 30): String =
            ProofCrypto.mac(holderKey, issuePayload(holder, id, gateway, bytes, minutes))
    }
}
