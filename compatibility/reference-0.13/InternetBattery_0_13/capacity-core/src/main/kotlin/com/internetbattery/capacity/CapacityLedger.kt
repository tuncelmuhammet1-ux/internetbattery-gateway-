package com.internetbattery.capacity

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.time.Clock
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Research-only reciprocal gateway credit ledger. Credit is INTERNAL to a willing
 * network of participating gateways; it is NOT mobile operator data/Internet itself.
 *
 * This implementation is portable Kotlin/JVM, so real cryptographic, metering,
 * replay/overdraft and persistence tests run without Android or a network.
 * Its operator MUST register willing gateways through a trusted channel.
 * Gateway self-reported metering is NOT proof against a malicious gateway.
 */
data class UsageReceipt(
    val id: String,
    val gatewayId: String,
    val consumerId: String,
    val uplinkBytes: Long,
    val downlinkBytes: Long,
    val createdAtMs: Long,
    val signature: String = ""
) {
    val totalBytes: Long get() = Math.addExact(uplinkBytes, downlinkBytes)
    fun payload(): String = listOf(id, gatewayId, consumerId, uplinkBytes, downlinkBytes, createdAtMs).joinToString("|")
}

object ProofCrypto {
    fun mac(key: ByteArray, data: String): String {
        val h = Mac.getInstance("HmacSHA256")
        h.init(SecretKeySpec(key, "HmacSHA256"))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(h.doFinal(data.toByteArray(Charsets.UTF_8)))
    }
    fun verify(key: ByteArray, data: String, actual: String): Boolean = runCatching {
        val expected = Base64.getUrlDecoder().decode(mac(key, data))
        val got = Base64.getUrlDecoder().decode(actual)
        MessageDigest.isEqual(expected, got)
    }.getOrDefault(false)
}

class GatewayReceiptSigner(val gatewayId: String, private val key: ByteArray) {
    init { require(key.size >= 32) }
    fun sign(id: String, consumer: String, up: Long, down: Long, timeMs: Long): UsageReceipt {
        val r = UsageReceipt(id, gatewayId, consumer, up, down, timeMs)
        return r.copy(signature = ProofCrypto.mac(key, r.payload()))
    }
}

/** A gateway's public identity and trusted secret are configured by operator, not mobile users. */
data class TrustedGateway(val id: String, val ownerId: String, val secret: ByteArray) {
    init { require(secret.size >= 32) }
}

/**
 * Append-only, MAC-chained journal with forced disk flush prior to committing balances.
 * Demonstrates durable atomic accounting on a SINGLE local server. A real deployment
 * needs authenticated HTTPS APIs, gateway identity attestation, independent usage
 * verification, rate limits, backups, monitoring, and provider agreements.
 */
class CapacityLedger(
    private val journal: Path,
    journalKey: ByteArray,
    gateways: List<TrustedGateway>,
    private val clock: Clock = Clock.systemUTC()
) {
    private val journalSecret = journalKey.copyOf()
    private val trusted = gateways.associateBy { it.id }
    private val balances = mutableMapOf<String, Long>()
    private val recordedIds = mutableSetOf<String>()
    private val reservedVoucherIds = mutableSetOf<String>()
    private var tail = "GENESIS"
    private var recordCount = 0L
    private var faulted = false
    private val anchor = JournalIntegrityAnchor(journal,journalSecret)

    init {
        require(journalSecret.size >= 32)
        require(trusted.size == gateways.size)
        replayJournal()
    }

    @Synchronized fun balance(id: String): Long = balances[id] ?: 0L
    @Synchronized fun recordedCount(): Int = recordedIds.size

    /**
     * Reserve previously earned internal network units for an offline roaming voucher.
     * A production issuer must persist the signed voucher together with this reservation
     * and support idempotent retrieval if delivery fails.
     */
    @Synchronized fun reserveForVoucher(holderId: String, voucherId: String, bytes: Long): Boolean {
        if (!validId(holderId) || !validId(voucherId) || reservedVoucherIds.contains(voucherId)) return false
        if (bytes !in 1..MAX_VOUCHER_RESERVATION_BYTES || balance(holderId) < bytes) return false
        append("R|$holderId|$voucherId|$bytes")
        balances[holderId] = balance(holderId) - bytes
        reservedVoucherIds.add(voucherId)
        return true
    }

    /** Explicit admin-only DEMO allocation, not real earned access and never exposed as an unauthenticated API. */
    @Synchronized fun seedTestQuota(consumerId: String, bytes: Long) {
        checkId(consumerId)
        require(bytes in 1..TEST_CREDIT_MAX)
        val old = balance(consumerId)
        val next = Math.addExact(old, bytes)
        append("T|$consumerId|$bytes")
        balances[consumerId] = next
    }

    /** Settles real relay metering claimed and authenticated by a registered gateway. */
    @Synchronized fun settle(r: UsageReceipt): Boolean {
        if (!validId(r.id) || !validId(r.gatewayId) || !validId(r.consumerId)) return false
        val gateway = trusted[r.gatewayId] ?: return false
        if (gateway.ownerId == r.consumerId || recordedIds.contains(r.id)) return false
        if (r.uplinkBytes < 0 || r.downlinkBytes < 0) return false
        val total = runCatching { r.totalBytes }.getOrNull() ?: return false
        if (total !in 1..MAX_RECEIPT_BYTES) return false
        val age = clock.millis() - r.createdAtMs
        if (age < -MAX_SKEW_MS || age > MAX_SKEW_MS) return false
        if (!ProofCrypto.verify(gateway.secret, r.payload(), r.signature)) return false
        if (balance(r.consumerId) < total) return false
        val ownerBalance = runCatching { Math.addExact(balance(gateway.ownerId), total) }.getOrNull() ?: return false
        // If the disk write fails, NO in-memory transfer occurs.
        append("X|${r.id}|${r.gatewayId}|${r.consumerId}|${r.uplinkBytes}|${r.downlinkBytes}|${r.createdAtMs}|${r.signature}")
        balances[r.consumerId] = balance(r.consumerId) - total
        balances[gateway.ownerId] = ownerBalance
        recordedIds.add(r.id)
        return true
    }

    private fun append(record: String) {
        check(!faulted) { "Journal write failed previously: restart and investigate" }
        try {
            Files.createDirectories(journal.toAbsolutePath().parent)
            val chain = ProofCrypto.mac(journalSecret, "$tail|$record")
            val line = "$record|$chain\n".toByteArray(Charsets.UTF_8)
            FileChannel.open(journal, StandardOpenOption.CREATE, StandardOpenOption.WRITE, StandardOpenOption.APPEND).use { ch ->
                val buffer = ByteBuffer.wrap(line)
                while (buffer.hasRemaining()) ch.write(buffer)
                ch.force(true)
            }
            // A crash between file append and anchor commit produces a mismatch.
            // This is deliberately fail-closed, requiring an operator recovery.
            anchor.write(chain,recordCount+1)
            tail = chain
            recordCount++
        } catch (ex: Exception) {
            faulted=true
            throw ex
        }
    }

    private fun replayJournal() {
        if (!Files.exists(journal)) { anchor.validate(false,"GENESIS",0); return }
        var prev = "GENESIS"
        val rows=Files.readAllLines(journal, Charsets.UTF_8)
        rows.forEachIndexed { index, row ->
            val n = row.lastIndexOf('|')
            require(n > 0) { "Ledger journal truncated at line ${index + 1}" }
            val record = row.substring(0, n)
            val claimed = row.substring(n + 1)
            require(ProofCrypto.verify(journalSecret, "$prev|$record", claimed)) {
                "Ledger journal integrity failure at line ${index + 1}"
            }
            val fields = record.split('|')
            when (fields[0]) {
                "T" -> {
                    require(fields.size == 3)
                    checkId(fields[1])
                    val quota = fields[2].toLong()
                    require(quota in 1..TEST_CREDIT_MAX)
                    balances[fields[1]] = Math.addExact(balance(fields[1]), quota)
                }
                "R" -> {
                    require(fields.size == 4 && validId(fields[1]) && validId(fields[2]))
                    val bytes = fields[3].toLong()
                    require(bytes in 1..MAX_VOUCHER_RESERVATION_BYTES)
                    require(fields[2] !in reservedVoucherIds && balance(fields[1]) >= bytes)
                    balances[fields[1]] = balance(fields[1]) - bytes
                    reservedVoucherIds.add(fields[2])
                }
                "X" -> {
                    require(fields.size == 8)
                    val r = UsageReceipt(fields[1], fields[2], fields[3], fields[4].toLong(),
                        fields[5].toLong(), fields[6].toLong(), fields[7])
                    val gateway = trusted[r.gatewayId] ?: error("Unregistered gateway journal: ${r.gatewayId}")
                    require(validId(r.id) && validId(r.consumerId) && !recordedIds.contains(r.id))
                    require(gateway.ownerId != r.consumerId && r.uplinkBytes >= 0 && r.downlinkBytes >= 0)
                    val bytes = r.totalBytes
                    require(bytes in 1..MAX_RECEIPT_BYTES && balance(r.consumerId) >= bytes)
                    require(ProofCrypto.verify(gateway.secret, r.payload(), r.signature))
                    balances[r.consumerId] = balance(r.consumerId) - bytes
                    balances[gateway.ownerId] = Math.addExact(balance(gateway.ownerId), bytes)
                    recordedIds.add(r.id)
                }
                else -> error("Unknown ledger entry")
            }
            prev = claimed
        }
        anchor.validate(true,prev,rows.size.toLong())
        tail = prev
        recordCount=rows.size.toLong()
    }

    companion object {
        private const val MAX_SKEW_MS = 5 * 60 * 1000L
        private const val MAX_RECEIPT_BYTES = 200L * 1024 * 1024
        private const val MAX_VOUCHER_RESERVATION_BYTES = 50L * 1024 * 1024 * 1024 // 50 GiB
        private const val TEST_CREDIT_MAX = 1024L * 1024 * 1024
        private val ID = Regex("[A-Za-z0-9_-]{1,100}")
        private fun validId(v: String) = ID.matches(v)
        private fun checkId(v: String) { require(validId(v)) { "Invalid ledger ID" } }
    }
}
