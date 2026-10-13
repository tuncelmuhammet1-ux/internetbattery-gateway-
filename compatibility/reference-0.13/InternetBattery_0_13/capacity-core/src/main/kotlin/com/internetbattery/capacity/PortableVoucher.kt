package com.internetbattery.capacity

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.time.Clock
import java.util.Base64

/**
 * Network member's OFFLINE verifiable roaming ticket. Not a SIM/eSIM/mobile data plan.
 * Binds usage rights to ONE participating physical gateway to avoid offline
 * cross-gateway double-spending. That gateway must have genuine internet access.
 */
data class PortableVoucher(
    val voucherId: String,
    val holderId: String,
    val targetGateway: String,
    val quotaBytes: Long,
    val issuedAtMs: Long,
    val expiresAtMs: Long,
    val signature: String = ""
) {
    fun payload(): String = listOf(voucherId,holderId,targetGateway,quotaBytes,issuedAtMs,expiresAtMs).joinToString("|")
}

/** Central issuer: authorizes by reserving internal units before releasing voucher. */
class VoucherIssuer(private val ledger: CapacityLedger, private val privateKey: PrivateKey, private val clock: Clock = Clock.systemUTC()) {
    fun issue(holderId: String, voucherId: String, targetGateway: String, bytes: Long, validityMinutes: Long = 30): PortableVoucher? {
        require(validityMinutes in 1..1440)
        require(listOf(holderId,voucherId,targetGateway).all { it.matches(Regex("[A-Za-z0-9_-]{1,100}")) })
        val now=clock.millis()
        val draft=PortableVoucher(voucherId,holderId,targetGateway,bytes,now,now+validityMinutes*60_000)
        val signature=Signature.getInstance("Ed25519").apply {
            initSign(privateKey); update(draft.payload().toByteArray(Charsets.UTF_8))
        }.sign()
        val signed = draft.copy(signature=Base64.getUrlEncoder().withoutPadding().encodeToString(signature))
        // Verify transport encoding BEFORE any irreversible reservation: SOCKS5
        // RFC1929 credentials have a strict 255-byte length ceiling.
        require(VoucherCredential.encode(signed).toByteArray(Charsets.US_ASCII).size <= 255) {
            "Voucher does not fit the SOCKS5 credential format"
        }
        if (!ledger.reserveForVoucher(holderId,voucherId,bytes)) return null
        return signed
    }
}

/**
 * Gateway-local, durable, offline verifier. The issuer's PUBLIC key is provisioned in
 * advance (e.g., via signed application configuration). No server call at spend time.
 * Transactions are MAC chained. Save happens before approving bytes; crash may cause
 * an over-debit, never free usage. Real product needs lease/refund/recovery protocol.
 */
class LocalGatewayVoucherVerifier(
    private val gatewayId: String,
    private val issuerPublicKey: PublicKey,
    private val journal: Path,
    journalKey: ByteArray,
    private val clock: Clock = Clock.systemUTC()
) {
    private val key = journalKey.copyOf()
    private val spent = mutableMapOf<String, Long>()
    private var chain = "GENESIS"
    private var recordCount = 0L
    private var faulted = false
    private val anchor = JournalIntegrityAnchor(journal,key)
    init {
        require(gatewayId.matches(Regex("[A-Za-z0-9_-]{1,100}")))
        require(key.size >= 32)
        restore()
    }

    @Synchronized fun spentBytes(voucherId: String): Long = spent[voucherId] ?: 0L

    /** Verify eligibility WITHOUT deducting credit or creating an outbound connection. */
    @Synchronized fun canSpend(v: PortableVoucher, authenticatedHolder: String): Boolean {
        if (v.targetGateway != gatewayId || authenticatedHolder != v.holderId) return false
        if (!v.voucherId.matches(Regex("[A-Za-z0-9_-]{1,100}"))) return false
        if (v.quotaBytes !in 1..MAX_VOUCHER_BYTES) return false
        val now=clock.millis()
        if (v.issuedAtMs > now+60_000 || v.expiresAtMs <= now || v.expiresAtMs-v.issuedAtMs > 86_400_000) return false
        if (!signatureValid(v)) return false
        return spentBytes(v.voucherId) < v.quotaBytes
    }

    @Synchronized fun spend(v: PortableVoucher, actualMeteredBytes: Long, authenticatedHolder: String): Boolean {
        if (actualMeteredBytes <= 0 || actualMeteredBytes > MAX_SPEND_CHUNK) return false
        if (!canSpend(v, authenticatedHolder)) return false
        val newTotal=runCatching { Math.addExact(spentBytes(v.voucherId),actualMeteredBytes) }.getOrNull() ?: return false
        if (newTotal > v.quotaBytes) return false
        val entry="S|${v.voucherId}|$actualMeteredBytes"
        append(entry)
        spent[v.voucherId]=newTotal
        return true
    }

    private fun signatureValid(v: PortableVoucher): Boolean = runCatching {
        val bytes=Base64.getUrlDecoder().decode(v.signature)
        Signature.getInstance("Ed25519").apply { initVerify(issuerPublicKey); update(v.payload().toByteArray(Charsets.UTF_8)) }.verify(bytes)
    }.getOrDefault(false)

    private fun append(entry: String) {
        check(!faulted) { "Voucher journal write failed; restart and investigate" }
        try {
            Files.createDirectories(journal.toAbsolutePath().parent)
            val mac = ProofCrypto.mac(key,"$chain|$entry")
            val buffer=ByteBuffer.wrap("$entry|$mac\n".toByteArray(Charsets.UTF_8))
            FileChannel.open(journal,StandardOpenOption.CREATE,StandardOpenOption.WRITE,StandardOpenOption.APPEND).use { file ->
                while (buffer.hasRemaining()) file.write(buffer)
                file.force(true)
            }
            anchor.write(mac,recordCount+1)
            chain=mac
            recordCount++
        } catch (ex: Exception) {
            faulted=true
            throw ex
        }
    }

    private fun restore() {
        if (!Files.exists(journal)) { anchor.validate(false,"GENESIS",0); return }
        var prev="GENESIS"
        val rows=Files.readAllLines(journal,Charsets.UTF_8)
        rows.forEachIndexed { idx,line ->
            val pos=line.lastIndexOf('|')
            require(pos>0) { "Voucher journal corrupt at line ${idx+1}" }
            val record=line.substring(0,pos)
            val sig=line.substring(pos+1)
            require(ProofCrypto.verify(key,"$prev|$record",sig)) { "Voucher journal was modified at line ${idx+1}" }
            val fields=record.split('|')
            require(fields.size==3 && fields[0]=="S" && fields[1].matches(Regex("[A-Za-z0-9_-]{1,100}")))
            val delta=fields[2].toLong()
            require(delta in 1..MAX_SPEND_CHUNK)
            spent[fields[1]]=Math.addExact(spentBytes(fields[1]),delta)
            prev=sig
        }
        anchor.validate(true,prev,rows.size.toLong())
        chain=prev
        recordCount=rows.size.toLong()
    }

    companion object {
        private const val MAX_VOUCHER_BYTES=50L*1024*1024*1024 // 50 GiB experimental cap
        private const val MAX_SPEND_CHUNK=10L*1024*1024
    }
}
