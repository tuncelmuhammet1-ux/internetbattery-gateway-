package com.internetbattery.capacity

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption

/**
 * Separate MAC-authenticated local journal head checkpoint.
 * A truncated/missing tail of ONE journal file is detected if its checkpoint
 * remains present. Fail CLOSED on any missing/mismatched checkpoint.
 *
 * LIMITATIONS: This does not defeat an attacker who can roll back BOTH files,
 * restore an entire device image, replace the journal key, or compromise the
 * server. Durable production credit needs a remotely anchored monotonic counter.
 */
internal class JournalIntegrityAnchor(private val journal: Path, secret: ByteArray) {
    private val key = secret.copyOf()
    private val checkpoint = journal.resolveSibling(journal.fileName.toString() + ".anchor")

    fun validate(exists: Boolean, tail: String, count: Long) {
        val checkpointExists = Files.exists(checkpoint)
        if (!exists) {
            require(!checkpointExists) { "Journal removed but signed checkpoint still exists" }
            return
        }
        require(checkpointExists) { "Journal checkpoint missing (refuse silent rollback)" }
        val expected = proof(tail,count)
        val actual = Files.readString(checkpoint).trimEnd('\n')
        require(ProofCrypto.verify(key,"IB_JOURNAL_ANCHOR_V1|$tail|$count",actual)) {
            "Journal rollback or checkpoint modification detected"
        }
        require(actual == expected) { "Noncanonical checkpoint" }
    }

    private fun proof(tail: String, count: Long): String =
        ProofCrypto.mac(key,"IB_JOURNAL_ANCHOR_V1|$tail|$count")

    fun write(tail: String, count: Long) {
        Files.createDirectories(checkpoint.toAbsolutePath().parent)
        val temp = Files.createTempFile(checkpoint.toAbsolutePath().parent, "ib-anchor-", ".part")
        try {
            val bytes=(proof(tail,count)+"\n").toByteArray(Charsets.US_ASCII)
            FileChannel.open(temp,StandardOpenOption.WRITE).use { ch ->
                val buffer=ByteBuffer.wrap(bytes)
                while(buffer.hasRemaining()) ch.write(buffer)
                ch.force(true)
            }
            // Fails closed if atomic replacement is unavailable.
            Files.move(temp,checkpoint,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING)
        } finally { Files.deleteIfExists(temp) }
    }
}
