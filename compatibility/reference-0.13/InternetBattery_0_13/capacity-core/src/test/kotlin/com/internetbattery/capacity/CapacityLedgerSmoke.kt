package com.internetbattery.capacity

import java.nio.file.Files
import java.util.Comparator
import java.time.Clock
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

object CapacityLedgerSmoke {
    @JvmStatic fun main(args: Array<String>) {
        val folder = Files.createTempDirectory("ib-ledger-test")
        val journal = folder.resolve("settlements.ledger")
        val gatewayKey = ByteArray(32) { (it * 3 + 11).toByte() }
        val journalKey = ByteArray(32) { (it * 2 + 7).toByte() }
        val trusted = listOf(TrustedGateway("gatewayA", "provider", gatewayKey))
        val signer = GatewayReceiptSigner("gatewayA", gatewayKey)
        val clock = Clock.systemUTC()
        val ledger = CapacityLedger(journal, journalKey, trusted, clock)
        val quota = 3_000L
        ledger.seedTestQuota("consumer", quota)
        val r1 = signer.sign("event_1", "consumer", 40, 60, clock.millis())
        check(ledger.settle(r1))
        check(ledger.balance("consumer") == quota - 100L)
        check(ledger.balance("provider") == 100L)
        println("PASS trusted metered transfer grants internal access units")
        check(!ledger.settle(r1))
        check(ledger.recordedCount() == 1)
        println("PASS replay/double settlement rejected")
        check(!ledger.settle(r1.copy(id="event_tampered")))
        check(!ledger.settle(r1.copy(downlinkBytes=5)))
        check(!ledger.settle(r1.copy(signature="fake")))
        println("PASS tampered receipt and forged signature rejected")
        check(!ledger.settle(signer.sign("event_too_big", "consumer", 99_000, 0, clock.millis())))
        check(!ledger.settle(signer.sign("event_stale", "consumer", 1, 0, clock.millis() - 3600_000L)))
        check(!ledger.settle(signer.sign("event_owner", "provider", 1, 0, clock.millis())))
        println("PASS overdraft/stale/self-payment rejected")
        val restored = CapacityLedger(journal, journalKey, trusted, clock)
        check(restored.balance("provider") == 100L && restored.balance("consumer") == quota - 100L)
        check(!restored.settle(r1))
        println("PASS durable restart and replay prevention")
        val pool = Executors.newFixedThreadPool(12)
        val ready = CountDownLatch(1)
        val settled = AtomicInteger()
        repeat(50) { k ->
            pool.submit {
                ready.await()
                val receipt=signer.sign("concurrent_$k", "consumer", 0, 100, clock.millis())
                if (restored.settle(receipt)) settled.incrementAndGet()
            }
        }
        ready.countDown();pool.shutdown()
        check(pool.awaitTermination(20, TimeUnit.SECONDS))
        check(settled.get() == 29) { "Expected exactly 29 successful settlements, got ${settled.get()}" }
        check(restored.balance("consumer") == 0L)
        check(restored.balance("provider") == 3_000L)
        println("PASS 50 concurrent settlements, exactly 29 permitted, no negative balance")
        val bytes = Files.readAllBytes(journal)
        val content = bytes.toString(Charsets.UTF_8)
        val replacement = content.replace("T|consumer|3000", "T|consumer|9000")
        check(content != replacement)
        Files.writeString(journal, replacement)
        val caught = runCatching { CapacityLedger(journal, journalKey, trusted, clock) }.isFailure
        check(caught) { "Tampered journal was accepted" }
        println("PASS persisted journal modification detected")
        Files.walk(folder).use { walk -> walk.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) } }
    }
}
