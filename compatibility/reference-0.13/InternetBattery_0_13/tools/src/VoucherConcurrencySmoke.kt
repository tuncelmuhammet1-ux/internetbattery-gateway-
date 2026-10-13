import com.internetbattery.capacity.*
import com.internetbattery.roaming.VoucherTransferAllowance
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/** Lab-only policy test. Cannot be redeemed for mobile carrier data. */
object VoucherConcurrencySmoke {
    @JvmStatic fun main(args: Array<String>) {
        val dir=Files.createTempDirectory("ib-budget-concurrency")
        try {
            val key=ByteArray(32){(it+1).toByte()}
            val ledger=CapacityLedger(dir.resolve("issuer.journal"),key,emptyList())
            ledger.seedTestQuota("laboratory-user",100)
            val kp=KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
            val ticket=VoucherIssuer(ledger,kp.private).issue("laboratory-user","quota-ticket","test-gateway",100)!!
            val verifier=LocalGatewayVoucherVerifier("test-gateway",kp.public,dir.resolve("site.journal"),key)
            val allowance=VoucherTransferAllowance(ticket,"laboratory-user",verifier)
            check(allowance.grant(20,true)==20)
            check(allowance.grant(85,true)==0) // Never truncate datagrams
            val start=CountDownLatch(1)
            val done=CountDownLatch(25)
            val credited=AtomicInteger(0)
            repeat(25) { thread(isDaemon=true) {
                try { start.await();credited.addAndGet(allowance.grant(10,false)) }
                finally { done.countDown() }
            } }
            start.countDown();done.await()
            check(credited.get()==80) { "Expected 80 granted, got ${credited.get()}" }
            check(verifier.spentBytes(ticket.voucherId)==100L)
            check(allowance.grant(1,false)==0)
            println("PASS 25 concurrent sockets cannot exceed 100 byte durable signed quota")
            println("PASS UDP datagrams are all-or-nothing; full signed quota accounted")
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }
}
