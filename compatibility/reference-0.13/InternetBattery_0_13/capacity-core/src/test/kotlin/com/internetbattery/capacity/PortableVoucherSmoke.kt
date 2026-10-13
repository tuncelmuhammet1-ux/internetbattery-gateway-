package com.internetbattery.capacity

import java.nio.file.Files
import java.security.KeyPairGenerator
import java.time.Clock
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

object PortableVoucherSmoke {
    @JvmStatic fun main(args: Array<String>) {
        val folder=Files.createTempDirectory("ib-portable-voucher")
        val accountFile=folder.resolve("account.ledger")
        val spendFile=folder.resolve("gateway-b.spends")
        val gateKey=ByteArray(32){(it+1).toByte()}
        val macKey=ByteArray(32){(it+19).toByte()}
        val issuerKeys=KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val clock=Clock.systemUTC()
        try {
            val account=CapacityLedger(accountFile,macKey,listOf(TrustedGateway("home-gateway","alice",gateKey)),clock)
            account.seedTestQuota("bob",250)
            check(account.settle(GatewayReceiptSigner("home-gateway",gateKey).sign("home-traffic","bob",40,60,clock.millis())))
            check(account.balance("alice")==100L)
            val voucher=VoucherIssuer(account,issuerKeys.private,clock).issue("alice","travel-ticket-01","participating-cafe",60,10)
                ?: error("Voucher should be issued from earned balance")
            check(account.balance("alice")==40L)
            check(VoucherIssuer(account,issuerKeys.private,clock).issue("alice","travel-ticket-01","participating-cafe",60,10)==null)
            println("PASS earned internal units reserved at home to signed gateway-bound voucher")
            val outside=LocalGatewayVoucherVerifier("participating-cafe",issuerKeys.public,spendFile,macKey,clock)
            check(outside.spend(voucher,30,"alice"))
            check(outside.spend(voucher,20,"alice"))
            check(!outside.spend(voucher,11,"alice"))
            check(outside.spentBytes(voucher.voucherId)==50L)
            println("PASS 50 real-metered unit charges offline; over-quota rejected")
            check(!outside.spend(voucher.copy(quotaBytes=999),1,"alice"))
            check(!outside.spend(voucher,1,"eve"))
            check(!LocalGatewayVoucherVerifier("different-gateway",issuerKeys.public,folder.resolve("other.spends"),macKey,clock).spend(voucher,1,"alice"))
            println("PASS forged quota, unauthorized holder and wrong gateway denied")
            val afterRestart=LocalGatewayVoucherVerifier("participating-cafe",issuerKeys.public,spendFile,macKey,clock)
            check(afterRestart.spentBytes(voucher.voucherId)==50L)
            println("PASS offline gateway usage survives process restart")
            val pool=Executors.newFixedThreadPool(8)
            val latch=CountDownLatch(1)
            val ok=AtomicInteger()
            repeat(50) {
                pool.submit {
                    latch.await()
                    if (afterRestart.spend(voucher,1,"alice")) ok.incrementAndGet()
                }
            }
            latch.countDown();pool.shutdown()
            check(pool.awaitTermination(20,TimeUnit.SECONDS))
            check(ok.get()==10 && afterRestart.spentBytes(voucher.voucherId)==60L)
            println("PASS concurrent gateway charging stops exactly at signed voucher quota")
            val old=Files.readString(spendFile)
            check(old.contains("S|travel-ticket-01|30"))
            Files.writeString(spendFile,old.replace("S|travel-ticket-01|30","S|travel-ticket-01|80"))
            check(runCatching { LocalGatewayVoucherVerifier("participating-cafe",issuerKeys.public,spendFile,macKey,clock) }.isFailure)
            println("PASS voucher usage journal tampering rejected")
        } finally { Files.walk(folder).sorted(Comparator.reverseOrder()).forEach{Files.deleteIfExists(it)} }
    }
}
