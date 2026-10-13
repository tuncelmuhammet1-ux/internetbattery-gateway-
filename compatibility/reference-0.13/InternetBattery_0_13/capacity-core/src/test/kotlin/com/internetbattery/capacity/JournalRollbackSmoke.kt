package com.internetbattery.capacity

import java.nio.file.Files
import java.security.KeyPairGenerator
import java.security.SecureRandom

/** Tests LOCAL journal tail truncation detection. Not protection against full disk snapshots. */
object JournalRollbackSmoke {
    private fun key()=ByteArray(32).also(SecureRandom()::nextBytes)
    @JvmStatic fun main(args:Array<String>) {
        val dir=Files.createTempDirectory("ib-journal-anchor-")
        val gatewaySecret=key()
        val ledgerSecret=key()
        val ledgerPath=dir.resolve("wallet.journal")
        val gateways=listOf(TrustedGateway("home","owner",gatewaySecret))
        val ledger=CapacityLedger(ledgerPath,ledgerSecret,gateways)
        ledger.seedTestQuota("consumer",100)
        ledger.seedTestQuota("consumer",50)
        check(Files.exists(dir.resolve("wallet.journal.anchor")))
        val reopened=CapacityLedger(ledgerPath,ledgerSecret,gateways)
        check(reopened.balance("consumer")==150L)
        Files.writeString(ledgerPath,Files.readAllLines(ledgerPath).first()+"\n")
        check(runCatching { CapacityLedger(ledgerPath,ledgerSecret,gateways) }.isFailure)
        println("PASS truncating a valid MAC-chained credit journal tail is detected by separate signed checkpoint")

        val issuer=KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val sourcePath=dir.resolve("funded.journal")
        val sourceLedger=CapacityLedger(sourcePath,key(),gateways)
        sourceLedger.seedTestQuota("owner",100)
        val token=VoucherIssuer(sourceLedger,issuer.private).issue("owner","voucher1","remote",40,60)!!
        val spentPath=dir.resolve("remote.spent")
        val spentKey=key()
        val verifier=LocalGatewayVoucherVerifier("remote",issuer.public,spentPath,spentKey)
        check(verifier.spend(token,20,"owner"))
        check(verifier.spend(token,10,"owner"))
        check(LocalGatewayVoucherVerifier("remote",issuer.public,spentPath,spentKey).spentBytes("voucher1")==30L)
        Files.writeString(spentPath,Files.readAllLines(spentPath).first()+"\n")
        check(runCatching { LocalGatewayVoucherVerifier("remote",issuer.public,spentPath,spentKey) }.isFailure)
        println("PASS truncating voucher-spend journal tail is detected: expired/replayed quota cannot be silently recovered")

        // Deleting the anchor should not be interpreted as a new installation.
        val forgotten=dir.resolve("forgotten.journal")
        val testKey=key()
        val testLedger=CapacityLedger(forgotten,testKey,gateways)
        testLedger.seedTestQuota("consumer",5)
        Files.delete(forgotten.resolveSibling("forgotten.journal.anchor"))
        check(runCatching { CapacityLedger(forgotten,testKey,gateways) }.isFailure)
        println("PASS deleting a journal checkpoint refuses startup (fail closed; manual operator recovery required)")
        // A full rollback of BOTH files and keys remains possible without remote anchoring.
        println("NOTE full device snapshot rollback / compromised disk is NOT solved by a local checkpoint")
    }
}
