package com.internetbattery.capacity

import java.nio.file.Files
import java.security.KeyPairGenerator

/** Validates multi-gigabyte RIGHTS accounting, never pretends to transmit that many bytes. */
object HighCapacityVoucherSmoke {
    @JvmStatic fun main(args: Array<String>) {
        val dir = Files.createTempDirectory("ib08-highcap-")
        try {
            val ledgerFile = dir.resolve("ledger.journal")
            val spendFile = dir.resolve("away.journal")
            val ledgerKey = ByteArray(32) { (it + 41).toByte() }
            val voucherKey = ByteArray(32) { (it + 83).toByte() }
            val pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
            val ledger = CapacityLedger(ledgerFile, ledgerKey, emptyList())
            val gb = 1024L * 1024 * 1024
            repeat(4) { ledger.seedTestQuota("holder", gb) } // Explicit LAB test units only
            check(ledger.balance("holder") == 4 * gb)
            val issuer = VoucherIssuer(ledger, pair.private)
            val voucher = issuer.issue("holder", "three-gb-001", "away", 3 * gb)
                ?: error("Valid 3GiB voucher was refused")
            check(VoucherCredential.encode(voucher).toByteArray(Charsets.US_ASCII).size <= 255)
            check(ledger.balance("holder") == gb)
            val away = LocalGatewayVoucherVerifier("away", pair.public, spendFile, voucherKey)
            check(away.canSpend(voucher, "holder"))
            check(away.spend(voucher, 65_536, "holder"))
            check(away.spentBytes(voucher.voucherId) == 65_536L)
            check(!away.canSpend(voucher.copy(quotaBytes = 4 * gb), "holder"))
            println("PASS experimental 3 GiB signed voucher issuance, transport encoding and partial consumption")
            val afterRestart = LocalGatewayVoucherVerifier("away", pair.public, spendFile, voucherKey)
            check(afterRestart.spentBytes(voucher.voucherId) == 65_536L)
            check(afterRestart.canSpend(voucher, "holder"))
            val recovered = CapacityLedger(ledgerFile, ledgerKey, emptyList())
            check(recovered.balance("holder") == gb)
            println("PASS multi-GiB ledger and journal reload without balance loss")
            // Isolate the upper-bound check from insufficient funds: the holder now
            // has MORE than 51 GiB of explicit, test-only units in the ledger.
            repeat(51) { recovered.seedTestQuota("holder", gb) }
            check(recovered.balance("holder") == 52 * gb)
            val oversized = VoucherIssuer(recovered, pair.private).issue("holder", "too-large", "away", 51 * gb)
            check(oversized == null && recovered.balance("holder") == 52 * gb)
            val maxAllowed = VoucherIssuer(recovered, pair.private).issue("holder", "fifty-gb", "away", 50 * gb)
                ?: error("Valid 50 GiB experimental voucher unexpectedly denied")
            check(VoucherCredential.encode(maxAllowed).toByteArray(Charsets.US_ASCII).size <= 255)
            check(recovered.balance("holder") == 2 * gb)
            check(afterRestart.canSpend(maxAllowed,"holder"))
            println("PASS 51 GiB voucher is rejected despite sufficient test funds, exactly 50 GiB is accepted")
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }
}
