package com.internetbattery

import android.content.Context
import com.internetbattery.capacity.LocalGatewayVoucherVerifier
import com.internetbattery.roaming.VoucherSessionAuthorizer
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/** LAB-ONLY: a trusted gateway operator manually installs the issuer public key.
 * The journal MAC key is stored in Android's private application preferences.
 * Clearing application data or restoring an old device snapshot can reset spent
 * state; a production provider MUST reconcile with a trusted central ledger. */
object VoucherGatewayProvision {
    fun authorize(context: Context, gatewayId: String, issuerPublicKeyB64: String): VoucherSessionAuthorizer {
        require(gatewayId.matches(Regex("[A-Za-z0-9_-]{1,100}"))) { "Gateway kimliği geçersiz" }
        val raw = Base64.getUrlDecoder().decode(issuerPublicKeyB64)
        require(raw.size in 32..256) { "Issuer public key geçersiz" }
        val publicKey=KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(raw))
        // Separate journals/secret per issuer + physical gateway identity.
        val namespace = java.security.MessageDigest.getInstance("SHA-256")
            .digest((gatewayId + ":" + issuerPublicKeyB64).toByteArray(Charsets.UTF_8))
            .take(16).joinToString("") { "%02x".format(it) }
        val pref=context.getSharedPreferences("ib-private-voucher-secrets", Context.MODE_PRIVATE)
        val keyPref="hmac_" + namespace
        val journalKey = synchronized(this) {
            val found=pref.getString(keyPref,null)
            if (found != null) Base64.getDecoder().decode(found)
            else ByteArray(32).also { SecureRandom().nextBytes(it) }.also { secret ->
                check(pref.edit().putString(keyPref,Base64.getEncoder().encodeToString(secret)).commit()) {
                    "Kalıcı journal anahtarı saklanamadı"
                }
            }
        }
        val journal=java.io.File(context.filesDir,"voucher-$namespace.journal").toPath()
        val verifier=LocalGatewayVoucherVerifier(gatewayId,publicKey,journal,journalKey)
        return VoucherSessionAuthorizer(verifier)
    }
}
