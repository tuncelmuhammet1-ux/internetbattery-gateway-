package com.internetbattery

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Experimental Android 13+ local credential storage.
 * Encrypts only the per-device 32-byte key, never the server master key.
 * Uses a non-exportable Android Keystore AES/GCM key and app-private preferences.
 * This is not a substitute for a full independent VPN/security audit.
 */
object LabKeyStore {
    private const val ALIAS = "ib-lab-device-aes-v1"
    private const val PREFS = "ib_lab_pairing_v1"
    private const val ENTRY = "encrypted_device_key"
    private val hex64 = Regex("[0-9a-fA-F]{64}")

    private fun key():SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val old = store.getKey(ALIAS, null) as? SecretKey
        if (old != null) return old
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .build()
        )
        return generator.generateKey()
    }

    fun read(context:Context):String {
        return try {
            val saved = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getString(ENTRY, null) ?: return ""
            val data = Base64.decode(saved, Base64.NO_WRAP)
            if (data.size <= 12 + 16) return ""
            val iv = data.copyOfRange(0, 12)
            val ciphertext = data.copyOfRange(12, data.size)
            val decrypt = Cipher.getInstance("AES/GCM/NoPadding")
            decrypt.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
            val value = String(decrypt.doFinal(ciphertext), Charsets.UTF_8)
            if (hex64.matches(value)) value else ""
        } catch (_:Exception) { "" }
    }

    fun save(context:Context,value:String) {
        if (!hex64.matches(value)) return
        try {
            val encrypt = Cipher.getInstance("AES/GCM/NoPadding")
            encrypt.init(Cipher.ENCRYPT_MODE, key())
            val encrypted = encrypt.iv + encrypt.doFinal(value.toByteArray(Charsets.UTF_8))
            val encoded = Base64.encodeToString(encrypted, Base64.NO_WRAP)
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit().putString(ENTRY,encoded).apply()
        } catch (_:Exception) { /* Require explicit re-entry if Keystore is unavailable */ }
    }

    fun clear(context:Context) {
        context.getSharedPreferences(PREFS,Context.MODE_PRIVATE)
            .edit().remove(ENTRY).apply()
    }
}
