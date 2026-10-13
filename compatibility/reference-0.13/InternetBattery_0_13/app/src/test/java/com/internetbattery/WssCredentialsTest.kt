package com.internetbattery

import org.junit.Assert.*
import org.junit.Test
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class WssCredentialsTest {
    @Test fun acceptedEndpoint() {
        assertEquals("relay.example.com",WssCredentials.validateAddress("wss://relay.example.com/tunnel").host)
    }

    @Test fun insecureAndMisleadingEndpointRejected() {
        listOf("ws://relay.example.com/tunnel","https://relay.example.com/tunnel",
                "wss://relay.example.com/not-tunnel",
                "wss://user:pass@relay.example.com/tunnel",
                "wss://relay.example.com/tunnel?token=123").forEach {
            try { WssCredentials.validateAddress(it);fail("bad url accepted: $it") }
            catch(_:IllegalArgumentException){}
        }
    }

    @Test fun signedHeadersMatchHmacReference() {
        val key=ByteArray(32){0x55.toByte()}
        val nonce="a3".repeat(16)
        val ts=1791800000000L
        val value=WssCredentials.authenticate("test-device-1",key,ts,nonce)
        val ref=Mac.getInstance("HmacSHA256").apply {
            init(SecretKeySpec(key,"HmacSHA256"))
        }.doFinal("test-device-1\n$ts\n$nonce".toByteArray()).joinToString("") { "%02x".format(it.toInt() and 255) }
        assertEquals(ref,value.getValue("x-ib-mac"))
        assertEquals(64,value.getValue("x-ib-mac").length)
    }

    @Test fun changedIdChangesSignature() {
        val k=ByteArray(32){1}
        val a=WssCredentials.authenticate("user-1",k,1L,"ab".repeat(16))
        val b=WssCredentials.authenticate("user-2",k,1L,"ab".repeat(16))
        assertNotEquals(a["x-ib-mac"],b["x-ib-mac"])
    }

    @Test fun shortSecretOrBadIdRejected() {
        try { WssCredentials.authenticate("user-1",ByteArray(5),1L,"ab".repeat(16));fail("weak key") }
        catch(_:IllegalArgumentException){}
        try { WssCredentials.authenticate("USER",ByteArray(32),1L,"ab".repeat(16));fail("bad ID") }
        catch(_:IllegalArgumentException){}
    }

    @Test fun shortNonceRejected() {
        try { WssCredentials.authenticate("user-1",ByteArray(32),1L,"abc");fail("nonce too short") }
        catch(_:IllegalArgumentException){}
    }
}
