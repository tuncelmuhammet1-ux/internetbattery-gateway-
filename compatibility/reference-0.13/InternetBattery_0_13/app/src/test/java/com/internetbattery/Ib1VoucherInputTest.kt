package com.internetbattery

import org.junit.Assert.*
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64

class Ib1VoucherInputTest {
    private fun token(
        id:String="v13", holder:String="prov13",gateway:String="gate-b",
        quota:Long=24000L,issued:Long=System.currentTimeMillis(),
        expires:Long=issued+600_000
    ):String {
        val p="$id|$holder|$gateway|$quota|$issued|$expires"
        val kp=KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val sig=Signature.getInstance("Ed25519").apply {
            initSign(kp.private);update(p.toByteArray(Charsets.UTF_8))
        }.sign()
        return "IB1."+Base64.getUrlEncoder().withoutPadding().encodeToString(
            (p+"|"+Base64.getUrlEncoder().withoutPadding().encodeToString(sig)).toByteArray(Charsets.UTF_8))
    }
    @Test fun canonicalJavaVoucherCanBeRead(){
        val v=Ib1VoucherInput.decode(token(),"prov13")
        assertEquals(24000L,v.quotaBytes)
        assertEquals("gate-b",v.gatewayId)
    }
    @Test fun rejectsOtherHolder(){
        try{Ib1VoucherInput.decode(token(),"other");fail("different holder")}catch(_:IllegalArgumentException){}
    }
    @Test fun rejectsExpired(){
        val past=System.currentTimeMillis()-600_000
        try{Ib1VoucherInput.decode(token(issued=past-60000,expires=past),"prov13");fail("expired")}catch(_:IllegalArgumentException){}
    }
    @Test fun rejectsNoncanonicalInput(){
        try{Ib1VoucherInput.decode("IB1.A=","prov13");fail("bad b64")}catch(_:IllegalArgumentException){}
    }
    @Test fun rejectsOversizedBearerString(){
        try{Ib1VoucherInput.decode("IB1."+"a".repeat(255),"prov13");fail("oversized")}catch(_:IllegalArgumentException){}
    }
    @Test fun rejectsUnknownFormat(){
        try{Ib1VoucherInput.decode("jwt.token","prov13");fail("wrong prefix")}catch(_:IllegalArgumentException){}
    }
}
