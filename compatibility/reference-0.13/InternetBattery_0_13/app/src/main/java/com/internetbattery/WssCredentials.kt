package com.internetbattery

import java.net.URI
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Protocol v0.9 authentication shared by the Android VPN bridge and preflight. */
object WssCredentials {
    private val idPattern=Regex("[a-z0-9-]{3,40}")
    private val noncePattern=Regex("[a-f0-9]{24,64}")

    fun validateAddress(url:String):URI {
        val uri=URI(url)
        require(uri.scheme=="wss" && !uri.host.isNullOrBlank()){"WSS/TLS adresi gerekli"}
        require(uri.rawPath=="/tunnel" && uri.rawUserInfo==null &&
                uri.rawQuery==null && uri.rawFragment==null){"WSS adresi /tunnel ile bitmeli"}
        require(uri.port==-1 || uri.port in 1..65535){"Port geçersiz"}
        return uri
    }

    fun validateDeviceId(id:String) {
        require(idPattern.matches(id)){"Cihaz ID: 3–40 küçük harf/rakam/tire"}
    }

    fun hexKey(hex:String):ByteArray=BridgeWire.hexDecode(hex)

    fun authenticate(id:String,key:ByteArray,timestampMs:Long,nonce:String):Map<String,String> {
        validateDeviceId(id)
        require(key.size==32){"Cihaz anahtarı 32 bayt olmalı"}
        require(timestampMs>0){"Saat geçersiz"}
        require(noncePattern.matches(nonce)){"Nonce geçersiz"}
        val signed="$id\n$timestampMs\n$nonce"
        val signature=Mac.getInstance("HmacSHA256").apply {
            init(SecretKeySpec(key,"HmacSHA256"))
        }.doFinal(signed.toByteArray(Charsets.UTF_8))
           .joinToString("") { "%02x".format(it.toInt() and 255) }
        return mapOf(
            "x-ib-id" to id,
            "x-ib-ts" to timestampMs.toString(),
            "x-ib-nonce" to nonce,
            "x-ib-mac" to signature,
        )
    }
}
