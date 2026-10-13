package com.internetbattery

import java.util.Base64

/**
 * Transport-level validation for Java/Node interoperable IB1 Ed25519 vouchers.
 * The Android app never trusts a voucher as credit until a TLS-authenticated
 * gateway confirms a positive remaining balance.
 */
object Ib1VoucherInput {
    data class Preview(
        val voucherId:String, val holderId:String, val gatewayId:String,
        val quotaBytes:Long, val expiresAtMs:Long
    )
    private val safe=Regex("[A-Za-z0-9_-]{1,100}")
    private val numeric=Regex("(0|[1-9][0-9]*)")
    fun decode(token:String,expectedHolder:String,nowMs:Long=System.currentTimeMillis()):Preview {
        require(token.length in 5..255 && token.startsWith("IB1.")) { "IB1 belge biçimi geçersiz" }
        val encoded=token.substring(4)
        require(encoded.matches(Regex("[A-Za-z0-9_-]+"))) { "IB1 karakterleri geçersiz" }
        val bytes=Base64.getUrlDecoder().decode(encoded)
        require(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)==encoded) { "IB1 kodlama değişmiş" }
        val text=bytes.toString(Charsets.UTF_8)
        require(!text.contains('\uFFFD')){"IB1 UTF-8 geçersiz"}
        val fields=text.split('|')
        require(fields.size==7 && fields.take(3).all(safe::matches)){"IB1 alanları geçersiz"}
        require(fields[1]==expectedHolder){"Belge farklı kullanıcıya ait"}
        require(fields.subList(3,6).all(numeric::matches)){"Belgede geçersiz sayılar var"}
        val quota=fields[3].toLong()
        val issued=fields[4].toLong()
        val expiry=fields[5].toLong()
        require(quota in 1..(50L*1024*1024*1024)){"IB1 kota alanı geçersiz"}
        require(issued>0 && issued<=nowMs+60_000 && expiry>nowMs && expiry>issued && expiry-issued<=24*3600_000){"Belgenin süresi geçersiz"}
        val sig=fields[6]
        require(sig.matches(Regex("[A-Za-z0-9_-]+"))){"IB1 imzası geçersiz"}
        val binarySignature=Base64.getUrlDecoder().decode(sig)
        require(binarySignature.size==64 && Base64.getUrlEncoder().withoutPadding().encodeToString(binarySignature)==sig){"IB1 imzası geçersiz"}
        return Preview(fields[0],fields[1],fields[2],quota,expiry)
    }
}
