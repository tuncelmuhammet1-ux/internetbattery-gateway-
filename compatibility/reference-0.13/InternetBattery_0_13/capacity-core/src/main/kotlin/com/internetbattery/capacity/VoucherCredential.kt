package com.internetbattery.capacity

import java.util.Base64

/** RFC 1929 password field: URL-safe ASCII, <=255 bytes. The password IS a bearer
 * credential: it MUST be transferred via trusted pairing, never logged, and never
 * shared with arbitrary peers. A voucher remains gateway-bound and short-lived. */
object VoucherCredential {
    private const val PREFIX="IB1."
    fun encode(v: PortableVoucher): String {
        val joined = v.payload() + "|" + v.signature
        val token = PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(joined.toByteArray(Charsets.UTF_8))
        require(token.length in 1..255) { "Voucher is too long for SOCKS5 credential; use shorter identifiers" }
        return token
    }
    fun decode(token: String): PortableVoucher? = runCatching {
        require(token.length in 5..255 && token.startsWith(PREFIX))
        val text = Base64.getUrlDecoder().decode(token.removePrefix(PREFIX)).toString(Charsets.UTF_8)
        val fields = text.split('|')
        require(fields.size == 7)
        require(fields[0].matches(Regex("[A-Za-z0-9_-]{1,100}")))
        require(fields[1].matches(Regex("[A-Za-z0-9_-]{1,100}")))
        require(fields[2].matches(Regex("[A-Za-z0-9_-]{1,100}")))
        val voucher = PortableVoucher(fields[0],fields[1],fields[2],fields[3].toLong(),
            fields[4].toLong(),fields[5].toLong(),fields[6])
        require(encode(voucher) == token) { "Non-canonical encoding" }
        voucher
    }.getOrNull()
}
