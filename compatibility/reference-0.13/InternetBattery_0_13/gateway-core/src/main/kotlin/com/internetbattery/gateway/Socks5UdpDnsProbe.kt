package com.internetbattery.gateway

import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom

/**
 * Independent client-side SOCKS5 UDP ASSOCIATE + DNS probe.
 * Tests transport that HTTPS/TCP probes alone cannot validate. No Android APIs;
 * available to JVM tests and the actual Android application.
 *
 * The returned result confirms ONE DNS exchange across the authenticated gateway,
 * not that every app, game or QUIC session has been tested.
 */
object Socks5UdpDnsProbe {
    data class Result(val responseCode: Int, val answers: Int, val elapsedMs: Long)

    fun queryA(
        gatewayIpv4: String, port: Int, username: String, password: String,
        resolverIpv4: String = "1.1.1.1", resolverPort: Int = 53,
        hostname: String = "example.com", timeoutMs: Int = 8_000
    ): Result {
        require(port in 1..65535 && resolverPort in 1..65535 && timeoutMs in 100..60000)
        val gateway=InetAddress.getByName(gatewayIpv4)
        val resolver=InetAddress.getByName(resolverIpv4)
        require(gateway is Inet4Address && resolver is Inet4Address) { "IPv4 gateway and resolver required" }
        val id=SecureRandom().nextInt(65536)
        val question=dnsQuestion(hostname,id)
        val started=System.nanoTime()
        Socket().use { control ->
            control.soTimeout=timeoutMs
            control.connect(InetSocketAddress(gateway,port),timeoutMs)
            val input=DataInputStream(control.getInputStream())
            val output=control.getOutputStream()
            output.write(byteArrayOf(5,1,2));output.flush()
            check(input.readUnsignedByte()==5 && input.readUnsignedByte()==2) { "SOCKS5 authentication unsupported" }
            val u=username.toByteArray(Charsets.UTF_8)
            val p=password.toByteArray(Charsets.UTF_8)
            require(u.size in 1..255 && p.size in 1..255)
            output.write(byteArrayOf(1,u.size.toByte())+u+byteArrayOf(p.size.toByte())+p)
            output.flush()
            check(input.readUnsignedByte()==1 && input.readUnsignedByte()==0) { "Gateway rejected credentials" }
            // 0.0.0.0:0 requests UDP relay with client's port negotiated by first datagram.
            output.write(byteArrayOf(5,3,0,1,0,0,0,0,0,0));output.flush()
            check(input.readUnsignedByte()==5)
            val status=input.readUnsignedByte()
            check(status==0) { "Gateway rejected UDP ASSOCIATE ($status)" }
            check(input.readUnsignedByte()==0)
            val atyp=input.readUnsignedByte()
            val udpServer=when(atyp) {
                1 -> ByteArray(4).also { input.readFully(it) }.let { InetAddress.getByAddress(it) }
                4 -> ByteArray(16).also { input.readFully(it) }.let { InetAddress.getByAddress(it) }
                3 -> ByteArray(input.readUnsignedByte()).also { input.readFully(it) }
                    .let { InetAddress.getByName(it.toString(Charsets.UTF_8)) }
                else -> error("Malformed SOCKS5 UDP endpoint")
            }
            val udpPort=input.readUnsignedShort()
            check(udpPort in 1..65535)
            // Some servers use 0.0.0.0 to mean 'same IP as TCP control'.
            val relay=if(udpServer.isAnyLocalAddress) gateway else udpServer
            DatagramSocket().use { udp ->
                udp.soTimeout=timeoutMs
                val portBytes=byteArrayOf((resolverPort ushr 8).toByte(), resolverPort.toByte())
                val pkt=byteArrayOf(0,0,0,1)+resolver.address+portBytes+question
                udp.send(DatagramPacket(pkt,pkt.size,relay,udpPort))
                val response=DatagramPacket(ByteArray(4096),4096)
                udp.receive(response)
                check(response.address==relay && response.port==udpPort) { "Unexpected UDP relay origin" }
                val content=response.data.copyOf(response.length)
                check(content.size>=10 && content[0]==0.toByte() && content[1]==0.toByte() && content[2]==0.toByte())
                val contentType=content[3].toInt() and 255
                val overhead=when(contentType) {
                    1 -> 10
                    4 -> 22
                    3 -> 7 + (content.getOrNull(4)?.toInt()?.and(255) ?: error("Bad ATYP"))
                    else -> error("Invalid SOCKS UDP ATYP")
                }
                check(content.size>=overhead+12)
                val dns=content.copyOfRange(overhead,content.size)
                check(((dns[0].toInt() and 255) shl 8 or (dns[1].toInt() and 255)) == id) {
                    "DNS transaction ID mismatch"
                }
                check(dns[2].toInt() and 128 != 0) { "No DNS response flag" }
                val rcode=dns[3].toInt() and 15
                check(rcode==0) { "DNS failure response code $rcode" }
                val answers=((dns[6].toInt() and 255) shl 8) or (dns[7].toInt() and 255)
                return Result(rcode,answers,(System.nanoTime()-started)/1_000_000)
            }
        }
    }

    private fun dnsQuestion(name: String, id:Int):ByteArray {
        val ascii=name.lowercase()
        require(ascii.length in 1..253)
        val labels=ascii.split('.')
        require(labels.all { it.matches(Regex("[a-z0-9-]{1,63}")) })
        val domain=labels.flatMap { label ->
            listOf(label.length.toByte())+label.toByteArray(Charsets.US_ASCII).toList()
        }.toByteArray()+byteArrayOf(0)
        // ID; standard recursion desired; one question for A IN.
        return byteArrayOf((id ushr 8).toByte(),id.toByte(),1,0,0,1,0,0,0,0,0,0) +
               domain + byteArrayOf(0,1,0,1)
    }
}
