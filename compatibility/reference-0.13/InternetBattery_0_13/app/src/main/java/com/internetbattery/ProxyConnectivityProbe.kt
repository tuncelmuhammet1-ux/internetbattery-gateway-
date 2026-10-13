package com.internetbattery

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.DataInputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocketFactory

/** Tests that the *other device's gateway* can carry an actual HTTPS request. */
object ProxyConnectivityProbe {
    /** Real SOCKS5 UDP relay + DNS lookup through the external gateway.
     * This tests DNS/UDP reachability; it does not certify QUIC/video games. */
    suspend fun testDns(proxyIp: String, port: Int, password: String, username: String="ib"): Result<String> =
        withContext(Dispatchers.IO) {
            runCatching {
                val outcome=com.internetbattery.gateway.Socks5UdpDnsProbe.queryA(
                    proxyIp,port,username,password)
                "SOCKS5 UDP DNS yanıtı: rcode=${outcome.responseCode}, " +
                    "cevap=${outcome.answers}, süre=${outcome.elapsedMs}ms"
            }
        }

    suspend fun test(proxyIp: String, port: Int, password: String, username: String = "ib"): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            require(password.toByteArray().size in 16..255) { "16-255 baytlık kod veya imzalı belge gir" }
            require(username.toByteArray().size in 1..255) { "SOCKS kullanıcı kimliği geçersiz" }
            Socket().use { plain ->
                plain.soTimeout = 12000
                plain.connect(InetSocketAddress(proxyIp, port), 7000)
                val input = DataInputStream(plain.getInputStream()); val output = plain.getOutputStream()
                output.write(byteArrayOf(5, 1, 2));output.flush()
                require(input.readUnsignedByte()==5 && input.readUnsignedByte()==2) { "SOCKS5 kimlik doğrulama yöntemi desteklenmiyor" }
                val name=username.toByteArray();val pass=password.toByteArray()
                output.write(byteArrayOf(1,name.size.toByte())+name+byteArrayOf(pass.size.toByte())+pass)
                output.flush()
                require(input.readUnsignedByte()==1 && input.readUnsignedByte()==0) { "Eşleştirme kodu reddedildi" }
                val target="example.com".toByteArray()
                output.write(byteArrayOf(5,1,0,3,target.size.toByte())+target+byteArrayOf(1,0xbb.toByte())) // port 443
                output.flush()
                val answer=ByteArray(4);input.readFully(answer)
                require(answer[0]==5.toByte() && answer[1]==0.toByte()) { "Gateway dış sunucuya bağlanamadı (SOCKS kodu ${answer[1]})" }
                val addrType=answer[3].toInt() and 255
                when(addrType) {
                    1 -> input.readFully(ByteArray(4))
                    3 -> input.readFully(ByteArray(input.readUnsignedByte()))
                    4 -> input.readFully(ByteArray(16))
                    else -> error("Geçersiz SOCKS yanıtı")
                }
                input.readUnsignedShort() // bound port
                val tls = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(plain, "example.com",443,true) as javax.net.ssl.SSLSocket
                tls.soTimeout=12_000
                tls.use { s ->
                    // Default raw SSLSocket does not guarantee hostname verification.
                    s.sslParameters = s.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                    s.startHandshake()
                    val request="GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: InternetBattery-MVP\r\nConnection: close\r\n\r\n"
                    s.outputStream.write(request.toByteArray());s.outputStream.flush()
                    val status=s.inputStream.bufferedReader().readLine() ?: error("HTTPS yanıtı boş")
                    require(status.startsWith("HTTP/") && status.split(' ').getOrNull(1)?.toIntOrNull() in 200..399) {
                        "Beklenmeyen HTTPS yanıtı: $status"
                    }
                    "SOCKS5 + TLS: $status"
                }
            }
        }
    }
}
