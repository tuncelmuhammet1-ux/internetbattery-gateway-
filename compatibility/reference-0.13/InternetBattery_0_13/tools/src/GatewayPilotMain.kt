package com.internetbattery.gateway

import java.io.DataInputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * Lab pilot for TWO authorized PCs on the same LAN. It is NOT a public proxy.
 * Real external networking is attempted only when user runs `test` on a real LAN.
 * Existing automated tests cover this protocol on localhost, not physical hardware.
 */
object GatewayPilotMain {
    private fun secret(): String {
        val fromEnv=System.getenv("IB_GATEWAY_SECRET")
        val raw=fromEnv ?: System.console()?.readPassword("One-time pairing secret: ")?.concatToString()
            ?: error("Set IB_GATEWAY_SECRET in this shell or run in an interactive terminal")
        require(raw.toByteArray(StandardCharsets.UTF_8).size in 16..255) { "Secret must contain 16-255 UTF-8 bytes" }
        return raw
    }

    @JvmStatic fun main(args: Array<String>) {
        require(args.size == 3 && args[0] in setOf("serve","test")) {
            "Usage: serve <owned LAN IPv4> <port> OR test <gateway IPv4> <port>; use IB_GATEWAY_SECRET"
        }
        val raw=args[1]
        require(raw.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))) { "A numeric IPv4 literal is required" }
        val ip=InetAddress.getByName(raw)
        require(ip is Inet4Address && !ip.isAnyLocalAddress && ip.hostAddress==raw) { "Wildcard and invalid bind addresses rejected" }
        val port=args[2].toInt()
        require(port in 1024..65535) { "Use a nonprivileged port" }
        val pwd=secret()
        when(args[0]) {
            "serve" -> {
                // Intentional user action starts a sensitive listener; bound ONLY to owned interface.
                Socks5Gateway(ip,port,password=pwd,
                    onLog={ println("GATEWAY: $it") },
                    onSessionCompleted={ println("MEASURED: up=${it.upstreamBytes} down=${it.downstreamBytes}") }
                ).use { gateway ->
                    check(gateway.start()) { "Cannot bind $raw:$port. Is this your device's interface?" }
                    println("LISTENING $raw:$port - requires secret; public/private target filters enabled")
                    Runtime.getRuntime().addShutdownHook(Thread { gateway.close() })
                    CountDownLatch(1).await()
                }
            }
            "test" -> {
                Socket().use { plain ->
                    plain.soTimeout=12000
                    plain.connect(InetSocketAddress(ip,port),7000)
                    val input=DataInputStream(plain.getInputStream());val output=plain.getOutputStream()
                    output.write(byteArrayOf(5,1,2));output.flush()
                    check(input.readUnsignedByte()==5 && input.readUnsignedByte()==2) { "Proxy refused secure auth" }
                    val username="ib".toByteArray();val pass=pwd.toByteArray()
                    output.write(byteArrayOf(1,username.size.toByte())+username+byteArrayOf(pass.size.toByte())+pass)
                    output.flush()
                    check(input.readUnsignedByte()==1 && input.readUnsignedByte()==0) { "Authentication refused" }
                    val host="example.com";val ascii=host.toByteArray()
                    output.write(byteArrayOf(5,1,0,3,ascii.size.toByte())+ascii+byteArrayOf(1,0xbb.toByte()))
                    output.flush()
                    val h=ByteArray(4);input.readFully(h)
                    check(h[0]==5.toByte()&&h[1]==0.toByte()) { "Internet gateway connect failed: ${h[1]}" }
                    when (h[3].toInt() and 255) {
                        1 -> input.readFully(ByteArray(4))
                        3 -> input.readFully(ByteArray(input.readUnsignedByte()))
                        4 -> input.readFully(ByteArray(16))
                        else -> error("Invalid SOCKS response")
                    }
                    input.readUnsignedShort()
                    ((SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(plain,host,443,true) as SSLSocket).use { tls ->
                        tls.soTimeout=12000
                        tls.sslParameters=tls.sslParameters.apply { endpointIdentificationAlgorithm="HTTPS" }
                        tls.startHandshake()
                        tls.outputStream.write("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n".toByteArray())
                        tls.outputStream.flush()
                        val response=tls.inputStream.bufferedReader().readLine().orEmpty()
                        check(response.startsWith("HTTP/") && response.split(' ').getOrNull(1)?.toIntOrNull() in 200..399) {
                            "HTTPS response invalid: $response"
                        }
                        println("PASS authenticated remote SOCKS5 -> verified TLS -> $response")
                    }
                }
            }
        }
    }
}
