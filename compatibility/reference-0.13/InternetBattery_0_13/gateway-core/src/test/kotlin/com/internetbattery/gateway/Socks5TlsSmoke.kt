package com.internetbattery.gateway

import java.io.DataInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import kotlin.concurrent.thread

/** Real, locally encrypted TLS/HTTP through an authenticated SOCKS gateway.
 * Tests transport correctness; DOES NOT imply live internet or Android success. */
object Socks5TlsSmoke {
    @JvmStatic fun main(args: Array<String>) {
        val certFile = Files.createTempFile("internetbattery-localhost", ".p12")
        Files.deleteIfExists(certFile)
        try {
            val process=ProcessBuilder("keytool", "-genkeypair", "-alias", "tls-localhost", "-keyalg", "RSA", "-keysize", "2048", "-validity", "1", "-storetype", "PKCS12", "-keystore", certFile.toString(), "-storepass", "changeit", "-keypass", "changeit", "-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-noprompt")
                .redirectErrorStream(true).start()
            val output=process.inputStream.bufferedReader().readText()
            check(process.waitFor() == 0) { "keytool failed: $output" }
            val ks = KeyStore.getInstance("PKCS12")
            Files.newInputStream(certFile).use { ks.load(it,"changeit".toCharArray()) }
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            kmf.init(ks,"changeit".toCharArray())
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(ks)
            val serverContext = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers,null,null) }
            val clientContext = SSLContext.getInstance("TLS").apply { init(null,tmf.trustManagers,null) }
            val local = InetAddress.getByName("127.0.0.1")
            val https = serverContext.serverSocketFactory.createServerSocket(0,1,local) as SSLServerSocket
            https.use { tlsServer ->
                val serverThread=thread(isDaemon=true) {
                    tlsServer.accept().use { accepted ->
                        val tls = accepted as SSLSocket
                        tls.soTimeout=5000
                        val reader = tls.inputStream.bufferedReader()
                        val request=reader.readLine()
                        check(request=="GET /probe HTTP/1.1")
                        while (reader.readLine()?.isNotEmpty() == true) {}
                        tls.outputStream.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK".toByteArray())
                        tls.outputStream.flush()
                    }
                }
                Socks5Gateway(local,0,password="local-only-test-token-xxxxxxxx",allowPrivateDestinations=true).use { gateway ->
                    check(gateway.start())
                    Socket(local,gateway.boundPort).use { plain ->
                        plain.soTimeout=6000
                        val input=DataInputStream(plain.getInputStream()); val out=plain.getOutputStream()
                        out.write(byteArrayOf(5,1,2));out.flush()
                        check(input.readUnsignedByte()==5 && input.readUnsignedByte()==2)
                        val username="ib".toByteArray(); val password="local-only-test-token-xxxxxxxx".toByteArray()
                        out.write(byteArrayOf(1,username.size.toByte())+username+byteArrayOf(password.size.toByte())+password);out.flush()
                        check(input.readUnsignedByte()==1 && input.readUnsignedByte()==0)
                        val host="localhost".toByteArray()
                        out.write(byteArrayOf(5,1,0,3,host.size.toByte())+host+byteArrayOf((https.localPort ushr 8).toByte(),https.localPort.toByte()));out.flush()
                        val reply=ByteArray(10);input.readFully(reply)
                        check(reply[1].toInt()==0)
                        val tls=clientContext.socketFactory.createSocket(plain,"localhost",https.localPort,false) as SSLSocket
                        tls.use {
                            it.sslParameters = it.sslParameters.apply { endpointIdentificationAlgorithm="HTTPS" }
                            it.startHandshake()
                            it.outputStream.write("GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".toByteArray())
                            it.outputStream.flush()
                            check(it.inputStream.bufferedReader().readLine()=="HTTP/1.1 200 OK")
                        }
                    }
                    serverThread.join(3000)
                    check(!serverThread.isAlive) { "TLS server thread unfinished" }
                    check(gateway.upstreamBytes.get()>0 && gateway.downstreamBytes.get()>0)
                    println("PASS actual local TLS 1.x handshake + HTTPS 200 over SOCKS5 (hostname verified)")
                    println("PASS bidirectional TLS byte measurement")
                }
            }
        } finally { Files.deleteIfExists(certFile) }
    }
}
