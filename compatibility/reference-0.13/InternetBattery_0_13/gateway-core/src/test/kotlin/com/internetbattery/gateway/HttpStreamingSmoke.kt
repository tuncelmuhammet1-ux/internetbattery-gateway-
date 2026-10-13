package com.internetbattery.gateway

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.MessageDigest
import kotlin.concurrent.thread

/** Synthetic HTTP video-like stream via real sockets; NOT a real streaming provider. */
object HttpStreamingSmoke {
    @JvmStatic fun main(args:Array<String>) {
        val loop = InetAddress.getByName("127.0.0.1")
        val password="private-lab-HTTP-stream-secret"
        val body=ByteArray(1_048_576) { (it*31).toByte() }
        ServerSocket(0, 8, loop).use { origin ->
            val sender=thread(name="ib-mock-video-stream") {
                origin.accept().use { conn ->
                    conn.soTimeout=12000
                    val reader=conn.getInputStream()
                    var matched=0
                    val delimiter="\r\n\r\n".toByteArray()
                    while (matched<4) {
                        val b=reader.read()
                        check(b>=0) { "HTTP request incomplete" }
                        matched=if(b==delimiter[matched].toInt()) matched+1 else 0
                    }
                    val out=conn.getOutputStream()
                    out.write(("HTTP/1.1 200 OK\r\nContent-Type: video/mp2t\r\n"+
                        "Content-Length: ${body.size}\r\nConnection: close\r\n\r\n").toByteArray())
                    body.asList().chunked(8192).forEach { segment ->
                        out.write(segment.toByteArray())
                    }
                    out.flush()
                }
            }
            Socks5Gateway(loop,port=0,password=password,allowPrivateDestinations=true).use { gateway ->
                check(gateway.start())
                Socket("127.0.0.1",gateway.boundPort).use { client ->
                    client.soTimeout=15000
                    val input=DataInputStream(client.getInputStream())
                    val output=client.getOutputStream()
                    output.write(byteArrayOf(5,1,2));output.flush()
                    check(input.readUnsignedByte()==5 && input.readUnsignedByte()==2)
                    val user="ib".toByteArray();val pass=password.toByteArray()
                    output.write(byteArrayOf(1,user.size.toByte())+user+byteArrayOf(pass.size.toByte())+pass);output.flush()
                    check(input.readUnsignedByte()==1 && input.readUnsignedByte()==0)
                    output.write(byteArrayOf(5,1,0,1,127,0,0,1,(origin.localPort shr 8).toByte(),origin.localPort.toByte()));output.flush()
                    val socks=ByteArray(10);input.readFully(socks)
                    check(socks[0]==5.toByte() && socks[1]==0.toByte())
                    output.write("GET /video.ts HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n".toByteArray());output.flush()
                    val header=ByteArrayOutputStream();var state=0
                    val ending="\r\n\r\n".toByteArray()
                    while (state<4) {
                        val b=input.read()
                        check(b>=0 && header.size()<2048)
                        header.write(b)
                        state=if(b== (ending[state].toInt() and 255)) state+1 else 0
                    }
                    check(header.toString("UTF-8").startsWith("HTTP/1.1 200"))
                    val bytes=ByteArray(body.size);input.readFully(bytes)
                    check(MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(bytes),
                        MessageDigest.getInstance("SHA-256").digest(body)))
                    check(gateway.downstreamBytes.get() >= body.size)
                    println("PASS sustained 1 MiB synthetic HTTP video stream across SOCKS TCP byte-exact SHA-256")
                    println("PASS streaming downstream bytes metered by real gateway")
                }
            }
            sender.join(2000)
        }
    }
}
