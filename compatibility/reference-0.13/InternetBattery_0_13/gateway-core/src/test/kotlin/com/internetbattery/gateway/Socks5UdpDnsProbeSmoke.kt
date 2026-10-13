package com.internetbattery.gateway

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.concurrent.thread

/** A fully local test DNS responder, through the real gateway UDP ASSOCIATE. */
object Socks5UdpDnsProbeSmoke {
    @JvmStatic fun main(args:Array<String>) {
        val loop=InetAddress.getByName("127.0.0.1")
        DatagramSocket(0,loop).use { resolver ->
            resolver.soTimeout=15_000
            val dns=thread(name="ib-dns-responder") {
                repeat(2) {
                    val recv=DatagramPacket(ByteArray(1024),1024)
                    resolver.receive(recv)
                    val request=recv.data.copyOf(recv.length)
                    check(request.size>=20)
                    // A minimal standards-shaped response for the query, with one A answer.
                    val answer=request.copyOf().apply {
                        this[2]=0x81.toByte();this[3]=0x80.toByte()
                        this[6]=0;this[7]=1
                    } + byteArrayOf(0xc0.toByte(),0x0c,0,1,0,1,0,0,0,60,0,4,127,0,0,1)
                    resolver.send(DatagramPacket(answer,answer.size,recv.address,recv.port))
                }
            }
            Socks5Gateway(loop,port=0,password="lab-valid-long-password",
                allowPrivateDestinations=true).use { gateway ->
                check(gateway.start())
                check(runCatching {
                    Socks5UdpDnsProbe.queryA("127.0.0.1",gateway.boundPort,"ib",
                        "wrong-untrusted-password",resolverIpv4="127.0.0.1",
                        resolverPort=resolver.localPort)
                }.isFailure) { "Invalid SOCKS5 password was accepted" }
                println("PASS unauthenticated UDP/DNS probe denied before forwarding")
                repeat(2) {
                    val result=Socks5UdpDnsProbe.queryA("127.0.0.1",gateway.boundPort,"ib",
                        "lab-valid-long-password",resolverIpv4="127.0.0.1",resolverPort=resolver.localPort,
                        hostname="example.com")
                    check(result.responseCode==0 && result.answers==1)
                }
                check(gateway.upstreamBytes.get()>0 && gateway.downstreamBytes.get()>0)
                println("PASS authenticated SOCKS5 UDP + real DNS-format request/answer x2")
                println("PASS UDP DNS relay has measured upload AND download bytes")
            }
            dns.join(1000)
        }
    }
}
