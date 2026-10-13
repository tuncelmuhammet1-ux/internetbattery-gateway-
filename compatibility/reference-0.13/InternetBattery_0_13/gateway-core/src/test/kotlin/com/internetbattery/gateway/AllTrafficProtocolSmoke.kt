package com.internetbattery.gateway

import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/**
 * Exercises real IPv6-destination TCP and UDP relay through the IPv4 SOCKS5 listener,
 * A/AAAA fallback, and a large bidirectional payload. IPv6 loopback requires host OS support.
 * These are JVM socket tests, NOT Android VPN tests or public Internet tests.
 */
object AllTrafficProtocolSmoke {
    private const val PASSWORD = "local-lab-secret-of-adequate-length"
    @JvmStatic fun main(args: Array<String>) {
        val ipv4 = InetAddress.getByName("127.0.0.1")
        val ipv6 = InetAddress.getByName("::1")
        val server = ServerSocket(0, 10, ipv6)
        val first = AtomicReference<Throwable?>(null)
        val echo = thread(name="ipv6-echo") {
            try {
                repeat(2) {
                    server.accept().use { client ->
                        client.soTimeout = 10_000
                        val input=client.getInputStream()
                        val output=client.getOutputStream()
                        val buf=ByteArray(8192)
                        while (true) {
                            val n=input.read(buf)
                            if (n<0) break
                            output.write(buf,0,n)
                        }
                        client.shutdownOutput()
                    }
                }
            } catch (e: Throwable) { first.set(e) }
        }
        val gateway = Socks5Gateway(ipv4, port=0, password=PASSWORD,
            allowPrivateDestinations=true,
            resolveHost = { host -> if (host=="dualstack.test") arrayOf(ipv4,ipv6)
               else InetAddress.getAllByName(host) })
        check(gateway.start())
        try {
            val payload=ByteArray(131_072) { (it*37).toByte() }
            socksConnect(gateway.boundPort, "::1", server.localPort, ipv6).use { client ->
                client.soTimeout=10_000
                client.getOutputStream().write(payload)
                client.shutdownOutput()
                val echoed=client.getInputStream().readBytes()
                check(echoed.contentEquals(payload)) { "IPv6 SOCKS TCP data corruption" }
            }
            println("PASS IPv4 P2P SOCKS gateway => IPv6 TCP 128 KiB byte-exact echo")
            // IPv4 loopback has no listener on this port; fail A, try AAAA.
            socksConnect(gateway.boundPort,"dualstack.test",server.localPort,null).use { client ->
                client.soTimeout=10_000
                client.getOutputStream().write("family-fallback".toByteArray())
                client.shutdownOutput()
                check(client.getInputStream().readBytes().decodeToString()=="family-fallback")
            }
            println("PASS dual-stack DNS A -> AAAA TCP fallback")
            check(gateway.upstreamBytes.get()>=payload.size+15L)
            check(gateway.downstreamBytes.get()>=payload.size+15L)
            println("PASS full-duplex IPv6 traffic metering")
            udpIpv6RoundTrip(gateway.boundPort,ipv6)
        } finally {
            gateway.close()
            server.close()
            echo.join(2000)
        }
        first.get()?.let { throw IllegalStateException("IPv6 echo failed",it) }
    }

    private fun authenticate(socket: Socket): Pair<DataInputStream,java.io.OutputStream> {
        socket.soTimeout=10_000
        val input=DataInputStream(socket.getInputStream())
        val out=socket.getOutputStream()
        out.write(byteArrayOf(5,1,2))
        out.flush()
        check(input.readUnsignedByte()==5 && input.readUnsignedByte()==2)
        val name="ib".toByteArray();val pass=PASSWORD.toByteArray()
        out.write(byteArrayOf(1,name.size.toByte())+name+byteArrayOf(pass.size.toByte())+pass)
        out.flush()
        check(input.readUnsignedByte()==1 && input.readUnsignedByte()==0) { "SOCKS authorization failed" }
        return input to out
    }

    private fun readReply(input: DataInputStream): Pair<InetAddress,Int> {
        check(input.readUnsignedByte()==5)
        val code=input.readUnsignedByte()
        check(code==0) { "SOCKS error $code" }
        check(input.readUnsignedByte()==0)
        val atyp=input.readUnsignedByte()
        val addr=when(atyp) {
            1 -> ByteArray(4)
            4 -> ByteArray(16)
            3 -> ByteArray(input.readUnsignedByte())
            else -> error("Bad SOCKS address type $atyp")
        }
        input.readFully(addr)
        val port=input.readUnsignedShort()
        return (if(atyp==3) InetAddress.getByName(addr.decodeToString()) else InetAddress.getByAddress(addr)) to port
    }

    private fun socksConnect(proxyPort:Int,hostname:String,targetPort:Int,ip:InetAddress?):Socket {
        val client=Socket("127.0.0.1",proxyPort)
        try {
            val (input,out)=authenticate(client)
            val dest=if (ip!=null) byteArrayOf(if(ip.address.size==16) 4 else 1)+ip.address
                else hostname.toByteArray().let { byteArrayOf(3,it.size.toByte())+it }
            out.write(byteArrayOf(5,1,0)+dest+byteArrayOf((targetPort shr 8).toByte(),targetPort.toByte()))
            out.flush()
            readReply(input)
            return client
        } catch(t:Throwable) { client.close();throw t }
    }

    private fun udpIpv6RoundTrip(proxyPort:Int,ipv6:InetAddress) {
        DatagramSocket(0,ipv6).use { upstream ->
            upstream.soTimeout=8_000
            val echo=thread(name="ipv6-udp-echo") {
                val msg=DatagramPacket(ByteArray(2048),2048)
                upstream.receive(msg)
                upstream.send(DatagramPacket(msg.data,msg.length,msg.address,msg.port))
            }
            Socket("127.0.0.1",proxyPort).use { control ->
                val (input,out)=authenticate(control)
                out.write(byteArrayOf(5,3,0,1,0,0,0,0,0,0))
                out.flush()
                val (gatewayAddress,gatewayPort)=readReply(input)
                DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { clientUdp ->
                    clientUdp.soTimeout=8_000
                    val payload="DNS-UDP-over-IPv6-route".toByteArray()
                    val header=byteArrayOf(0,0,0,4)+ipv6.address+
                        byteArrayOf((upstream.localPort shr 8).toByte(),upstream.localPort.toByte())
                    val request=header+payload
                    clientUdp.send(DatagramPacket(request,request.size,gatewayAddress,gatewayPort))
                    val response=DatagramPacket(ByteArray(4096),4096)
                    clientUdp.receive(response)
                    val received=response.data.copyOfRange(22,response.length)
                    check(received.contentEquals(payload)) { "IPv6 UDP data corrupted" }
                }
            }
            echo.join(500)
        }
        println("PASS SOCKS5 UDP ASSOCIATE IPv6 payload and response over IPv4 client link")
    }
}
