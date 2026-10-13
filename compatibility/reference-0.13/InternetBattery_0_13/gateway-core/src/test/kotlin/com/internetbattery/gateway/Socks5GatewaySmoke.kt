package com.internetbattery.gateway

import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

object Socks5GatewaySmoke {
    private val local = InetAddress.getByName("127.0.0.1")
    private const val SECRET = "super-strong-test-passphrase-1234"

    @JvmStatic fun main(args: Array<String>) {
        ServerSocket(0, 8, local).use { echo ->
            val tcpEcho = thread(isDaemon=true) {
                repeat(1) {
                    echo.accept().use { socket ->
                        val input = socket.getInputStream(); val output = socket.getOutputStream()
                        val data = ByteArray(128)
                        val count = input.read(data)
                        if (count > 0) { output.write(data, 0, count); output.flush() }
                    }
                }
            }
            DatagramSocket(0,local).use { udpEcho ->
                udpEcho.soTimeout = 9000
                val udpEchoThread = thread(isDaemon=true) {
                    val data = DatagramPacket(ByteArray(1024),1024)
                    udpEcho.receive(data)
                    udpEcho.send(DatagramPacket(data.data, data.length, data.address, data.port))
                }
                Socks5Gateway(local, 0, password=SECRET, allowPrivateDestinations=true).use { proxy ->
                    check(proxy.start()) { "Gateway failed to bind" }
                    val port = proxy.boundPort
                    check(port > 0)
                    Socket(local,port).use { client ->
                        val i = DataInputStream(client.getInputStream()); val o = client.getOutputStream()
                        o.write(byteArrayOf(5,1,2)); o.flush()
                        check(i.readUnsignedByte()==5 && i.readUnsignedByte()==2)
                        val u = "ib".toByteArray(); val p = SECRET.toByteArray()
                        o.write(byteArrayOf(1,u.size.toByte()) + u + byteArrayOf(p.size.toByte())+p);o.flush()
                        check(i.readUnsignedByte()==1 && i.readUnsignedByte()==0)
                        val ip = local.address
                        o.write(byteArrayOf(5,1,0,1) + ip + byteArrayOf((echo.localPort shr 8).toByte(),echo.localPort.toByte()));o.flush()
                        val result = ByteArray(10); i.readFully(result)
                        check(result[1]==0.toByte()) { "CONNECT reply ${result[1]}" }
                        o.write("hello via socks5".toByteArray());o.flush()
                        val answer=ByteArray(16);i.readFully(answer)
                        check(String(answer)=="hello via socks5")
                    }
                    println("PASS TCP CONNECT relay")
                    Socket(local,port).use { client ->
                        val i=DataInputStream(client.getInputStream());val o=client.getOutputStream()
                        o.write(byteArrayOf(5,1,2));o.flush();check(i.readUnsignedByte()==5 && i.readUnsignedByte()==2)
                        val u="ib".toByteArray();val p="wrong-password-123456789".toByteArray()
                        o.write(byteArrayOf(1,u.size.toByte())+u+byteArrayOf(p.size.toByte())+p);o.flush()
                        check(i.readUnsignedByte()==1 && i.readUnsignedByte()==1)
                    }
                    println("PASS invalid secret denied")
                    Socket(local,port).use { control ->
                        val i=DataInputStream(control.getInputStream());val o=control.getOutputStream()
                        o.write(byteArrayOf(5,1,2));o.flush();check(i.readUnsignedByte()==5 && i.readUnsignedByte()==2)
                        val u="ib".toByteArray();val p=SECRET.toByteArray()
                        o.write(byteArrayOf(1,u.size.toByte())+u+byteArrayOf(p.size.toByte())+p);o.flush()
                        check(i.readUnsignedByte()==1 && i.readUnsignedByte()==0)
                        o.write(byteArrayOf(5,3,0,1,0,0,0,0,0,0));o.flush()
                        val reply=ByteArray(10);i.readFully(reply);check(reply[1]==0.toByte())
                        val udpPort=(reply[8].toInt() and 255)*256+(reply[9].toInt() and 255)
                        DatagramSocket(0,local).use { udp ->
                            udp.soTimeout = 8000
                            val message="dns-example".toByteArray()
                            val packet=byteArrayOf(0,0,0,1)+local.address+byteArrayOf((udpEcho.localPort shr 8).toByte(), udpEcho.localPort.toByte())+message
                            udp.send(DatagramPacket(packet,packet.size,local,udpPort))
                            val r=DatagramPacket(ByteArray(500),500);udp.receive(r)
                            check(String(r.data.copyOfRange(10,r.length))=="dns-example")
                        }
                    }
                    println("PASS UDP ASSOCIATE relay")
                    check(proxy.upstreamBytes.get()>0 && proxy.downstreamBytes.get()>0)
                    println("PASS measured bytes upload=${proxy.upstreamBytes.get()} download=${proxy.downstreamBytes.get()}")
                }
                udpEchoThread.join(500)
                // Production default must prevent access to private/loopback targets.
                Socks5Gateway(local,0,password=SECRET).use { restricted ->
                    check(restricted.start())
                    Socket(local,restricted.boundPort).use { client ->
                        val inp=DataInputStream(client.getInputStream()); val out=client.getOutputStream()
                        out.write(byteArrayOf(5,1,2));out.flush()
                        check(inp.readUnsignedByte()==5 && inp.readUnsignedByte()==2)
                        val u="ib".toByteArray();val p=SECRET.toByteArray()
                        out.write(byteArrayOf(1,u.size.toByte())+u+byteArrayOf(p.size.toByte())+p);out.flush()
                        check(inp.readUnsignedByte()==1 && inp.readUnsignedByte()==0)
                        out.write(byteArrayOf(5,1,0,1)+local.address+byteArrayOf(0,80));out.flush()
                        val reply=ByteArray(10);inp.readFully(reply)
                        check(reply[1]==2.toByte()) { "Local target should be blocked by default" }
                    }
                }
                println("PASS private destination denied")
            }
            tcpEcho.join(1000)
        }
    }
}
