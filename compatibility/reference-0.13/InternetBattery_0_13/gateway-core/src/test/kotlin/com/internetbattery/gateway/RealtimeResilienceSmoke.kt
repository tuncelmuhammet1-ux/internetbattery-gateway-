package com.internetbattery.gateway

import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/**
 * InternetBattery 0.8: real loopback SOCKET tests for a normal-internet workload.
 * Simulates QUIC/game/voice-like UDP datagrams and TCP half-close/recovery.
 * These tests are NOT Android, a real VPN, a public Internet provider or a performance benchmark.
 */
object RealtimeResilienceSmoke {
    private const val SECRET = "ib08-correct-horse-battery-stable-credential"
    private val loop = InetAddress.getByName("127.0.0.1")

    @JvmStatic fun main(args: Array<String>) {
        udpMalformedMustNotCapturePort()
        udpMixedRealtimeTraffic()
        udpDeclaredPortIsEnforced()
        tcpHalfCloseAndRecovery()
        privateDestinationBlockedByDefault()
    }

    private data class Association(val control: Socket, val relayIp: InetAddress, val relayPort: Int): AutoCloseable {
        override fun close() { control.close() }
    }

    private fun authenticate(port: Int): Pair<Socket, DataInputStream> {
        val client = Socket(loop, port)
        client.soTimeout = 3500
        val input = DataInputStream(client.getInputStream())
        val out = client.getOutputStream()
        out.write(byteArrayOf(5, 1, 2)); out.flush()
        check(input.readUnsignedByte() == 5 && input.readUnsignedByte() == 2)
        val user = "ib".toByteArray()
        val pass = SECRET.toByteArray()
        out.write(byteArrayOf(1, user.size.toByte()) + user + byteArrayOf(pass.size.toByte()) + pass)
        out.flush()
        check(input.readUnsignedByte() == 1 && input.readUnsignedByte() == 0)
        return client to input
    }

    private fun readReply(input: DataInputStream): Pair<Int, Pair<InetAddress, Int>> {
        check(input.readUnsignedByte() == 5)
        val code = input.readUnsignedByte()
        check(input.readUnsignedByte() == 0)
        val atyp = input.readUnsignedByte()
        val address = when (atyp) {
            1 -> ByteArray(4)
            4 -> ByteArray(16)
            3 -> ByteArray(input.readUnsignedByte())
            else -> error("Unexpected SOCKS5 ATYP $atyp")
        }
        input.readFully(address)
        val port = input.readUnsignedShort()
        val ip = if (atyp == 3) InetAddress.getByName(address.decodeToString()) else InetAddress.getByAddress(address)
        return code to (ip to port)
    }

    private fun associate(port: Int, announcedUdpPort: Int = 0): Association {
        val (client, input) = authenticate(port)
        try {
            client.getOutputStream().write(byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0,
                (announcedUdpPort shr 8).toByte(), announcedUdpPort.toByte()))
            client.getOutputStream().flush()
            val (status, addr) = readReply(input)
            check(status == 0) { "UDP associate refused: $status" }
            return Association(client, addr.first, addr.second)
        } catch (ex: Throwable) { client.close(); throw ex }
    }

    private fun udpRequest(destination: InetAddress, port: Int, payload: ByteArray, fragment: Int = 0): ByteArray =
        byteArrayOf(0, 0, fragment.toByte(), if (destination.address.size == 4) 1 else 4) +
            destination.address + byteArrayOf((port shr 8).toByte(), port.toByte()) + payload

    private fun udpEcho(upstream: DatagramSocket, count: Int): Pair<Thread, AtomicReference<Throwable?>> {
        val failure = AtomicReference<Throwable?>()
        val worker = thread(name = "ib08-udp-echo") {
            try {
                repeat(count) {
                    val msg = DatagramPacket(ByteArray(4096), 4096)
                    upstream.receive(msg)
                    upstream.send(DatagramPacket(msg.data, msg.length, msg.address, msg.port))
                }
            } catch (ex: Throwable) { failure.set(ex) }
        }
        return worker to failure
    }

    private fun udpMalformedMustNotCapturePort() {
        DatagramSocket(0, loop).use { remote ->
            remote.soTimeout = 4000
            val (responder, failure) = udpEcho(remote, 1)
            Socks5Gateway(loop, 0, password = SECRET, allowPrivateDestinations = true).use { gateway ->
                check(gateway.start())
                associate(gateway.boundPort).use { a ->
                    DatagramSocket(0, loop).use { malformed ->
                        // Deliberately invalid fragment/header MUST be ignored, not pin the sender port.
                        val poison = udpRequest(loop, remote.localPort, "invalid".toByteArray(), fragment = 1)
                        malformed.send(DatagramPacket(poison, poison.size, a.relayIp, a.relayPort))
                    }
                    Thread.sleep(100)
                    DatagramSocket(0, loop).use { legitimate ->
                        legitimate.soTimeout = 2500
                        val expected = "valid-datagram-after-poison".toByteArray()
                        val request = udpRequest(loop, remote.localPort, expected)
                        legitimate.send(DatagramPacket(request, request.size, a.relayIp, a.relayPort))
                        val response = DatagramPacket(ByteArray(4096), 4096)
                        try { legitimate.receive(response) }
                        catch (t: SocketTimeoutException) { error("Malformed UDP datagram hijacked an otherwise valid association") }
                        check(response.data.copyOfRange(10, response.length).contentEquals(expected))
                    }
                }
            }
            responder.join(1500)
            failure.get()?.let { throw IllegalStateException("poison UDP echo failure", it) }
        }
        println("PASS malformed UDP/fragment cannot pin SOCKS association to wrong client port")
    }

    private fun udpMixedRealtimeTraffic() {
        val count = 120
        DatagramSocket(0, loop).use { remote ->
            remote.soTimeout = 5000
            val (responder, failure) = udpEcho(remote, count)
            Socks5Gateway(loop, 0, password = SECRET, allowPrivateDestinations = true).use { gateway ->
                check(gateway.start())
                associate(gateway.boundPort).use { a ->
                    DatagramSocket(0, loop).use { transport ->
                        transport.soTimeout = 3000
                        var expectedMetered = 0L
                        repeat(count) { i ->
                            // 160 bytes simulates voice, 1000+ bytes simulates game/QUIC-like traffic.
                            val size = if (i % 2 == 0) 160 else 1200
                            val payload = ByteArray(size) { ((i + it * 13) and 255).toByte() }
                            val packet = udpRequest(loop, remote.localPort, payload)
                            transport.send(DatagramPacket(packet, packet.size, a.relayIp, a.relayPort))
                            val response = DatagramPacket(ByteArray(4096), 4096)
                            transport.receive(response)
                            check(response.data.copyOfRange(10, response.length).contentEquals(payload)) {
                                "Datagram mismatch $i"
                            }
                            expectedMetered += payload.size
                        }
                        // give async meter a moment after last UDP receive
                        repeat(20) {
                            if (gateway.upstreamBytes.get() >= expectedMetered && gateway.downstreamBytes.get() >= expectedMetered) return@repeat
                            Thread.sleep(10)
                        }
                        check(gateway.upstreamBytes.get() == expectedMetered)
                        check(gateway.downstreamBytes.get() == expectedMetered)
                    }
                }
            }
            responder.join(1000)
            failure.get()?.let { throw IllegalStateException("realtime echo worker failed", it) }
        }
        println("PASS 120 bidirectional voice/game/QUIC-shaped datagrams delivered byte-exact & metered")
    }

    private fun udpDeclaredPortIsEnforced() {
        DatagramSocket(0, loop).use { upstream ->
            upstream.soTimeout=4500
            val (responder,failure)=udpEcho(upstream,1)
            Socks5Gateway(loop,0,password=SECRET,allowPrivateDestinations=true).use { gateway ->
                check(gateway.start())
                DatagramSocket(0,loop).use { actual ->
                    actual.soTimeout=3000
                    associate(gateway.boundPort,actual.localPort).use { association ->
                        DatagramSocket(0,loop).use { wrong ->
                            val packet=udpRequest(loop,upstream.localPort,"wrong-port".toByteArray())
                            wrong.send(DatagramPacket(packet,packet.size,association.relayIp,association.relayPort))
                        }
                        Thread.sleep(80)
                        val expected="declared-client-port".toByteArray()
                        val packet=udpRequest(loop,upstream.localPort,expected)
                        actual.send(DatagramPacket(packet,packet.size,association.relayIp,association.relayPort))
                        val response=DatagramPacket(ByteArray(4096),4096)
                        actual.receive(response)
                        check(response.data.copyOfRange(10,response.length).contentEquals(expected))
                        check(gateway.upstreamBytes.get()==expected.size.toLong()) { "wrong-port UDP was relayed" }
                    }
                }
            }
            responder.join(1200)
            failure.get()?.let { throw IllegalStateException("declared UDP port echo failure",it) }
        }
        println("PASS SOCKS UDP ASSOCIATE declared client port enforced; spoof source port ignored")
    }

    private fun tcpHalfCloseAndRecovery() {
        ServerSocket(0, 4, loop).use { origin ->
            origin.soTimeout = 4000
            val failure = AtomicReference<Throwable?>()
            val serverWorker = thread(name = "ib08-tcp-echo") {
                try {
                    repeat(2) {
                        origin.accept().use { remote ->
                            remote.soTimeout = 3000
                            val payload = remote.getInputStream().readBytes()
                            remote.getOutputStream().write(payload)
                            remote.shutdownOutput()
                        }
                    }
                } catch (e: Throwable) { failure.set(e) }
            }
            Socks5Gateway(loop, 0, password = SECRET, allowPrivateDestinations = true).use { gateway ->
                check(gateway.start())
                repeat(2) { i ->
                    val (client, input) = authenticate(gateway.boundPort)
                    client.use {
                        val request = byteArrayOf(5, 1, 0, 1, 127, 0, 0, 1,
                            (origin.localPort shr 8).toByte(), origin.localPort.toByte())
                        client.getOutputStream().write(request)
                        client.getOutputStream().flush()
                        check(readReply(input).first == 0)
                        val payload = ByteArray(4096 * (i + 1)) { (i + it).toByte() }
                        client.getOutputStream().write(payload)
                        client.shutdownOutput()
                        check(client.getInputStream().readBytes().contentEquals(payload)) { "Half-close $i lost data" }
                    }
                }
                check(gateway.activeSessions <= 1)
            }
            serverWorker.join(1200)
            failure.get()?.let { throw IllegalStateException("TCP echo failed", it) }
        }
        println("PASS TCP half-close and sequential session recovery")
    }

    private fun privateDestinationBlockedByDefault() {
        Socks5Gateway(loop, 0, password = SECRET).use { gateway ->
            check(gateway.start())
            val (socket, input) = authenticate(gateway.boundPort)
            socket.use { client ->
                client.getOutputStream().write(byteArrayOf(5, 1, 0, 1, 127, 0, 0, 1, 0, 80))
                client.getOutputStream().flush()
                check(readReply(input).first != 0) { "Open local service SSRF in production policy" }
            }
        }
        println("PASS production proxy policy rejects private/loopback destination")
    }
}
