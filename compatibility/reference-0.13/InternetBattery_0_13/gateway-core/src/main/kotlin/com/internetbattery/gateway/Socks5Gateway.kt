package com.internetbattery.gateway

import java.io.DataInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Semaphore
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * A trusted, synchronous spend-before-forward gate for this gateway instance.
 * Grant counts payload bytes, not SOCKS/TCP/IP framing. The implementation MUST
 * be thread-safe and durable before returning nonzero, because TCP/UDP connections
 * can operate concurrently and a crash must never create free access.
 * For datagrams grant either the whole payload or zero; datagrams cannot be split.
 * This is a reserved allowance: I/O failure can over-debit. Refunds require a
 * separate verified reconciliation protocol and are deliberately not fabricated.
 */
fun interface TransferAllowance {
    fun grant(requestedBytes: Int, datagram: Boolean): Int
    /** Called before opening an outbound socket; implementations SHOULD fail closed. */
    fun mayOpen(): Boolean = true
}

/** Result of explicit per-session authentication; allowance is unique per session and
 * is enforced for BOTH TCP and UDP forwarding. Null means legacy unlimited mode. */
data class SessionAdmission(val allowance: TransferAllowance? = null)

/** Return null to deny a credential. Used by the signed-voucher access mode. */
fun interface SessionAuthorizer {
    fun authenticate(username: String, secret: String): SessionAdmission?
}

data class SessionTraffic(
    val clientIp: String,
    val authenticatedUsername: String,
    val upstreamBytes: Long,
    val downstreamBytes: Long,
    val completedAtMs: Long
)

/**
 * Small, testable SOCKS5 gateway, without Android dependencies.
 * RFC 1928: CONNECT and UDP ASSOCIATE; RFC 1929: password authentication.
 * Bind to the *specific P2P group owner address*; never expose an open proxy on 0.0.0.0.
 * Can route sockets over Android's validated cellular Network via injected factories.
 */
class Socks5Gateway(
    private val listenAddress: InetAddress,
    private val port: Int = 8888,
    private val username: String = "ib",
    private val password: String,
    private val allowPrivateDestinations: Boolean = false,
    private val tcpFactory: () -> Socket = { Socket() },
    private val udpFactory: () -> DatagramSocket = { DatagramSocket() },
    private val resolveHost: (String) -> Array<InetAddress> = { InetAddress.getAllByName(it) },
    private val onLog: (String) -> Unit = {},
    private val onBytes: (Long, Long) -> Unit = { _, _ -> },
    private val onSessionCompleted: (SessionTraffic) -> Unit = {},
    private val allowance: TransferAllowance? = null,
    private val sessionAuthorizer: SessionAuthorizer? = null,
) : AutoCloseable {
    private val active = AtomicBoolean(false)
    private val permit = Semaphore(16)
    private val clients = ConcurrentHashMap.newKeySet<Socket>()
    private val remoteSockets = ConcurrentHashMap.newKeySet<Socket>()
    private var server: ServerSocket? = null
    private var acceptThread: Thread? = null
    val upstreamBytes = AtomicLong(0)  // client -> Internet
    val downstreamBytes = AtomicLong(0) // Internet -> client
    val activeSessions get() = clients.size
    val isRunning get() = active.get()
    val boundPort get() = server?.localPort ?: 0

    init {
        require(listenAddress is Inet4Address) { "First MVP uses IPv4 P2P" }
        require(username.toByteArray(Charsets.UTF_8).size in 1..255)
        require(password.toByteArray(Charsets.UTF_8).size in 16..255) { "Pairing secret must be at least 16 bytes" }
        require(port in 0..65535)
    }

    @Synchronized fun start(): Boolean {
        if (active.get()) return true
        return try {
            val sock = ServerSocket()
            sock.reuseAddress = true
            sock.bind(InetSocketAddress(listenAddress, port), 24)
            server = sock
            active.set(true)
            acceptThread = thread(name="ib-socks-accept", isDaemon=true) {
                while (active.get()) {
                    val client = try { sock.accept() } catch (_: SocketException) { break }
                    catch (e: Exception) { onLog("accept: ${e.javaClass.simpleName}"); continue }
                    if (!permit.tryAcquire()) { client.close(); continue }
                    clients.add(client)
                    thread(name="ib-socks-client", isDaemon=true) {
                        try { handle(client) } catch (e: Exception) { onLog("session: ${e.javaClass.simpleName}") }
                        finally { clients.remove(client); runCatching { client.close() }; permit.release() }
                    }
                }
            }
            onLog("SOCKS gateway listening at ${listenAddress.hostAddress}:${sock.localPort}")
            true
        } catch (e: Exception) {
            onLog("Gateway start failed: ${e.message}")
            false
        }
    }

    private fun handle(client: Socket) {
        val sessionUpload=AtomicLong(0)
        val sessionDownload=AtomicLong(0)
        var authorized=false
        var authenticatedName=username
        try {
        client.soTimeout = 15_000
        val input = DataInputStream(client.getInputStream())
        val output = client.getOutputStream()
        if (input.readUnsignedByte() != 5) return
        val count = input.readUnsignedByte()
        if (count !in 1..16) return
        val methods = ByteArray(count)
        input.readFully(methods)
        if (!methods.contains(2.toByte())) { output.write(byteArrayOf(5, 0xff.toByte())); return }
        output.write(byteArrayOf(5,2)); output.flush()
        // RFC 1929 authentication: username and password are checked in constant time.
        if (input.readUnsignedByte() != 1) return
        val userLen = input.readUnsignedByte(); if (userLen == 0) return
        val user = ByteArray(userLen); input.readFully(user)
        val passLen = input.readUnsignedByte(); if (passLen == 0) return
        val pass = ByteArray(passLen); input.readFully(pass)
        val presentedName = user.toString(Charsets.UTF_8)
        val presentedSecret = pass.toString(Charsets.UTF_8)
        val dynamicAuthorizer = sessionAuthorizer
        val session = if (dynamicAuthorizer != null) {
            // No static password fallback in voucher mode: NEVER bypass a spent/invalid ticket.
            runCatching { dynamicAuthorizer.authenticate(presentedName, presentedSecret) }.getOrNull()
        } else {
            val valid = MessageDigest.isEqual(user, username.toByteArray(Charsets.UTF_8)) &&
                MessageDigest.isEqual(pass, password.toByteArray(Charsets.UTF_8))
            if (valid) SessionAdmission(allowance) else null
        }
        output.write(byteArrayOf(1, if (session != null) 0 else 1)); output.flush()
        if (session == null) { onLog("Denied invalid or expired authorization"); return }
        authenticatedName=presentedName
        authorized=true
        val sessionAllowance = session.allowance

        if (input.readUnsignedByte() != 5) return
        val cmd = input.readUnsignedByte()
        if (input.readUnsignedByte() != 0) return
        val target = decodeAddress(input) ?: run { reply(output, 8); return }
        val targetPort = input.readUnsignedShort()
        if (targetPort == 0 && cmd == 1) { reply(output, 1); return }
        if (sessionAllowance?.mayOpen() == false) { reply(output, 2); return }
        client.soTimeout = 0
        when (cmd) {
            1 -> connectTcp(client, target, targetPort, output, sessionUpload, sessionDownload, sessionAllowance)
            3 -> associateUdp(client, output, sessionUpload, sessionDownload, sessionAllowance, targetPort)
            else -> reply(output, 7)
        }
        } finally {
            if (authorized && (sessionUpload.get() > 0 || sessionDownload.get() > 0)) {
                runCatching { onSessionCompleted(SessionTraffic(
                    client.inetAddress.hostAddress ?: "", authenticatedName,
                    sessionUpload.get(), sessionDownload.get(), System.currentTimeMillis()
                )) }
            }
        }
    }

    private fun connectTcp(client: Socket, host: String, targetPort: Int, output: OutputStream,
                           sessionUpload: AtomicLong, sessionDownload: AtomicLong,
                           sessionAllowance: TransferAllowance?) {
        var remote: Socket? = null
        var responseSent = false
        try {
            // Dual-stack domains can resolve to A and AAAA addresses, but a
            // validated upstream network may only route one family. Try each
            // *policy-approved* address rather than failing at the first AAAA.
            val candidates = resolveTargets(host)
            if (candidates.isEmpty()) { reply(output, 2); return }
            var connected: Socket? = null
            for (addr in candidates) {
                val candidate = tcpFactory()
                try {
                    candidate.connect(InetSocketAddress(addr, targetPort), 4_000)
                    connected = candidate
                    break
                } catch (_: Exception) {
                    runCatching { candidate.close() }
                }
            }
            val upstreamSocket = connected ?: run { reply(output, 5); return }
            remote = upstreamSocket
            remoteSockets.add(upstreamSocket)
            upstreamSocket.soTimeout = 120_000
            client.soTimeout = 120_000
            reply(output, 0)
            responseSent = true
            val downstream = thread(name="ib-tcp-down", isDaemon=true) {
                pump(upstreamSocket.getInputStream(), client.getOutputStream(), false, sessionUpload, sessionDownload, sessionAllowance) {
                    runCatching { client.shutdownOutput() }
                }
            }
            pump(client.getInputStream(), upstreamSocket.getOutputStream(), true, sessionUpload, sessionDownload, sessionAllowance) {
                runCatching { upstreamSocket.shutdownOutput() }
            }
            downstream.join(125_000)
        } catch (e: Exception) {
            onLog("connect refused: ${e.javaClass.simpleName}")
            if (!responseSent) runCatching { reply(output, 5) }
        } finally {
            remote?.let { remoteSockets.remove(it); runCatching { it.close() } }
        }
    }

    private fun pump(input: InputStream, out: OutputStream, upstream: Boolean,
                     sessionUpload: AtomicLong, sessionDownload: AtomicLong,
                     sessionAllowance: TransferAllowance?, onEnd: () -> Unit) {
        val buffer = ByteArray(16_384)
        try {
            while (active.get()) {
                val n = try { input.read(buffer) } catch (_: SocketTimeoutException) { break }
                if (n < 0) break
                if (n == 0) continue
                val granted = sessionAllowance?.grant(n, false) ?: n
                if (granted <= 0) break
                require(granted <= n) { "Transfer allowance granted more than requested" }
                // The debit is durable BEFORE forwarding. Crashes can over-debit,
                // never silently exceed a signed quota.
                out.write(buffer, 0, granted)
                if (upstream) sessionUpload.addAndGet(granted.toLong()) else sessionDownload.addAndGet(granted.toLong())
                reportBytes(if (upstream) granted.toLong() else 0L, if (upstream) 0L else granted.toLong())
                if (granted < n) break
            }
        } catch (_: Exception) { } finally { onEnd() }
    }

    // A UDP associate session is tied to the authenticated TCP control channel.
    // Fragments (FRAG != 0) are intentionally unsupported and dropped (RFC 1928).
    private fun associateUdp(client: Socket, output: OutputStream,
                             sessionUpload: AtomicLong, sessionDownload: AtomicLong,
                             sessionAllowance: TransferAllowance?, declaredClientPort: Int) {
        val listenUdp = DatagramSocket(0, listenAddress)
        val remoteUdp = udpFactory()
        val alive = AtomicBoolean(true)
        val permittedRemotes = ConcurrentHashMap.newKeySet<String>()
        val clientPort = java.util.concurrent.atomic.AtomicInteger(0)
        listenUdp.soTimeout = 500
        remoteUdp.soTimeout = 500
        try {
            reply(output, 0, listenAddress, listenUdp.localPort)
            val fromClient = thread(name="ib-udp-upload", isDaemon=true) {
                while (alive.get() && active.get()) {
                    val msg = DatagramPacket(ByteArray(65535), 65535)
                    try { listenUdp.receive(msg) } catch (_: SocketTimeoutException) { continue }
                    catch (_: Exception) { break }
                    if (msg.address != client.inetAddress) continue
                    // RFC 1928: when UDP ASSOCIATE declares a nonzero client port,
                    // reject packets from any other port even before structural checks.
                    // A zero port means the first valid datagram establishes it.
                    if (declaredClientPort != 0 && msg.port != declaredClientPort) continue
                    // Do not lock an association to the source port of an invalid or
                    // malformed datagram. The old version pinned the port BEFORE
                    // validating FRAG / address / destination, allowing a malformed
                    // packet from the same host to deny all subsequent valid traffic.
                    if (clientPort.get() != 0 && msg.port != clientPort.get()) continue
                    val bytes = msg.data.copyOfRange(0, msg.length)
                    if (bytes.size < 10 || bytes[0] != 0.toByte() || bytes[1] != 0.toByte() || bytes[2] != 0.toByte()) continue
                    try {
                        val din = DataInputStream(bytes.inputStream())
                        din.skipBytes(3)
                        val dst = decodeAddress(din) ?: continue
                        val destPort = din.readUnsignedShort()
                        val address = resolveTarget(dst) ?: continue
                        val payload = bytes.copyOfRange(bytes.size - din.available(), bytes.size)
                        if (payload.isEmpty() || destPort == 0) continue
                        val key = "${address.hostAddress}:$destPort"
                        // Cap authenticated UDP association fan-out to prevent unbounded memory growth.
                        if (key !in permittedRemotes && permittedRemotes.size >= 256) continue
                        // Only a well-formed, policy-approved datagram can claim the
                        // client UDP port. No quota is deducted for rejected packets.
                        if (!clientPort.compareAndSet(0, msg.port) && msg.port != clientPort.get()) continue
                        // A UDP datagram must be accepted in full. Never split it.
                        if ((sessionAllowance?.grant(payload.size, true) ?: payload.size) != payload.size) continue
                        permittedRemotes.add(key)
                        remoteUdp.send(DatagramPacket(payload, payload.size, address, destPort))
                        sessionUpload.addAndGet(payload.size.toLong())
                        reportBytes(payload.size.toLong(), 0)
                    } catch (_: Exception) { }
                }
            }
            val toClient = thread(name="ib-udp-download", isDaemon=true) {
                while (alive.get() && active.get()) {
                    val msg = DatagramPacket(ByteArray(65535), 65535)
                    try { remoteUdp.receive(msg) } catch (_: SocketTimeoutException) { continue }
                    catch (_: Exception) { break }
                    if (clientPort.get() == 0 || !permittedRemotes.contains("${msg.address.hostAddress}:${msg.port}")) continue
                    val address = msg.address.address
                    val packetHeader = byteArrayOf(0,0,0, if (address.size == 4) 1 else 4) +
                        address + byteArrayOf((msg.port shr 8).toByte(), msg.port.toByte())
                    val packet = packetHeader + msg.data.copyOfRange(0, msg.length)
                    try {
                        if ((sessionAllowance?.grant(msg.length, true) ?: msg.length) != msg.length) continue
                        listenUdp.send(DatagramPacket(packet, packet.size, client.inetAddress, clientPort.get()))
                        sessionDownload.addAndGet(msg.length.toLong())
                        reportBytes(msg.length.toLong(), 0L, reverse=true)
                    } catch (_: Exception) { }
                }
            }
            // The client closing the control socket terminates the UDP association.
            while (active.get() && client.getInputStream().read() != -1) { }
            alive.set(false)
            fromClient.join(1500)
            toClient.join(1500)
        } catch (_: Exception) { }
        finally { alive.set(false); listenUdp.close(); remoteUdp.close() }
    }

    private fun reportBytes(up: Long, down: Long, reverse: Boolean = false) {
        val upstream = if (reverse) down else up
        val downstream = if (reverse) up else down
        if (upstream > 0) upstreamBytes.addAndGet(upstream)
        if (downstream > 0) downstreamBytes.addAndGet(downstream)
        onBytes(upstream, downstream)
    }

    // Production default rejects loopback, RFC1918, CGNAT, link local, documentation,
    // benchmarking, unique-local IPv6, multicast, and other non-global IP destinations.
    // Tests may override this ONLY for a local echo/TLS server.
    private fun isGlobalUnicast(addr: InetAddress): Boolean {
        if (addr.isAnyLocalAddress || addr.isLoopbackAddress || addr.isLinkLocalAddress ||
            addr.isSiteLocalAddress || addr.isMulticastAddress) return false
        val b = addr.address
        if (addr is Inet4Address) {
            val a=b[0].toInt() and 255; val c=b[1].toInt() and 255; val d=b[2].toInt() and 255
            return when {
                a == 0 || a == 10 || a == 127 || a >= 224 -> false
                a == 100 && c in 64..127 -> false // carrier-grade NAT 100.64/10
                a == 169 && c == 254 -> false
                a == 172 && c in 16..31 -> false
                a == 192 && (c == 168 || c == 0) -> false
                a == 192 && c == 88 && d == 99 -> false
                a == 192 && c == 0 && d == 2 -> false
                a == 198 && (c in 18..19 || (c == 51 && d == 100)) -> false
                a == 203 && c == 0 && d == 113 -> false
                else -> true
            }
        }
        if (addr is Inet6Address) {
            val a=b[0].toInt() and 255; val c=b[1].toInt() and 255
            if (a and 0xFE == 0xFC) return false // fc00::/7 private ULA
            if (a == 0x20 && c == 0x01 && b[2].toInt() and 255 == 0x0d && b[3].toInt() and 255 == 0xb8) return false // 2001:db8::/32 docs
            return true
        }
        return false
    }

    private fun resolveTargets(host: String): List<InetAddress> = runCatching {
        resolveHost(host)
            .filter { addr -> allowPrivateDestinations || isGlobalUnicast(addr) }
            // Prefer A over AAAA on networks where IPv6 reachability is unknown;
            // automatically fall back if the IPv4 socket fails to connect.
            .sortedBy { if (it is Inet4Address) 0 else 1 }
            .distinctBy { it.hostAddress }
            // Bound DNS fan-out so a malicious/huge answer cannot stall one session.
            .take(8)
    }.getOrDefault(emptyList())

    private fun resolveTarget(host: String): InetAddress? = resolveTargets(host).firstOrNull()

    private fun decodeAddress(input: DataInputStream): String? = when (input.readUnsignedByte()) {
        1 -> ByteArray(4).also { input.readFully(it) }.let { InetAddress.getByAddress(it).hostAddress }
        3 -> { val n = input.readUnsignedByte(); if (n == 0) null else ByteArray(n).also { input.readFully(it) }.toString(Charsets.UTF_8) }
        4 -> ByteArray(16).also { input.readFully(it) }.let { InetAddress.getByAddress(it).hostAddress }
        else -> null
    }

    private fun reply(output: OutputStream, code: Int, bindAddr: InetAddress? = null, bindPort: Int = 0) {
        val addr = (bindAddr as? Inet4Address)?.address ?: byteArrayOf(0,0,0,0)
        output.write(byteArrayOf(5,code.toByte(),0,1) + addr + byteArrayOf((bindPort shr 8).toByte(), bindPort.toByte()))
        output.flush()
    }

    @Synchronized override fun close() {
        active.set(false)
        runCatching { server?.close() }
        clients.forEach { runCatching { it.close() } }
        remoteSockets.forEach { runCatching { it.close() } }
        runCatching { acceptThread?.join(500) }
        onLog("Gateway stopped. Upload=${upstreamBytes.get()} download=${downstreamBytes.get()}")
    }
}
