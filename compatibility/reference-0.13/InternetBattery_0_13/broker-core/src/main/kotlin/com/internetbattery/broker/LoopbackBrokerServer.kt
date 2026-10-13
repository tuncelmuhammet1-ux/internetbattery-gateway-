package com.internetbattery.broker

import com.internetbattery.capacity.UsageReceipt
import com.internetbattery.capacity.VoucherCredential
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import com.sun.net.httpserver.HttpsServer
import com.sun.net.httpserver.HttpsParameters
import com.sun.net.httpserver.HttpsConfigurator
import javax.net.ssl.SSLContext
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.PublicKey
import java.util.Base64
import java.util.concurrent.Executors

/** Shared laboratory request processor. Only instantiate through the loopback HTTP
 * wrapper or a TLS endpoint that REQUIRES a client certificate. Not a payments API.
 */
internal class BrokerApiServer(
    private val broker: MutualReceiptBroker,
    issuerPublic: PublicKey,
    private val server: HttpServer
) : AutoCloseable {
    private val workers = Executors.newFixedThreadPool(4)
    private val pub = Base64.getUrlEncoder().withoutPadding().encodeToString(issuerPublic.encoded)
    val boundPort: Int get() = server.address.port

    init {
        server.executor = workers
        server.createContext("/v1/health") { ex ->
            if (ex.requestMethod != "GET") reject(ex, 405, "method_not_allowed")
            else reply(ex, 200, "lab_only=1\nstatus=ready\n")
        }
        server.createContext("/v1/settle") { ex ->
            process(ex) { form ->
                val receipt = UsageReceipt(
                    id = form.need("id"), gatewayId = form.need("gateway"), consumerId = form.need("consumer"),
                    uplinkBytes = form.need("up").toLong(), downlinkBytes = form.need("down").toLong(),
                    createdAtMs = form.need("at").toLong(), signature = form.need("gatewaySig")
                )
                if (!broker.settle(receipt, form.need("consumerSig"))) {
                    reject(ex, 403, "invalid_or_replayed_receipt")
                } else reply(ex, 201, "settled=1\n")
            }
        }
        server.createContext("/v1/issue") { ex ->
            process(ex) { form ->
                val holder = form.need("holder")
                val id = form.need("id")
                val gateway = form.need("gateway")
                val bytes = form.need("bytes").toLong()
                val minutes = form.need("minutes").toLong()
                val voucher = broker.issueVoucher(holder, id, gateway, bytes, form.need("authorization"), minutes)
                if (voucher == null) reject(ex, 403, "invalid_request_or_insufficient_credit")
                else reply(ex, 201, "voucher=${VoucherCredential.encode(voucher)}\nissuer_public=$pub\n")
            }
        }
    }

    private fun process(ex: HttpExchange, action: (Map<String,String>) -> Unit) {
        if (ex.requestMethod != "POST") { reject(ex, 405, "method_not_allowed"); return }
        try {
            if (ex.requestHeaders.getFirst("Content-Type")?.substringBefore(';') != "application/x-www-form-urlencoded") {
                reject(ex, 415, "unsupported_media_type"); return
            }
            val body = ex.requestBody.use { it.readNBytes(8193) }
            if (body.size > 8192) { reject(ex, 413, "payload_too_large"); return }
            val encoded = String(body, StandardCharsets.UTF_8)
            if (encoded.contains('\u0000')) { reject(ex, 400, "invalid_body"); return }
            val fields = linkedMapOf<String, String>()
            for (piece in encoded.split('&')) {
                if (piece.isEmpty()) continue
                val parts = piece.split('=', limit = 2)
                require(parts.size == 2)
                val key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8)
                val value = URLDecoder.decode(parts[1], StandardCharsets.UTF_8)
                require(key.matches(Regex("[A-Za-z]{1,30}")) && !fields.containsKey(key))
                fields[key] = value
            }
            action(fields)
        } catch (_: IllegalArgumentException) { reject(ex, 400, "invalid_body") }
          catch (_: ArithmeticException) { reject(ex, 400, "invalid_number") }
          catch (_: Exception) { reject(ex, 500, "internal_error") }
    }

    private fun Map<String, String>.need(name: String): String = get(name) ?: throw IllegalArgumentException("missing_$name")
    private fun reject(ex: HttpExchange, code: Int, detail: String) = reply(ex, code, "error=$detail\n")
    private fun reply(ex: HttpExchange, code: Int, body: String) {
        val data = body.toByteArray(StandardCharsets.UTF_8)
        ex.responseHeaders.set("Content-Type", "text/plain; charset=utf-8")
        ex.responseHeaders.set("Cache-Control", "no-store")
        ex.responseHeaders.set("X-Content-Type-Options", "nosniff")
        ex.sendResponseHeaders(code, data.size.toLong())
        ex.responseBody.use { it.write(data) }
    }
    fun start() { server.start() }
    override fun close() { server.stop(0); workers.shutdownNow() }

    companion object {
        fun form(fields: Map<String,String>): String = fields.entries.joinToString("&") { (k,v) ->
            "${URLEncoder.encode(k,StandardCharsets.UTF_8)}=${URLEncoder.encode(v,StandardCharsets.UTF_8)}"
        }
    }
}

/** Local-only development broker. This class deliberately exposes NO LAN port. */
class LoopbackBrokerServer(
    broker: MutualReceiptBroker, issuerPublic: PublicKey, port: Int = 0
) : AutoCloseable {
    private val service = BrokerApiServer(broker, issuerPublic,
        HttpServer.create(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 20))
    val boundPort: Int get() = service.boundPort
    fun start() = service.start()
    override fun close() = service.close()
    companion object {
        fun form(fields: Map<String, String>): String = BrokerApiServer.form(fields)
    }
}

/**
 * A separate mTLS entry point for authorized, geographically distinct gateways.
 * The caller MUST supply an SSLContext with a private server key and a trust store
 * containing ONLY authorized client CAs/certificates. Client auth cannot be disabled.
 * This is a lab/developer service, not a billing/payment system.
 */
class MutualTlsBrokerServer(
    broker: MutualReceiptBroker,
    issuerPublic: PublicKey,
    sslContext: SSLContext,
    listenAddress: InetAddress = InetAddress.getLoopbackAddress(),
    port: Int = 0
) : AutoCloseable {
    private val server = HttpsServer.create(InetSocketAddress(listenAddress, port), 20).apply {
        httpsConfigurator = object : HttpsConfigurator(sslContext) {
            override fun configure(params: HttpsParameters) {
                // Never permit a plaintext endpoint or unauthenticated TLS client.
                val conf = sslContext.defaultSSLParameters
                conf.needClientAuth = true
                conf.protocols = conf.protocols.filter { it == "TLSv1.3" || it == "TLSv1.2" }.toTypedArray()
                params.setSSLParameters(conf)
            }
        }
    }
    private val service = BrokerApiServer(broker, issuerPublic, server)
    val boundPort: Int get() = service.boundPort
    fun start() = service.start()
    override fun close() = service.close()
}
