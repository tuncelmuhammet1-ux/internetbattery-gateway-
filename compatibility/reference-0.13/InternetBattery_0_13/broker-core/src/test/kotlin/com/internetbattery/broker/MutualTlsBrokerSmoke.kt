package com.internetbattery.broker

import com.internetbattery.capacity.*
import com.internetbattery.gateway.Socks5Gateway
import com.internetbattery.roaming.VoucherSessionAuthorizer
import java.io.DataInputStream
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.util.Base64
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import kotlin.concurrent.thread

/** Real TLS handshake tests and relay calls over OS sockets, NOT a mobile radio test. */
object MutualTlsBrokerSmoke {
    private val local = InetAddress.getByName("127.0.0.1")

    private fun context(identity: Path?, trust: Path): SSLContext {
        val password = "changeit".toCharArray() // Ephemeral SELF-SIGNED test fixtures ONLY
        val trustStore=KeyStore.getInstance("PKCS12").apply { Files.newInputStream(trust).use { load(it,password) } }
        val tm=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trustStore) }
        val managers = identity?.let { path ->
            val own=KeyStore.getInstance("PKCS12").apply { Files.newInputStream(path).use { load(it,password) } }
            KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(own,password) }.keyManagers
        }
        return SSLContext.getInstance("TLS").apply { init(managers,tm.trustManagers,SecureRandom()) }
    }
    private fun call(root:String, ssl:SSLContext, path:String, values:Map<String,String>?=null):Pair<Int,String> {
        val con=(URL(root+path).openConnection() as HttpsURLConnection).apply {
            sslSocketFactory=ssl.socketFactory
            connectTimeout=4500; readTimeout=4500
            if (values!=null) {
                requestMethod="POST"; doOutput=true
                setRequestProperty("Content-Type","application/x-www-form-urlencoded")
                outputStream.use { it.write(LoopbackBrokerServer.form(values).toByteArray()) }
            }
        }
        return try {
            val code=con.responseCode
            code to (if(code<400) con.inputStream else con.errorStream)?.bufferedReader()?.readText().orEmpty()
        } finally { con.disconnect() }
    }

    private fun relay(secret:String, user:String, payload:ByteArray, voucherAuthorizer:VoucherSessionAuthorizer?=null): Pair<Long,Long> {
        val echo=ServerSocket(0,10,local)
        val echoThread=thread(isDaemon=true,name="ib-mtls-echo") {
            echo.use { server ->
                server.accept().use { inbound ->
                    val b=ByteArray(payload.size)
                    DataInputStream(inbound.getInputStream()).readFully(b)
                    inbound.getOutputStream().write(b)
                    inbound.getOutputStream().flush()
                }
            }
        }
        Socks5Gateway(local,0,username="ib",password="strong-lab-password-1234",
            allowPrivateDestinations=true,sessionAuthorizer=voucherAuthorizer).use { gateway ->
            check(gateway.start())
            Socket(local,gateway.boundPort).use { c ->
                c.soTimeout=5000
                val inp=DataInputStream(c.getInputStream())
                val out=c.getOutputStream()
                out.write(byteArrayOf(5,1,2)); out.flush()
                check(inp.readUnsignedByte()==5 && inp.readUnsignedByte()==2)
                val u=user.toByteArray(); val p=secret.toByteArray()
                check(u.size in 1..255 && p.size in 1..255)
                out.write(byteArrayOf(1,u.size.toByte())+u+byteArrayOf(p.size.toByte())+p);out.flush()
                check(inp.readUnsignedByte()==1 && inp.readUnsignedByte()==0)
                out.write(byteArrayOf(5,1,0,1,127,0,0,1,(echo.localPort shr 8).toByte(),echo.localPort.toByte()))
                out.flush()
                val rep=ByteArray(10);inp.readFully(rep)
                check(rep[1]==0.toByte())
                out.write(payload);out.flush()
                val got=ByteArray(payload.size);inp.readFully(got)
                check(got.contentEquals(payload))
            }
            echoThread.join(2000)
            var tries=0
            while (gateway.upstreamBytes.get()+gateway.downstreamBytes.get()<payload.size*2 && tries++<100) Thread.sleep(10)
            return gateway.upstreamBytes.get() to gateway.downstreamBytes.get()
        }
    }

    @JvmStatic fun main(args:Array<String>) {
        require(args.size==5) { "server.p12, client.p12, serverTrust.p12, clientTrust.p12, rogue.p12" }
        val serverTLS=context(Path.of(args[0]),Path.of(args[2]))
        val clientTLS=context(Path.of(args[1]),Path.of(args[3]))
        val noCertTLS=context(null,Path.of(args[3]))
        val rogueTLS=context(Path.of(args[4]),Path.of(args[3]))
        val folder=Files.createTempDirectory("ib-mtls-pilot-")
        fun secret()=ByteArray(32).also(SecureRandom()::nextBytes)
        val issuer=KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val gatewayKey=secret();val consumerKey=secret();val homeOwnerKey=secret();val journalKey=secret()
        val ledger=CapacityLedger(folder.resolve("ledger.journal"),journalKey,
            listOf(TrustedGateway("home","home_owner",gatewayKey)))
        ledger.seedTestQuota("visitor",256)
        val broker=MutualReceiptBroker(ledger,issuer.private,mapOf("visitor" to consumerKey,
            "home_owner" to homeOwnerKey),setOf("destination"))
        MutualTlsBrokerServer(broker,issuer.public,serverTLS,local).use { server ->
            server.start()
            val root="https://localhost:${server.boundPort}"
            check(call(root,clientTLS,"/v1/health").first==200)
            println("PASS HTTPS health with pinned server trust and authorized client certificate")
            check(runCatching{call(root,noCertTLS,"/v1/health")}.isFailure)
            check(runCatching{call(root,rogueTLS,"/v1/health")}.isFailure)
            println("PASS mTLS rejects missing and untrusted client certificates")
            check(runCatching { (URL(root+"/v1/health").openConnection() as HttpsURLConnection).apply {
                sslSocketFactory=SSLContext.getDefault().socketFactory
                connectTimeout=3000;readTimeout=3000
            }.inputStream.use { it.read() } }.isFailure)
            println("PASS default public trust does not accept private test broker identity")
            val data="MOBILE-ROAMING".toByteArray()
            val (up,down)=relay("strong-lab-password-1234","ib",data)
            check(up==data.size.toLong() && down==up)
            val receipt=GatewayReceiptSigner("home",gatewayKey).sign("tls_receipt","visitor",up,down,System.currentTimeMillis())
            val settlement=mapOf("id" to receipt.id,"gateway" to receipt.gatewayId,"consumer" to receipt.consumerId,
                "up" to up.toString(),"down" to down.toString(),"at" to receipt.createdAtMs.toString(),
                "gatewaySig" to receipt.signature,"consumerSig" to MutualReceiptBroker.signConsumerApproval(consumerKey,receipt))
            check(call(root,clientTLS,"/v1/settle",settlement).first==201)
            check(call(root,clientTLS,"/v1/settle",settlement).first==403)
            check(broker.balance("home_owner")==up+down)
            println("PASS actual measured home SOCKS bytes double approved over mTLS, replay denied")
            val id="destination_1"
            val signed=MutualReceiptBroker.signIssueRequest(homeOwnerKey,"home_owner",id,"destination",16)
            // Visitor has LAB test-funded units; they pay the home gateway. Home owner then spends EARNED units at a second gateway.
            val req=mapOf("holder" to "home_owner","id" to id,"gateway" to "destination", "bytes" to "16",
                "minutes" to "30","authorization" to signed)
            val issuance=call(root,clientTLS,"/v1/issue",req)
            check(issuance.first==201)
            val bearer=issuance.second.lines().first{it.startsWith("voucher=")}.substringAfter('=')
            val token=VoucherCredential.decode(bearer) ?: error("invalid signed access voucher")
            val verifier=LocalGatewayVoucherVerifier("destination",issuer.public,folder.resolve("destination.journal"),secret())
            val second=relay(bearer,"home_owner","12345678".toByteArray(), VoucherSessionAuthorizer(verifier))
            check(second.first==8L && second.second==8L && verifier.spentBytes(token.voucherId)==16L)
            check(!verifier.canSpend(token,"home_owner"))
            check(broker.balance("home_owner") == up + down - 16L)
            check(call(root,clientTLS,"/v1/issue",req).first==403)
            println("PASS home owner EARNED metered transfer credits -> mTLS signed voucher -> second REAL SOCKET gateway; quota/replay enforced")
            println("NOTE both gateways share localhost in lab; physical roaming and cellular usage NOT verified")
        }
    }
}
