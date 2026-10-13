package com.internetbattery.broker

import com.internetbattery.capacity.*
import com.internetbattery.gateway.Socks5Gateway
import com.internetbattery.roaming.VoucherSessionAuthorizer
import com.internetbattery.capacity.LocalGatewayVoucherVerifier
import java.io.DataInputStream
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.time.Clock
import java.util.Comparator
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/**
 * A full virtual two-location pilot using ACTUAL OS sockets:
 * home gateway -> independently co-signed real-byte receipt -> local HTTP clearinghouse
 * -> signed destination-specific quota -> second gateway -> real relayed echo bytes.
 * Nothing here claims Android VPN or carrier WAN success.
 */
object BrokerRoamingSmoke {
    @JvmStatic fun main(args: Array<String>) {
        val local = InetAddress.getByName("127.0.0.1")
        val folder = Files.createTempDirectory("ib-v05-broker-")
        val random = SecureRandom()
        fun key() = ByteArray(32).also(random::nextBytes)
        val issuerKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val homeSecret = key()
        val aliceSecret = key()
        val bobSecret = key()
        val carolSecret = key()
        val journalKey = key()
        val ledger = CapacityLedger(folder.resolve("credits.journal"), journalKey,
            listOf(TrustedGateway("home", "alice", homeSecret)), Clock.systemUTC())
        try {
            // Explicit laboratory-only starting units: the test does NOT claim a
            // live mobile data operator sold or gave these bytes to Bob.
            ledger.seedTestQuota("bob",100)
            ledger.seedTestQuota("carol",10) // laboratory stress-test units, NOT real earned GB
            val broker = MutualReceiptBroker(ledger,issuerKey.private,
                mapOf("alice" to aliceSecret,"bob" to bobSecret,"carol" to carolSecret),setOf("away"))
            LoopbackBrokerServer(broker,issuerKey.public).use { http ->
                http.start()
                val root="http://127.0.0.1:${http.boundPort}"
                check(getStatus("$root/v1/health")==200)
                val original = "HELLO-WIFI".toByteArray(Charsets.US_ASCII)
                val homeTraffic = runGatewayEcho(local, original,"ib","home-strong-password-for-test") { }
                check(homeTraffic.first==original.size.toLong() && homeTraffic.second==original.size.toLong())
                val receipt = GatewayReceiptSigner("home",homeSecret).sign(
                    "measured_receipt", "bob", homeTraffic.first, homeTraffic.second, System.currentTimeMillis()
                )
                val receiptFields = receiptForm(receipt)
                check(post(root,"/v1/settle", receiptFields) == 400) { "Missing consumer proof was accepted" }
                check(post(root,"/v1/settle", receiptFields + ("consumerSig" to MutualReceiptBroker.signConsumerApproval(aliceSecret,receipt))) == 403)
                val validAck = MutualReceiptBroker.signConsumerApproval(bobSecret,receipt)
                check(post(root,"/v1/settle", receiptFields + ("consumerSig" to validAck)) == 201)
                check(post(root,"/v1/settle", receiptFields + ("consumerSig" to validAck)) == 403)
                check(ledger.balance("bob")==100-homeTraffic.first-homeTraffic.second)
                check(ledger.balance("alice")==homeTraffic.first+homeTraffic.second)
                println("PASS REAL home SOCKS bytes settled only with gateway MAC + independent consumer MAC; replay rejected")

                val altered = receipt.copy(uplinkBytes = receipt.uplinkBytes+1)
                check(post(root,"/v1/settle",receiptForm(altered) + ("consumerSig" to validAck)) == 403)
                check(post(root,"/v1/settle",receiptFields + ("consumerSig" to validAck) + ("bad" to "x")) == 403)
                println("PASS forged, modified and unauthenticated usage records rejected")

                val spendBytes = original.size.toLong()*2
                val fakeGatewayId="ghost-voucher"
                val fakeAuth = MutualReceiptBroker.signIssueRequest(aliceSecret,"alice",fakeGatewayId,"unknown_gateway",spendBytes)
                check(post(root,"/v1/issue",mapOf("holder" to "alice","id" to fakeGatewayId,
                    "gateway" to "unknown_gateway","bytes" to spendBytes.toString(),"minutes" to "30",
                    "authorization" to fakeAuth)) == 403)
                check(broker.balance("alice")==spendBytes) // no debit for an unregistered destination
                println("PASS unknown offsite gateway cannot consume earned balance")
                val id="away_credit_1"
                val wrongAuthorization = MutualReceiptBroker.signIssueRequest(bobSecret,"alice",id,"away",spendBytes)
                val issuerFields = mapOf("holder" to "alice","id" to id,"gateway" to "away",
                    "bytes" to spendBytes.toString(),"minutes" to "30")
                check(post(root,"/v1/issue",issuerFields + ("authorization" to wrongAuthorization)) == 403)
                check(post(root,"/v1/issue",issuerFields + ("authorization" to "forged")) == 403)
                val holderMac=MutualReceiptBroker.signIssueRequest(aliceSecret,"alice",id,"away",spendBytes)
                val (issueStatus, issueResponse) = request(root,"/v1/issue",issuerFields + ("authorization" to holderMac))
                check(issueStatus == 201)
                val token=issueResponse.lines().first { it.startsWith("voucher=") }.substringAfter('=')
                val portable=VoucherCredential.decode(token) ?: error("Failed to decode signed voucher")
                check(portable.targetGateway == "away" && portable.quotaBytes == spendBytes)
                check(post(root,"/v1/issue",issuerFields + ("authorization" to holderMac)) == 403)
                check(broker.balance("alice") == 0L)
                println("PASS issued signed OFFSITE bearer voucher only after real, dual-approved accounting")

                val awayKey=key()
                val awayVerifier=LocalGatewayVoucherVerifier("away",issuerKey.public,folder.resolve("away.journal"),awayKey)
                val outsider=LocalGatewayVoucherVerifier("other_gateway",issuerKey.public,folder.resolve("other.journal"),key())
                check(!outsider.canSpend(portable,"alice"))
                check(!awayVerifier.canSpend(portable.copy(quotaBytes=spendBytes+1),"alice"))
                check(!awayVerifier.canSpend(portable,"bob"))
                val spent=runGatewayEcho(local, original,"alice",token) { gatewayConstructor ->
                    gatewayConstructor(VoucherSessionAuthorizer(awayVerifier))
                }
                check(spent.first==original.size.toLong() && spent.second==original.size.toLong())
                check(awayVerifier.spentBytes(portable.voucherId)==portable.quotaBytes)
                val restored=LocalGatewayVoucherVerifier("away",issuerKey.public,folder.resolve("away.journal"),awayKey)
                check(!restored.canSpend(portable,"alice"))
                println("PASS actual second-gateway socket transfer consumes exact signed quota; wrong site/reuse denied")

                // Verify robust parsing and resource limits of the clearinghouse front end.
                check(post(root,"/v1/issue", issuerFields + ("id" to "other"), "id=other&holder=alice&id=duplicate") == 400)
                val huge= "x".repeat(9000)
                check(post(root,"/v1/issue", issuerFields + ("authorization" to holderMac), "x=$huge") == 413)
                println("PASS HTTP broker refuses oversized requests and duplicated form fields")

                val veryLongId="z".repeat(100)
                val tooLargeAuth=MutualReceiptBroker.signIssueRequest(carolSecret,"carol",veryLongId,"away",1)
                check(post(root,"/v1/issue",mapOf("holder" to "carol","id" to veryLongId,
                    "gateway" to "away","bytes" to "1","minutes" to "30","authorization" to tooLargeAuth)) == 403)
                check(broker.balance("carol")==10L)
                println("PASS overlength SOCKS5 bearer rejected BEFORE spending balance")

                val startGate=CountDownLatch(1)
                val finished=CountDownLatch(30)
                val accepted=java.util.concurrent.atomic.AtomicInteger(0)
                val denied=java.util.concurrent.atomic.AtomicInteger(0)
                val failures=java.util.concurrent.atomic.AtomicInteger(0)
                repeat(30) { index ->
                    thread(isDaemon=true, name="ib-http-issue-$index") {
                        try {
                            startGate.await()
                            val raceId="race_$index"
                            val auth=MutualReceiptBroker.signIssueRequest(carolSecret,"carol",raceId,"away",1)
                            val status=post(root,"/v1/issue",mapOf("holder" to "carol","id" to raceId,
                                "gateway" to "away","bytes" to "1","minutes" to "30","authorization" to auth))
                            when(status) {
                                201 -> accepted.incrementAndGet()
                                403 -> denied.incrementAndGet()
                                else -> failures.incrementAndGet()
                            }
                        } catch (_: Throwable) { failures.incrementAndGet() }
                        finally { finished.countDown() }
                    }
                }
                startGate.countDown()
                check(finished.await(20,TimeUnit.SECONDS)) { "Broker HTTP concurrency test timed out" }
                check(accepted.get()==10 && denied.get()==20 && failures.get()==0) {
                    "Expected 10 granted + 20 rejected + 0 errors, got ${accepted.get()} / ${denied.get()} / ${failures.get()}"
                }
                check(broker.balance("carol")==0L)
                println("PASS 30 parallel HTTP voucher issuance attempts: exactly 10 funded, 20 denied")
            }
            val reloaded=CapacityLedger(folder.resolve("credits.journal"),journalKey,listOf(TrustedGateway("home","alice",homeSecret)))
            check(reloaded.balance("alice")==0L && reloaded.balance("bob")==100-20L && reloaded.balance("carol")==0L)
            println("PASS broker credit journal survives restart without restoring spent credit")
        } finally {
            Files.walk(folder).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    private fun receiptForm(r: UsageReceipt): Map<String,String> = mapOf(
        "id" to r.id, "gateway" to r.gatewayId,"consumer" to r.consumerId,
        "up" to r.uplinkBytes.toString(), "down" to r.downlinkBytes.toString(),
        "at" to r.createdAtMs.toString(),"gatewaySig" to r.signature
    )

    private fun getStatus(url:String):Int=(java.net.URI.create(url).toURL().openConnection() as HttpURLConnection).run {
        connectTimeout=2000;readTimeout=2000
        try { responseCode } finally { disconnect() }
    }
    private fun post(root:String,path:String, form:Map<String,String>, raw:String?=null):Int = request(root,path,form,raw).first
    private fun request(root:String,path:String,form:Map<String,String>,raw:String?=null):Pair<Int,String> {
        val c=(java.net.URI.create("$root$path").toURL().openConnection() as HttpURLConnection).apply {
            requestMethod="POST";doOutput=true;connectTimeout=2500;readTimeout=2500
            setRequestProperty("Content-Type","application/x-www-form-urlencoded")
        }
        return try {
            c.outputStream.use { it.write((raw ?: LoopbackBrokerServer.form(form)).toByteArray(Charsets.UTF_8)) }
            val status=c.responseCode
            val stream=if(status in 200..299) c.inputStream else c.errorStream
            status to (stream?.bufferedReader()?.readText() ?: "")
        } finally { c.disconnect() }
    }

    /** Starts a genuine loopback gateway and TCP echo endpoint; both use OS sockets. */
    private fun runGatewayEcho(
        address: InetAddress, bytes: ByteArray, username:String, credential:String,
        configure: (( (com.internetbattery.gateway.SessionAuthorizer) -> Unit) -> Unit)
    ): Pair<Long,Long> {
        ServerSocket(0,2,address).use { echo ->
            val done=CountDownLatch(1)
            val echoJob=thread(isDaemon=true,name="ib-echo") {
                echo.accept().use { incoming ->
                    incoming.soTimeout=3000
                    val received=ByteArray(bytes.size)
                    DataInputStream(incoming.getInputStream()).readFully(received)
                    check(received.contentEquals(bytes))
                    incoming.getOutputStream().write(received)
                    incoming.getOutputStream().flush()
                    done.countDown()
                }
            }
            var signedAuthorizer:com.internetbattery.gateway.SessionAuthorizer?=null
            configure { signedAuthorizer=it }
            val measured = AtomicReference<Pair<Long,Long>?>(null)
            Socks5Gateway(address,0,username="ib",password="home-strong-password-for-test",
                sessionAuthorizer=signedAuthorizer,allowPrivateDestinations=true,
                onSessionCompleted={measured.set(it.upstreamBytes to it.downstreamBytes)}).use { gateway ->
                check(gateway.start())
                Socket(address,gateway.boundPort).use { client ->
                    client.soTimeout=3500
                    val input=DataInputStream(client.getInputStream());val output=client.getOutputStream()
                    output.write(byteArrayOf(5,1,2)); output.flush()
                    check(input.readUnsignedByte()==5 && input.readUnsignedByte()==2)
                    val u=username.toByteArray(Charsets.US_ASCII);val p=credential.toByteArray(Charsets.US_ASCII)
                    check(u.size in 1..255 && p.size in 1..255)
                    output.write(byteArrayOf(1,u.size.toByte())+u+byteArrayOf(p.size.toByte())+p);output.flush()
                    check(input.readUnsignedByte()==1 && input.readUnsignedByte()==0)
                    output.write(byteArrayOf(5,1,0,1)+address.address +
                        byteArrayOf((echo.localPort ushr 8).toByte(),echo.localPort.toByte()));output.flush()
                    val response=ByteArray(10);input.readFully(response);check(response[1]==0.toByte())
                    output.write(bytes);output.flush()
                    val reply=ByteArray(bytes.size);input.readFully(reply);check(reply.contentEquals(bytes))
                    client.shutdownOutput()
                }
                check(done.await(3000,TimeUnit.MILLISECONDS))
                echoJob.join(3000)
                val deadline=System.currentTimeMillis()+2000
                while(measured.get()==null && System.currentTimeMillis()<deadline) Thread.sleep(10)
                return measured.get() ?: error("Session measurement never finalized")
            }
        }
    }
}
