import com.internetbattery.capacity.*
import com.internetbattery.gateway.*
import com.internetbattery.roaming.VoucherTransferAllowance
import java.io.DataInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.time.Clock
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/** Integration test: real TCP bytes -> gateway session meter -> signed ledger receipt
 * -> earned voucher -> offline-bound gateway spend. Localhost, NO live Internet or Android. */
object IntegratedRoamingSmoke {
    @JvmStatic fun main(args: Array<String>) {
        val dir=Files.createTempDirectory("ib-real-byte-integration")
        try {
            val local=InetAddress.getByName("127.0.0.1")
            val gwKey=ByteArray(32){(it+71).toByte()}
            val journalKey=ByteArray(32){(it+35).toByte()}
            val ledger=CapacityLedger(dir.resolve("server.journal"),journalKey,
                listOf(TrustedGateway("home", "provider", gwKey)))
            val clock=Clock.systemUTC()
            ledger.seedTestQuota("consumer",200)
            val reported=CountDownLatch(1)
            val evidence=AtomicReference<SessionTraffic>()
            val verified=AtomicReference<Boolean>(false)
            val msg="REAL-BYTES-OVER-SOCKS5".toByteArray()
            ServerSocket(0,4,local).use { echo ->
                val thread=thread(isDaemon=true) {
                    echo.accept().use { client ->
                        val raw=ByteArray(256)
                        val n=client.getInputStream().read(raw)
                        if(n>0){ client.getOutputStream().write(raw,0,n); client.getOutputStream().flush() }
                    }
                }
                val signer=GatewayReceiptSigner("home",gwKey)
                Socks5Gateway(local,0,password="actual-proxy-secret-for-test-123",allowPrivateDestinations=true,
                    onSessionCompleted={ metered ->
                        evidence.set(metered)
                        val r=signer.sign("real-session-1","consumer",metered.upstreamBytes,metered.downstreamBytes,metered.completedAtMs)
                        verified.set(ledger.settle(r))
                        reported.countDown()
                    }).use { proxy ->
                    check(proxy.start())
                    Socket(local,proxy.boundPort).use { client ->
                        client.soTimeout=5000
                        val inp=DataInputStream(client.getInputStream()); val out=client.getOutputStream()
                        out.write(byteArrayOf(5,1,2));out.flush()
                        check(inp.readUnsignedByte()==5 && inp.readUnsignedByte()==2)
                        val u="ib".toByteArray();val p="actual-proxy-secret-for-test-123".toByteArray()
                        out.write(byteArrayOf(1,u.size.toByte())+u+byteArrayOf(p.size.toByte())+p);out.flush()
                        check(inp.readUnsignedByte()==1 && inp.readUnsignedByte()==0)
                        out.write(byteArrayOf(5,1,0,1)+local.address+byteArrayOf((echo.localPort ushr 8).toByte(),echo.localPort.toByte()));out.flush()
                        val reply=ByteArray(10);inp.readFully(reply)
                        check(reply[1].toInt()==0)
                        out.write(msg);out.flush()
                        val recv=ByteArray(msg.size);inp.readFully(recv)
                        check(recv.contentEquals(msg))
                    }
                    check(reported.await(5,TimeUnit.SECONDS)) { "Gateway session receipt missing" }
                    check(verified.get()) { "Observed traffic was not credited" }
                    val s=evidence.get()
                    check(s.upstreamBytes==msg.size.toLong() && s.downstreamBytes==msg.size.toLong())
                    check(ledger.balance("provider")==2*msg.size.toLong())
                    check(ledger.balance("consumer")==200-2*msg.size.toLong())
                    println("PASS live local SOCKS TCP measured session signed and journaled: up=${s.upstreamBytes} down=${s.downstreamBytes}")
                    val keypair=KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
                    // The provider earned exactly 2*msg.size real relay units at home.
                    // Reserve them in one signed, destination-only voucher.
                    val voucher=VoucherIssuer(ledger,keypair.private,clock).issue(
                        "provider","real-transfer-ticket","destination",2*msg.size.toLong(),30)
                    check(voucher!=null)
                    val site=LocalGatewayVoucherVerifier("destination",keypair.public,
                        dir.resolve("destination.journal"),journalKey,clock)
                    val budget=VoucherTransferAllowance(voucher,"provider",site)
                    // A SECOND proxy really carries traffic and persistently spends the voucher.
                    ServerSocket(0,4,local).use { secondEcho ->
                        val echoThread=thread(isDaemon=true) {
                            secondEcho.accept().use { c ->
                                val buff=ByteArray(256); val n=c.getInputStream().read(buff)
                                if(n>0) { c.getOutputStream().write(buff,0,n);c.getOutputStream().flush() }
                            }
                        }
                        Socks5Gateway(local,0,username="provider",password="destination-secret-for-test-123",
                            allowPrivateDestinations=true,allowance=budget).use { destination ->
                            check(destination.start())
                            Socket(local,destination.boundPort).use { bad ->
                                val i=DataInputStream(bad.getInputStream());val o=bad.getOutputStream()
                                o.write(byteArrayOf(5,1,2));o.flush()
                                check(i.readUnsignedByte()==5 && i.readUnsignedByte()==2)
                                val u="impostor".toByteArray();val pass="destination-secret-for-test-123".toByteArray()
                                o.write(byteArrayOf(1,u.size.toByte())+u+byteArrayOf(pass.size.toByte())+pass);o.flush()
                                check(i.readUnsignedByte()==1 && i.readUnsignedByte()==1)
                            }
                            Socket(local,destination.boundPort).use { c ->
                                c.soTimeout=5000
                                val input=DataInputStream(c.getInputStream());val output=c.getOutputStream()
                                output.write(byteArrayOf(5,1,2));output.flush()
                                check(input.readUnsignedByte()==5 && input.readUnsignedByte()==2)
                                val u="provider".toByteArray();val pass="destination-secret-for-test-123".toByteArray()
                                output.write(byteArrayOf(1,u.size.toByte())+u+byteArrayOf(pass.size.toByte())+pass);output.flush()
                                check(input.readUnsignedByte()==1 && input.readUnsignedByte()==0)
                                output.write(byteArrayOf(5,1,0,1)+local.address+
                                    byteArrayOf((secondEcho.localPort ushr 8).toByte(),secondEcho.localPort.toByte()))
                                output.flush()
                                val reply=ByteArray(10);input.readFully(reply);check(reply[1]==0.toByte())
                                output.write(msg);output.flush()
                                val recv=ByteArray(msg.size);input.readFully(recv);check(recv.contentEquals(msg))
                            }
                            echoThread.join(3000)
                            check(destination.upstreamBytes.get()==msg.size.toLong())
                            check(destination.downstreamBytes.get()==msg.size.toLong())
                            check(site.spentBytes(voucher.voucherId)==voucher.quotaBytes)
                            println("PASS authenticated voucher holder only; signed quota ENFORCED by destination TCP relay: "+
                                "up=${destination.upstreamBytes.get()} down=${destination.downstreamBytes.get()}")
                        }
                    }
                    val restored=LocalGatewayVoucherVerifier("destination",keypair.public,
                        dir.resolve("destination.journal"),journalKey,clock)
                    val reopened=VoucherTransferAllowance(voucher,"provider",restored)
                    check(!reopened.mayOpen())
                    check(reopened.grant(1,false)==0)
                    check(!VoucherTransferAllowance(voucher.copy(quotaBytes=200),"provider",restored).mayOpen())
                    check(!VoucherTransferAllowance(voucher,"wrong-holder",restored).mayOpen())
                    // A spent voucher must not even initiate an outbound TCP connection.
                    ServerSocket(0,4,local).use { noTrafficTarget ->
                        Socks5Gateway(local,0,username="provider",password="destination-secret-for-test-123",
                            allowPrivateDestinations=true,allowance=reopened).use { closedGate ->
                            check(closedGate.start())
                            Socket(local,closedGate.boundPort).use { c ->
                                c.soTimeout=4000
                                val input=DataInputStream(c.getInputStream());val output=c.getOutputStream()
                                output.write(byteArrayOf(5,1,2));output.flush()
                                check(input.readUnsignedByte()==5 && input.readUnsignedByte()==2)
                                val u="provider".toByteArray();val pass="destination-secret-for-test-123".toByteArray()
                                output.write(byteArrayOf(1,u.size.toByte())+u+byteArrayOf(pass.size.toByte())+pass);output.flush()
                                check(input.readUnsignedByte()==1 && input.readUnsignedByte()==0)
                                output.write(byteArrayOf(5,1,0,1)+local.address+
                                    byteArrayOf((noTrafficTarget.localPort ushr 8).toByte(),noTrafficTarget.localPort.toByte()))
                                output.flush()
                                val reply=ByteArray(10);input.readFully(reply)
                                check(reply[1]==2.toByte()) { "Spent voucher should be denied before connect" }
                            }
                            check(closedGate.upstreamBytes.get()==0L && closedGate.downstreamBytes.get()==0L)
                        }
                    }
                    println("PASS voucher quota survives restart; spent/forged/wrong-holder vouchers denied before outbound connect")
                }
                thread.join(1000)
            }
        } finally { Files.walk(dir).sorted(Comparator.reverseOrder()).forEach{Files.deleteIfExists(it)} }
    }
}
