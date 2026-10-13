import com.internetbattery.capacity.*
import com.internetbattery.gateway.*
import com.internetbattery.roaming.*
import java.io.DataInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.time.Clock
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/** Genuine local SOCKS sockets with different signed credentials; no Android, no live WAN. */
object VoucherSessionAdmissionSmoke {
    @JvmStatic fun main(args: Array<String>) {
        val dir=Files.createTempDirectory("ib-auth-voucher")
        val gatewayId="remoteA"
        val serverKey=ByteArray(32) { (it*3+7).toByte() }
        val ledger=CapacityLedger(dir.resolve("issuer.log"), ByteArray(32){(it+23).toByte()},emptyList())
        val keypair=KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        ledger.seedTestQuota("alice",32) // LAB-ONLY initial allocation, not a real earned mobile plan.
        ledger.seedTestQuota("bob",12)
        val issuer=VoucherIssuer(ledger,keypair.private)
        val alice=issuer.issue("alice","alice01",gatewayId,32,15)!!
        val bob=issuer.issue("bob","bob01",gatewayId,12,15)!!
        val token=VoucherCredential.encode(alice)
        check(token.length <= 255 && VoucherCredential.decode(token)==alice)
        check(VoucherCredential.decode(token.substring(0,token.length-4)+"abcd")!=alice)
        check(VoucherCredential.decode("IB1.${"~".repeat(200)}")==null)
        val site=LocalGatewayVoucherVerifier(gatewayId,keypair.public,dir.resolve("spent.log"),serverKey)
        val loopback=InetAddress.getByName("127.0.0.1")
        val opened=AtomicInteger()
        ServerSocket(0,25,loopback).use { echo ->
            val task=thread(isDaemon=true,name="ib-echo") {
                while(!echo.isClosed) {
                    val client=try { echo.accept() } catch (_:Exception) { break }
                    opened.incrementAndGet()
                    thread(isDaemon=true) {
                        client.use { c ->
                            c.soTimeout=2000
                            val data=ByteArray(128)
                            val n=runCatching{c.getInputStream().read(data)}.getOrDefault(-1)
                            if(n>0) { c.getOutputStream().write(data,0,n); c.getOutputStream().flush() }
                        }
                    }
                }
            }
            Socks5Gateway(loopback,0,password="legacy-password-unused-999", allowPrivateDestinations=true,
                sessionAuthorizer=VoucherSessionAuthorizer(site)).use { gateway ->
                check(gateway.start())
                // Static legacy authentication must NOT bypass signature-based voucher mode.
                check(connect(gateway.boundPort,"ib","legacy-password-unused-999", echo.localPort,ByteArray(1))==-1)
                // A voucher is holder-bound and destination-bound.
                check(connect(gateway.boundPort,"mallory",token,echo.localPort,ByteArray(1))==-1)
                val bad=alice.copy(quotaBytes=100)
                check(connect(gateway.boundPort,"alice",VoucherCredential.encode(bad),echo.localPort,ByteArray(1))==-1)
                val wrong=alice.copy(targetGateway="remoteB")
                check(connect(gateway.boundPort,"alice",VoucherCredential.encode(wrong),echo.localPort,ByteArray(1))==-1)
                // Genuine, independent session with holder alice. Two directions share ONE signed quota.
                val body="A".repeat(25).toByteArray()
                val echoBytes=connect(gateway.boundPort,"alice",token,echo.localPort,body)
                check(echoBytes in 0..7) { "Unexpected return past 32 byte two-way quota: $echoBytes" }
                val spent=site.spentBytes(alice.voucherId)
                check(spent==32L) { "Quota: expected exactly 32 bytes, actual $spent" }
                val count=opened.get()
                check(connect(gateway.boundPort,"alice",token,echo.localPort,ByteArray(1))==-1)
                check(opened.get()==count) { "Exhausted voucher opened an external target" }
                // Bob's valid independent ticket isn't affected by Alice's exhausted budget.
                val b=connect(gateway.boundPort,"bob",VoucherCredential.encode(bob),echo.localPort,"B".repeat(6).toByteArray())
                check(b==6)
                check(site.spentBytes(bob.voucherId)==12L)
                println("PASS voucher-as-RFC1929 credential: per-user authenticators; tampered/legacy/wrong-holder denied; real TCP quota 32B+12B")
                println("PASS exhausted voucher denied BEFORE outbound connection; target opened $count sessions before exhausted attempt")
            }
            echo.close();task.join(1000)
        }
        val restored=LocalGatewayVoucherVerifier(gatewayId,keypair.public,dir.resolve("spent.log"),serverKey)
        check(restored.spentBytes(alice.voucherId)==32L && restored.spentBytes(bob.voucherId)==12L)
        check(!restored.canSpend(alice,"alice") && !restored.canSpend(bob,"bob"))
        println("PASS gateway journal persisted two independent user quotas on restart")
    }

    /** -1 invalid auth, -2 authorized but quota exhausted; otherwise response payload bytes. */
    private fun connect(proxyPort:Int,user:String,password:String,targetPort:Int,payload:ByteArray):Int {
        val loop=InetAddress.getByName("127.0.0.1")
        Socket(loop,proxyPort).use { sock ->
            sock.soTimeout=3000
            val i=DataInputStream(sock.getInputStream());val o=sock.getOutputStream()
            o.write(byteArrayOf(5,1,2));o.flush()
            check(i.readUnsignedByte()==5 && i.readUnsignedByte()==2)
            val u=user.toByteArray();val p=password.toByteArray()
            check(u.size in 1..255 && p.size in 1..255)
            o.write(byteArrayOf(1,u.size.toByte())+u+byteArrayOf(p.size.toByte())+p);o.flush()
            if(i.readUnsignedByte()!=1 || i.readUnsignedByte()!=0) return -1
            o.write(byteArrayOf(5,1,0,1)+loop.address+byteArrayOf((targetPort ushr 8).toByte(),targetPort.toByte()));o.flush()
            val response=ByteArray(10);i.readFully(response)
            if(response[1]!=0.toByte()) return -2
            if(payload.isEmpty()) return 0
            o.write(payload);o.flush()
            var total=0
            val buff=ByteArray(payload.size)
            while(total<buff.size) {
                val n=runCatching { i.read(buff,total,buff.size-total) }.getOrDefault(-1)
                if(n<=0) break
                total+=n
            }
            return total
        }
    }
}
