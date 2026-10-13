import com.internetbattery.capacity.*
import com.internetbattery.gateway.*
import com.internetbattery.roaming.VoucherTransferAllowance
import java.io.DataInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread

/** Transfers only the signed byte budget, never the remainder of a TCP chunk. */
object QuotaPartialTcpSmoke {
    @JvmStatic fun main(args: Array<String>) {
        val dir=Files.createTempDirectory("ib-partial-tcp")
        val local=InetAddress.getByName("127.0.0.1")
        try {
            val key=ByteArray(32){(it+21).toByte()}
            val ledger=CapacityLedger(dir.resolve("issuer"),key,emptyList())
            ledger.seedTestQuota("participant",15)
            val kp=KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
            val voucher=VoucherIssuer(ledger,kp.private).issue("participant","partial", "site", 15)!!
            val site=LocalGatewayVoucherVerifier("site",kp.public,dir.resolve("site"),key)
            val received=AtomicInteger(-1)
            ServerSocket(0,5,local).use { sink ->
                val server=thread(isDaemon=true) {
                    sink.accept().use { incoming ->
                        incoming.soTimeout=5000
                        val buffer=ByteArray(100)
                        var total=0
                        while(true) {
                            val n=incoming.getInputStream().read(buffer)
                            if(n < 0) break
                            total+=n
                        }
                        received.set(total)
                    }
                }
                Socks5Gateway(local,0,username="participant",password="lab-secret-123456789",
                    allowPrivateDestinations=true,
                    allowance=VoucherTransferAllowance(voucher,"participant",site)).use { proxy ->
                    check(proxy.start())
                    Socket(local,proxy.boundPort).use { client ->
                        client.soTimeout=5000
                        val i=DataInputStream(client.getInputStream());val o=client.getOutputStream()
                        o.write(byteArrayOf(5,1,2));o.flush()
                        check(i.readUnsignedByte()==5&&i.readUnsignedByte()==2)
                        val u="participant".toByteArray();val p="lab-secret-123456789".toByteArray()
                        o.write(byteArrayOf(1,u.size.toByte())+u+byteArrayOf(p.size.toByte())+p);o.flush()
                        check(i.readUnsignedByte()==1&&i.readUnsignedByte()==0)
                        o.write(byteArrayOf(5,1,0,1)+local.address+
                            byteArrayOf((sink.localPort ushr 8).toByte(),sink.localPort.toByte()))
                        o.flush()
                        val reply=ByteArray(10);i.readFully(reply);check(reply[1]==0.toByte())
                        o.write(ByteArray(20){42});o.flush()
                    }
                    server.join(4000)
                    check(received.get()==15) { "20B TCP payload must be clipped to quota=15, got ${received.get()}" }
                    check(site.spentBytes(voucher.voucherId)==15L)
                    // Socket reader and metrics reporter run on different threads.
                    // Wait for the reporter instead of asserting a racy immediate read.
                    repeat(100) {
                        if(proxy.upstreamBytes.get()==15L) return@repeat
                        Thread.sleep(10)
                    }
                    check(proxy.upstreamBytes.get()==15L)
                    println("PASS real TCP chunk of 20B capped at 15B signed budget; no byte overrun")
                }
            }
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }
}
