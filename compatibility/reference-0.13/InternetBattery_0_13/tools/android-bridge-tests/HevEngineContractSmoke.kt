import android.content.Context
import com.internetbattery.HevEngine
import hev.htproxy.TProxyService
import java.nio.file.Files

/** Offline compilation of Android bridge against explicit documented JNI API stub.
 * Not an Android app or a native SO integration test. */
object HevEngineContractSmoke {
    @JvmStatic fun main(args: Array<String>) {
        val tmp=Files.createTempDirectory("ib-hev-bridge-")
        val context=Context(tmp.toFile())
        val statuses=mutableListOf<String>()
        val bridge=HevEngine(context) { synchronized(statuses) { statuses.add(it) } }
        check(runCatching { bridge.start(5,"127.0.0.1",8888,"bad") }.isFailure)
        check(runCatching { bridge.start(5,"; bad yml",8888,"1234567890123456") }.isFailure)
        bridge.start(5,"192.168.49.1",8888,"validSecret123456","test-user")
        var count=0
        while (!bridge.isRunning() && count++<100) Thread.sleep(10)
        check(bridge.isRunning())
        val conf=Files.readString(java.nio.file.Path.of(TProxyService.currentConfig()))
        check("192.168.49.1" in conf && "test-user" in conf)
        check("ipv4: 10.7.0.2" in conf && "ipv6: 'fd72:1b:07::2'" in conf)
        check(bridge.stats()?.contentEquals(longArrayOf(1,42,1,42)) == true)
        check(runCatching { bridge.start(5,"127.0.0.1",8888,"validSecret123456") }.isFailure)
        bridge.stop()
        check(!bridge.isRunning())
        check(tmp.toFile().listFiles()?.none { it.name.endsWith(".yml") }==true)
        tmp.toFile().delete()
        println("PASS Android HevEngine Kotlin source compiled against documented upstream JNI method contract (stub)")
        println("PASS bridge dual-stack ipv4+ipv6 config, start/run/stats/stop/secret cleanup (JVM STUB)")
        println("NOTE this does NOT test actual Android OS, JNI native code, or real VPN packet transfer")
    }
}
