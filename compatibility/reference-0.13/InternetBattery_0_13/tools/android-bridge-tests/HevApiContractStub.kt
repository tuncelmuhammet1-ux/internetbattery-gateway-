package hev.htproxy
import java.util.concurrent.atomic.AtomicBoolean
object TProxyService {
    private val running = AtomicBoolean(false)
    private var configPath = ""
    @JvmStatic fun TProxyStartService(path: String, fd: Int): Boolean {
        require(fd>=0 && java.io.File(path).isFile)
        configPath=path
        running.set(true)
        while (running.get()) Thread.sleep(10)
        return true
    }
    @JvmStatic fun TProxyStopService(): Boolean { running.set(false); return true }
    @JvmStatic fun TProxyIsRunning(): Boolean = running.get()
    @JvmStatic fun TProxyGetStats(): LongArray = longArrayOf(1, 42, 1, 42)
    fun currentConfig(): String = configPath
}
