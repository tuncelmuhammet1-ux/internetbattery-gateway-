package com.internetbattery

import android.content.Context
import android.util.Log
import hev.htproxy.TProxyService
import java.io.File
import kotlin.concurrent.thread

/**
 * Version-locked hev-socks5-tunnel 2.18.0 AAR integration.
 * Calls the upstream PUBLIC Java JNI binding directly. This must compile with
 * the downloaded and SHA-256 verified AAR, rather than hiding API mistakes
 * behind reflection that would fail only on a user's phone.
 *
 * AAR source: https://github.com/heiher/hev-socks5-tunnel (MIT).
 * Android assembly/physical TUN validation is STILL REQUIRED.
 * The native worker starts asynchronously; do not delete its config from
 * the Java starter thread immediately after TProxyStartService returns.
 */
class HevEngine(private val context: Context, private val onStatus: (String) -> Unit) {
    private var configFile: File? = null
    private var nativeThread: Thread? = null
    private val guard = Any()

    fun start(fd: Int, proxyIp: String, port: Int, secret: String, username: String = "ib") {
        require(fd >= 0 && port in 1..65535)
        require(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}").matches(proxyIp))
        require(secret.matches(Regex("[A-Za-z0-9_.-]{16,255}"))) { "Geçersiz eşleştirme kodu/belge" }
        require(username.matches(Regex("[A-Za-z0-9_-]{1,100}"))) { "Kullanıcı adı geçersiz" }
        synchronized(guard) {
            require(nativeThread?.isAlive != true) { "VPN motoru zaten çalışıyor" }
            val conf = File.createTempFile("ib-tun-", ".yml", context.filesDir)
            conf.writeText("""
                tunnel:
                  mtu: 1500
                  ipv4: ${FullTunnelRoutes.CLIENT_IPV4}
                  ipv6: '${FullTunnelRoutes.CLIENT_IPV6}'
                socks5:
                  address: '$proxyIp'
                  port: $port
                  username: '$username'
                  password: '$secret'
                  udp: 'udp'
                misc:
                  log-level: warn
            """.trimIndent())
            configFile = conf
            nativeThread = thread(name = "ib-native-tunnel", isDaemon = true) {
                try {
                    // Native may block while tunnel is active. Only isRunning + HTTPS
                    // + counters can prove real traffic is being relayed.
                    val started = TProxyService.TProxyStartService(conf.absolutePath, fd)
                    if (!started) onStatus("Native tun2socks başlatma başarısız")
                    else onStatus("Native tun2socks tamamlandı; bağlantı doğrulanmalı")
                } catch (e: Throwable) {
                    Log.e("InternetBattery", "Native tunnel failure", e)
                    onStatus("Native AAR/JNI hatası: ${e.message}")
                } finally {
                    // The pinned hev JNI returns after creating a native pthread.
                    // It does not wait for the pthread to open this YAML file.
                    // Keep the config alive through native startup and transfer;
                    // stop() removes it only AFTER TProxyStopService has joined.
                }
            }
        }
    }

    fun isRunning(): Boolean = try { TProxyService.TProxyIsRunning() }
        catch (_: Throwable) { false }

    fun stats(): LongArray? = try { TProxyService.TProxyGetStats() }
        catch (_: Throwable) { null }

    fun stop() {
        runCatching { TProxyService.TProxyStopService() }
        val t = synchronized(guard) { nativeThread }
        // Give the blocking native call a chance to unwind before removing its
        // config file. Never wait indefinitely in a foreground-service teardown.
        if (t != Thread.currentThread()) runCatching { t?.join(1200) }
        synchronized(guard) {
            configFile?.delete()
            configFile = null
            if (nativeThread === t) nativeThread = null
        }
    }
}
