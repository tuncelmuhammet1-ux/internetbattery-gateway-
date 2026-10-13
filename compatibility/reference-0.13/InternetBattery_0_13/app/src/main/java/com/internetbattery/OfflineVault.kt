package com.internetbattery

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection

data class OfflinePage(val url: String, val filename: String, val size: Int, val savedAt: Long)

/** Saves only individually selected HTTPS text pages. Never represents them as live Internet quota. */
class OfflineVault(private val ctx: Context) {
    private val root=File(ctx.filesDir,"offline_pages").apply { mkdirs() }
    private val prefs=ctx.getSharedPreferences("vault",Context.MODE_PRIVATE)

    @Synchronized fun list():List<OfflinePage> = runCatching {
        val array=JSONArray(prefs.getString("pages","[]"))
        (0 until array.length()).map { i ->
            val v=array.getJSONObject(i)
            OfflinePage(v.getString("url"),v.getString("filename"),v.getInt("size"),v.getLong("savedAt"))
        }.filter { File(root,it.filename).isFile }
    }.getOrDefault(emptyList())

    suspend fun save(urlString:String):OfflinePage=withContext(Dispatchers.IO) {
        require(urlString.startsWith("https://",ignoreCase=true)) { "Yalnızca HTTPS adresleri kaydedilebilir" }
        val url=URL(urlString)
        require(url.protocol=="https" && url.userInfo==null) { "Geçersiz HTTPS adresi" }
        val conn=url.openConnection() as HttpsURLConnection
        conn.connectTimeout=10000;conn.readTimeout=15000;conn.instanceFollowRedirects=false
        try {
            require(conn.responseCode==200) { "HTTP yanıtı: ${conn.responseCode}" }
            val type=conn.contentType.orEmpty().lowercase()
            require(type.startsWith("text/html") || type.startsWith("text/plain")) { "Şimdilik yalnızca HTML/metin destekleniyor" }
            val bytes=conn.inputStream.use { it.readNBytes(1_000_001) }
            require(bytes.size<=1_000_000) { "Sayfa 1 MB sınırını aşıyor" }
            val name=MessageDigest.getInstance("SHA-256").digest(urlString.toByteArray())
                .joinToString("") { "%02x".format(it) } + ".html"
            File(root,name).writeBytes(bytes)
            val page=OfflinePage(urlString,name,bytes.size,System.currentTimeMillis())
            synchronized(this@OfflineVault) {
                val all=list().filter { it.url!=urlString }+page
                val arr=JSONArray()
                all.takeLast(30).forEach { p ->
                    arr.put(JSONObject().put("url",p.url).put("filename",p.filename).put("size",p.size).put("savedAt",p.savedAt))
                }
                prefs.edit().putString("pages",arr.toString()).apply()
            }
            page
        } finally { conn.disconnect() }
    }
    suspend fun content(page:OfflinePage):String=withContext(Dispatchers.IO) {
        File(root,page.filename).readText(Charsets.UTF_8)
    }
}
