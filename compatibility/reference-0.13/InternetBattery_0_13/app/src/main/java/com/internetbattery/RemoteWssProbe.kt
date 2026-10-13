package com.internetbattery

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import java.net.InetAddress
import java.security.SecureRandom
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/**
 * Authenticated WSS preflight WITHOUT enabling the VPN.
 * Success is never reported as an actual VPN or credit redemption success.
 */
object RemoteWssProbe {
    suspend fun run(context:Context,url:String,id:String,keyHex:String,voucher:String=""):String=withContext(Dispatchers.IO) {
        WssCredentials.validateAddress(url)
        val key=WssCredentials.hexKey(keyHex)
        WssCredentials.validateDeviceId(id)
        val voucherPreview=if(voucher.isNotBlank()) Ib1VoucherInput.decode(voucher,id) else null
        var checkedBalance:Long?=null
        val cm=context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val underlay=cm.activeNetwork?:error("Aktif ağ bağlantısı bulunamadı")
        val capabilities=cm.getNetworkCapabilities(underlay)?:error("Ağın özellikleri okunamıyor")
        require(!capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            "Ön test için mevcut VPN bağlantısını kapat"
        }
        val nonce=ByteArray(16).also { SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        val h=WssCredentials.authenticate(id,key,System.currentTimeMillis(),nonce)
        val req=Request.Builder().url(url).apply {
            h.forEach { (name,value)->header(name,value) }
            if(voucherPreview!=null)header("x-ib-voucher",voucher)
        }.build()
        val client=OkHttpClient.Builder()
            .socketFactory(underlay.socketFactory)
            .dns(object:Dns {
                override fun lookup(hostname:String):List<InetAddress> =
                    underlay.getAllByName(hostname).toList()
            })
            .connectTimeout(9,TimeUnit.SECONDS)
            .readTimeout(0,TimeUnit.MILLISECONDS)
            .build()
        val outcome=CompletableFuture<String>()
        val started=System.nanoTime()
        val ws=client.newWebSocket(req,object:WebSocketListener() {
            override fun onOpen(webSocket:WebSocket,response:Response) {
                if(voucherPreview!=null) webSocket.send(JSONObject().put("op","balance").toString())
                else webSocket.send(JSONObject().put("op","dns").put("host","example.com").toString())
            }
            override fun onMessage(webSocket:WebSocket,text:String) {
                val json=runCatching { JSONObject(text) }.getOrNull()
                when(json?.optString("op")) {
                    "balance" -> {
                        val remaining=json.optLong("remaining",-1)
                        if(voucherPreview==null || json.optString("voucherId")!=voucherPreview.voucherId || remaining<=0) {
                            outcome.completeExceptionally(IllegalStateException("IB1 belgesi veya kullanılabilir bakiye doğrulanamadı"))
                        } else {
                            checkedBalance=remaining
                            webSocket.send(JSONObject().put("op","dns").put("host","example.com").toString())
                        }
                    }
                    "dns" -> {
                        val address=json.optString("address")
                        if(json.optString("host")=="example.com" &&
                            address.isNotBlank() && address.all { it.isDigit() || it=='.' || it==':' || it in 'a'..'f' || it in 'A'..'F' }) {
                            val millis=(System.nanoTime()-started)/1_000_000L
                            if(voucherPreview!=null && checkedBalance==null) {
                                outcome.completeExceptionally(IllegalStateException("IB1 kota onayı olmadan DNS yeterli değil"))
                            } else {
                                val info=if(checkedBalance!=null) " IB1 onaylı kalan hak: "+checkedBalance+" bayt." else ""
                                outcome.complete("Kimlik ve WSS DNS yanıtı doğrulandı ("+millis+" ms)."+info+" Bu VPN testi değildir.")
                            }
                        } else outcome.completeExceptionally(IllegalStateException("DNS doğrulama verisi geçersiz"))
                    }
                    "error","quota" -> outcome.completeExceptionally(
                        IllegalStateException("Gateway isteği reddetti: "+json.optString("error").ifBlank {json.optString("op")}))
                }
            }
            override fun onFailure(webSocket:WebSocket,t:Throwable,response:Response?) {
                val code=response?.code
                val msg=if(code==401) "Cihaz anahtarı/ID reddedildi (401)"
                    else if(code==403) "IB1 imzalı kullanım belgesi reddedildi (403)"
                    else if(code==429) "Bağlantı sayısı sınırı aşıldı (429)"
                    else "WSS bağlantısı açılamadı: "+t.javaClass.simpleName
                outcome.completeExceptionally(IllegalStateException(msg))
            }
            override fun onClosed(webSocket:WebSocket,code:Int,reason:String) {
                outcome.completeExceptionally(IllegalStateException("WSS erken kapandı: "+code))
            }
        })
        try { outcome.get(14,TimeUnit.SECONDS) }
        finally {
            ws.close(1000,"probe completed")
            client.dispatcher.executorService.shutdown()
            client.connectionPool.evictAll()
        }
    }
}
