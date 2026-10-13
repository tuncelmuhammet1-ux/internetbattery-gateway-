package com.internetbattery

import android.net.Network
import android.net.VpnService
import android.util.Base64
import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import org.json.JSONObject
import java.io.DataInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import javax.net.SocketFactory

/**
 * Android loopback SOCKS5-to-WSS bridge. Prototype; remote gateway is TCP/80/443 and UDP/53 only.
 * Connection keys are supplied by the user; the server's master secret is never embedded in the APK.
 */
class WssSocksBridge(
    private val vpn: VpnService,
    private val underlay: Network,
    private val wssAddress: String,
    private val deviceId: String,
    keyHex: String,
    private val localPassword: String,
    private val onStatus: (String)->Unit,
    private val voucher:String=""
) : AutoCloseable {
    private val key = WssCredentials.hexKey(keyHex)
    private val alive=AtomicBoolean(true)
    private val active=ConcurrentHashMap.newKeySet<Socket>()
    private val udpSockets=ConcurrentHashMap.newKeySet<DatagramSocket>()
    private val executor=Executors.newCachedThreadPool()
    private val random=SecureRandom()
    private val server by lazy { java.net.ServerSocket(0,16,InetAddress.getByName("127.0.0.1")) }
    private val client=OkHttpClient.Builder()
        .dns(object : Dns { override fun lookup(hostname: String): List<InetAddress> = underlay.getAllByName(hostname).toList() })
        .socketFactory(ProtectedSocketFactory(vpn,underlay))
        .connectTimeout(9,TimeUnit.SECONDS)
        .pingInterval(20,TimeUnit.SECONDS)
        .readTimeout(0,TimeUnit.MILLISECONDS)
        .build()

    init {
        val uri=URI(wssAddress)
        require(uri.scheme=="wss" && !uri.host.isNullOrBlank() && uri.path=="/tunnel" &&
                uri.userInfo==null && uri.query==null && uri.fragment==null)
        require(Regex("[a-z0-9-]{3,40}").matches(deviceId))
        require(localPassword.length in 16..255)
        if(voucher.isNotBlank()) Ib1VoucherInput.decode(voucher,deviceId)
    }

    val port:Int get()=server.localPort

    fun start() {
        executor.execute {
            while(alive.get()) {
                val conn=try{server.accept()}catch(_:Exception){break}
                if(active.size>=20){conn.close();continue}
                active.add(conn)
                executor.execute{
                    try{handle(conn)}catch(e:Exception){onStatus("SOCKS bağlantı hatası: "+e.javaClass.simpleName)}
                    finally{active.remove(conn);runCatching{conn.close()}}
                }
            }
        }
    }

    private fun webSocket(listener:WebSocketListener):WebSocket {
        val nonce=ByteArray(16).also(random::nextBytes).joinToString(""){"%02x".format(it.toInt() and 255)}
        val signed=WssCredentials.authenticate(deviceId,key,System.currentTimeMillis(),nonce)
        val request=Request.Builder().url(wssAddress).apply {
            signed.forEach { (name,value)->header(name,value) }
            if(voucher.isNotBlank())header("x-ib-voucher",voucher)
        }.build()
        return client.newWebSocket(request,listener)
    }

    fun probe():Boolean {
        val done=CompletableFuture<Boolean>()
        val balanceConfirmed=AtomicBoolean(false)
        val preview=if(voucher.isNotBlank()) Ib1VoucherInput.decode(voucher,deviceId) else null
        val ws=webSocket(object:WebSocketListener(){
            override fun onOpen(w:WebSocket,r:Response){
                if(preview!=null) w.send(JSONObject().put("op","balance").toString())
                else w.send(JSONObject().put("op","dns").put("host","example.com").toString())
            }
            override fun onMessage(w:WebSocket,text:String){
                val result=runCatching{JSONObject(text)}.getOrNull()
                when(result?.optString("op")){
                    "balance"->{
                        if(preview!=null && result.optString("voucherId")==preview.voucherId &&
                            result.optLong("remaining",-1)>0) {
                            balanceConfirmed.set(true)
                            w.send(JSONObject().put("op","dns").put("host","example.com").toString())
                        } else done.complete(false)
                    }
                    "dns"->done.complete((preview==null||balanceConfirmed.get()) &&
                        result.optString("host")=="example.com" && result.optString("address").isNotBlank())
                    "error","quota"->done.complete(false)
                }
            }
            override fun onFailure(w:WebSocket,t:Throwable,r:Response?){done.complete(false)}
            override fun onClosed(w:WebSocket,c:Int,reason:String){done.complete(false)}
        })
        return try{done.get(12,TimeUnit.SECONDS)}catch(_:Exception){false}
        finally{ws.close(1000,"probe")}
    }

    private fun handle(sock:Socket) {
        sock.soTimeout=15000
        val input=DataInputStream(sock.getInputStream())
        val out=sock.getOutputStream()
        if(input.readUnsignedByte()!=5)return
        val count=input.readUnsignedByte()
        if(count !in 1..8)return
        val methods=ByteArray(count).also(input::readFully)
        if(!methods.contains(2.toByte())){out.write(byteArrayOf(5,0xff.toByte()));return}
        out.write(byteArrayOf(5,2))
        if(input.readUnsignedByte()!=1)return
        val n=input.readUnsignedByte();if(n !in 1..100)return
        val username=ByteArray(n).also(input::readFully).toString(Charsets.UTF_8)
        val plen=input.readUnsignedByte();if(plen !in 16..255)return
        val pwd=ByteArray(plen).also(input::readFully).toString(Charsets.UTF_8)
        val valid=username=="ib" && MessageDigest.isEqual(
            pwd.toByteArray(Charsets.UTF_8),localPassword.toByteArray(Charsets.UTF_8))
        out.write(byteArrayOf(1,if(valid)0 else 1))
        if(!valid||input.readUnsignedByte()!=5)return
        val cmd=input.readUnsignedByte()
        if(input.readUnsignedByte()!=0)return
        val host=BridgeWire.readTarget(input) ?: return
        val port=input.readUnsignedShort()
        when(cmd){
            1->tcp(sock,host,port)
            3->udp(sock)
            else->out.write(BridgeWire.reply(7))
        }
    }

    private fun tcp(sock:Socket,host:String,port:Int) {
        val out=sock.getOutputStream()
        if(port!=80&&port!=443){out.write(BridgeWire.reply(2));return}
        val connected=CompletableFuture<Boolean>()
        val lock=Any()
        val ws=webSocket(object:WebSocketListener(){
            override fun onOpen(w:WebSocket,r:Response) {
                w.send(JSONObject().put("op","connect").put("host",host).put("port",port).toString())
            }
            override fun onMessage(w:WebSocket,text:String) {
                when(runCatching{JSONObject(text).optString("op")}.getOrDefault("")){
                    "connected"->connected.complete(true)
                    "error","quota"->{connected.complete(false);runCatching{sock.close()}}
                    "end"->runCatching{sock.shutdownOutput()}
                }
            }
            override fun onMessage(w:WebSocket,bytes:ByteString) {
                if(connected.getNow(false))try{
                    synchronized(lock){out.write(bytes.toByteArray());out.flush()}
                }catch(_:Exception){runCatching{sock.close()}}
            }
            override fun onFailure(w:WebSocket,t:Throwable,r:Response?) {
                connected.complete(false);runCatching{sock.close()}
            }
            override fun onClosed(w:WebSocket,c:Int,reason:String) {
                connected.complete(false);runCatching{sock.close()}
            }
        })
        try{
            if(!connected.get(12,TimeUnit.SECONDS)){out.write(BridgeWire.reply(1));return}
            out.write(BridgeWire.reply(0))
            sock.soTimeout=0
            val buf=ByteArray(32768);val input=sock.getInputStream()
            while(alive.get()&&!sock.isClosed){
                val n=input.read(buf);if(n<0)break
                if(n>0&&!ws.send(ByteString.of(*buf.copyOf(n))))break
                if(ws.queueSize()>1_048_576)break
            }
        }catch(_:Exception){}
        finally{ws.close(1000,"client_closed")}
    }

    private fun udp(sock:Socket) {
        val d=DatagramSocket(0,InetAddress.getByName("127.0.0.1"))
        udpSockets.add(d)
        val pending=ConcurrentHashMap<Int,Pair<InetSocketAddress,BridgeWire.UdpTarget>>()
        val rid=AtomicInteger()
        val ready=CompletableFuture<Boolean>()
        val ws=webSocket(object:WebSocketListener(){
            override fun onOpen(w:WebSocket,r:Response){ready.complete(true)}
            override fun onMessage(w:WebSocket,text:String){
                try{
                    val msg=JSONObject(text)
                    when(msg.optString("op")){
                        "udp53_reply"->{
                            val item=pending.remove(msg.getInt("rid")) ?:return
                            val payload=Base64.decode(msg.getString("data"),Base64.DEFAULT)
                            val packet=BridgeWire.udpReply(item.second.address,53,payload)
                            d.send(DatagramPacket(packet,packet.size,item.first))
                        }
                        "quota","error"->onStatus("Uzak DNS engeli: "+msg.optString("op"))
                    }
                }catch(_:Exception){}
            }
            override fun onFailure(w:WebSocket,t:Throwable,r:Response?){ready.complete(false);d.close()}
            override fun onClosed(w:WebSocket,c:Int,reason:String){d.close()}
        })
        try {
            if(!ready.get(12,TimeUnit.SECONDS)){sock.getOutputStream().write(BridgeWire.reply(1));return}
            sock.getOutputStream().write(BridgeWire.reply(0,d.localPort))
            sock.soTimeout=0
            executor.execute {
                val buf=ByteArray(8192)
                while(alive.get()&&!d.isClosed)try{
                    val pkt=DatagramPacket(buf,buf.size)
                    d.receive(pkt)
                    if(!pkt.address.isLoopbackAddress)continue
                    val t=BridgeWire.parseUdp(buf.copyOf(pkt.length)) ?:continue
                    if(t.port!=53||t.data.isEmpty()||t.data.size>1000)continue
                    // Only literal IPs are supported by the UDP gateway lab.
                    if(java.net.InetAddress.getByName(t.address).isAnyLocalAddress)continue
                    val next=rid.incrementAndGet()
                    pending[next]=InetSocketAddress(pkt.address,pkt.port) to t
                    val frame=JSONObject().put("op","udp53").put("host",t.address)
                        .put("port",53).put("rid",next)
                        .put("data",Base64.encodeToString(t.data,Base64.NO_WRAP))
                    if(!ws.send(frame.toString())){pending.remove(next);break}
                    if(pending.size>64)pending.clear()
                }catch(_:Exception){break}
            }
            while(alive.get()&&sock.getInputStream().read()!=-1){}
        }catch(_:Exception){}
        finally{d.close();udpSockets.remove(d);ws.close(1000,"udp_closed")}
    }

    override fun close() {
        if(!alive.compareAndSet(true,false))return
        runCatching{server.close()}
        active.forEach{runCatching{it.close()}}
        udpSockets.forEach{runCatching{it.close()}}
        client.dispatcher.executorService.shutdownNow()
        client.connectionPool.evictAll()
        executor.shutdownNow()
    }

    private class ProtectedSocketFactory(private val vpn:VpnService,private val network:Network):SocketFactory() {
        override fun createSocket():Socket {
            val s=network.socketFactory.createSocket()
            check(vpn.protect(s)){"VpnService.protect failed"}
            return s
        }
        private fun connect(addr:SocketAddress,bind:SocketAddress?=null):Socket {
            val s=createSocket()
            try{if(bind!=null)s.bind(bind);s.connect(addr,9000);return s}
            catch(e:Exception){s.close();throw e}
        }
        override fun createSocket(host:String,port:Int):Socket=connect(InetSocketAddress(host,port))
        override fun createSocket(host:InetAddress,port:Int):Socket=connect(InetSocketAddress(host,port))
        override fun createSocket(host:String,port:Int,localHost:InetAddress,localPort:Int):Socket=
            connect(InetSocketAddress(host,port),InetSocketAddress(localHost,localPort))
        override fun createSocket(address:InetAddress,port:Int,localAddress:InetAddress,localPort:Int):Socket=
            connect(InetSocketAddress(address,port),InetSocketAddress(localAddress,localPort))
    }
}
