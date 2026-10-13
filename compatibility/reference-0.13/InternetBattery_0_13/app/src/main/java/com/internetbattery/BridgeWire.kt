package com.internetbattery

import java.io.DataInputStream
import java.net.InetAddress

/** Pure Kotlin SOCKS framing: safe to test on the JVM without Android. */
object BridgeWire {
    data class UdpTarget(val address:String,val port:Int,val data:ByteArray)
    fun hexDecode(hex:String):ByteArray {
        require(hex.matches(Regex("[a-fA-F0-9]{64}"))) { "64 hex karakter anahtar gerekli" }
        return ByteArray(hex.length/2) { i -> hex.substring(2*i,2*i+2).toInt(16).toByte() }
    }
    fun reply(code:Int,bindPort:Int=0):ByteArray {
        require(code in 0..255 && bindPort in 0..65535)
        return byteArrayOf(5,code.toByte(),0,1,127,0,0,1,(bindPort ushr 8).toByte(),bindPort.toByte())
    }
    fun readTarget(input:DataInputStream):String? {
        return when(input.readUnsignedByte()) {
            1 -> InetAddress.getByAddress(ByteArray(4).also(input::readFully)).hostAddress
            4 -> InetAddress.getByAddress(ByteArray(16).also(input::readFully)).hostAddress
            3 -> {
                val n=input.readUnsignedByte()
                if(n !in 1..253)return null
                ByteArray(n).also(input::readFully).toString(Charsets.UTF_8)
            }
            else -> null
        }
    }
    fun parseUdp(data:ByteArray):UdpTarget? {
        if(data.size<11 || data[0]!=0.toByte() || data[1]!=0.toByte() || data[2]!=0.toByte())return null
        val t=data[3].toInt() and 255
        val sz=when(t){1->4;4->16;else->return null}
        if(data.size<4+sz+3)return null
        val host=InetAddress.getByAddress(data.copyOfRange(4,4+sz)).hostAddress
        val port=((data[4+sz].toInt() and 255) shl 8) or (data[5+sz].toInt() and 255)
        return UdpTarget(host,port,data.copyOfRange(6+sz,data.size))
    }
    fun udpReply(host:String,port:Int,packet:ByteArray):ByteArray {
        require(port in 1..65535)
        val address=InetAddress.getByName(host).address
        require(address.size==4||address.size==16)
        return byteArrayOf(0,0,0,if(address.size==4)1 else 4) + address +
            byteArrayOf((port ushr 8).toByte(),port.toByte()) + packet
    }
}
