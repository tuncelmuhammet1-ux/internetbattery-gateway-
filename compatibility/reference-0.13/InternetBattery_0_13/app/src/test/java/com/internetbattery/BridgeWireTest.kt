package com.internetbattery
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.DataInputStream
class BridgeWireTest {
    @Test fun hexDecodeLength() {
        assertArrayEquals(ByteArray(32){0xab.toByte()}, BridgeWire.hexDecode("ab".repeat(32)))
        try { BridgeWire.hexDecode("abcd");fail("short key accepted") } catch(_:IllegalArgumentException){}
    }
    @Test fun connectReplyPort() {
        val a=BridgeWire.reply(0,12345)
        assertEquals(10,a.size)
        assertEquals(12345,((a[8].toInt() and 255) shl 8) or (a[9].toInt() and 255))
    }
    @Test fun targetIPv4() {
        assertEquals("8.8.8.8",BridgeWire.readTarget(DataInputStream(ByteArrayInputStream(byteArrayOf(1,8,8,8,8)))))
    }
    @Test fun domainTarget() {
        val d="example.com".toByteArray()
        assertEquals("example.com",BridgeWire.readTarget(DataInputStream(ByteArrayInputStream(byteArrayOf(3,d.size.toByte())+d))))
    }
    @Test fun udpFrameRoundTrip() {
        val p=BridgeWire.parseUdp(BridgeWire.udpReply("1.1.1.1",53,byteArrayOf(1,2,3)))
        assertNotNull(p)
        assertEquals("1.1.1.1",p!!.address)
        assertEquals(53,p.port)
        assertArrayEquals(byteArrayOf(1,2,3),p.data)
    }
    @Test fun brokenUdpRejected() {
        assertNull(BridgeWire.parseUdp(byteArrayOf(0,0,1,1,1,1,1,1,0,53,10)))
        assertNull(BridgeWire.parseUdp(byteArrayOf(0,0,0,3,1,1,1,1,0,53,10)))
    }
}
