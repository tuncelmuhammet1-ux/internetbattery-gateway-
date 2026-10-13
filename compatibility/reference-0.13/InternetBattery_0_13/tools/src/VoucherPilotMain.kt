package com.internetbattery.gateway

import com.internetbattery.capacity.*
import com.internetbattery.roaming.VoucherSessionAuthorizer
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.file.Path
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.concurrent.CountDownLatch

/** Independent JVM gateway pilot with OFFLINE signed-voucher authorization.
 * Do not expose the unauthenticated SOCKS5 handshake to untrusted networks:
 * usernames/passwords are not TLS-encrypted at the SOCKS5 protocol layer.
 * The issuer below only creates LAB DEMO CREDIT — not an operator/data plan. */
object VoucherPilotMain {
    @JvmStatic fun main(args: Array<String>) {
        require(args.isNotEmpty()) { "Usage: issue-demo <gateway ID> <holder ID> <bytes> | serve-voucher <owned IPv4> <port> <gateway ID> <issuer public key b64url> <journal path>" }
        when(args[0]) {
            "issue-demo" -> {
                require(args.size==4)
                val gw=args[1];val holder=args[2];val bytes=args[3].toLong()
                require(bytes in 1..1_000_000)
                val dir=java.nio.file.Files.createTempDirectory("ib-issuer-demo-")
                val issuerKey=KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
                val ledger=CapacityLedger(dir.resolve("issuer.journal"),ByteArray(32).also{SecureRandom().nextBytes(it)},emptyList())
                ledger.seedTestQuota(holder,bytes) // DEMO ONLY: trusted issuer did NOT confirm any actual service.
                val voucher=VoucherIssuer(ledger,issuerKey.private).issue(holder,"demo${System.currentTimeMillis()}",gw,bytes,30)
                    ?: error("Could not issue lab demo voucher")
                val pub=Base64.getUrlEncoder().withoutPadding().encodeToString(issuerKey.public.encoded)
                val credential=VoucherCredential.encode(voucher)
                println("DEMO_ONLY: No paid data and no provider entitlement. Do not publish this bearer token.")
                println("GATEWAY_ID=$gw")
                println("ISSUER_PUBLIC_KEY=$pub")
                println("CLIENT_USERNAME=$holder")
                println("CLIENT_VOUCHER=$credential")
                println("LAB_QUOTA_BYTES=$bytes")
            }
            "serve-voucher" -> {
                require(args.size==6)
                val ipLiteral=args[1]
                require(ipLiteral.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")))
                val ip=InetAddress.getByName(ipLiteral)
                require(ip is Inet4Address && !ip.isAnyLocalAddress && ip.hostAddress==ipLiteral)
                val port=args[2].toInt(); require(port in 1024..65535)
                val gw=args[3]
                val rawPub=Base64.getUrlDecoder().decode(args[4])
                val pub=KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(rawPub))
                val journal=Path.of(args[5])
                val keyString=System.getenv("IB_GATEWAY_JOURNAL_KEY") ?: error("IB_GATEWAY_JOURNAL_KEY (base64url of 32 random bytes) required")
                val key=Base64.getUrlDecoder().decode(keyString)
                require(key.size==32)
                // An actual deployment provisions this key via Android Keystore or a managed secret store.
                val verifier=LocalGatewayVoucherVerifier(gw,pub,journal,key)
                val testing=ip.isLoopbackAddress && System.getenv("IB_LAB_ALLOW_PRIVATE_TARGETS")=="yes"
                Socks5Gateway(ip,port,password="STATIC-PASSWORD-DISABLED-VOUCHER-ONLY-12345",
                    sessionAuthorizer=VoucherSessionAuthorizer(verifier),
                    allowPrivateDestinations=testing,
                    onLog={ println("GATEWAY: $it") },
                    onSessionCompleted={ println("TRAFFIC: holder=${it.authenticatedUsername} up=${it.upstreamBytes} down=${it.downstreamBytes}") }).use { gateway ->
                    check(gateway.start())
                    println("LISTENING_VOUCHER $ipLiteral:$port gateway=$gw policy=${if(testing) "LOOPBACK_LAB_ONLY" else "PUBLIC_TARGETS_ONLY"}")
                    Runtime.getRuntime().addShutdownHook(Thread { gateway.close() })
                    CountDownLatch(1).await()
                }
            }
            else -> error("Unknown command; see usage")
        }
    }
}
