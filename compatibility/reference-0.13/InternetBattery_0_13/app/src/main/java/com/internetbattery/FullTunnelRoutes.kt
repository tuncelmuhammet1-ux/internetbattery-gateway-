package com.internetbattery

/** Single source of truth for the VPN and hev tun2socks interface addresses.
 * The gateway itself is still reached over the IPv4 Wi-Fi Direct link.
 * Defining routes is NOT evidence of working IPv6 connectivity; end-to-end
 * IPv6 transfer requires a routed upstream gateway and device tests. */
object FullTunnelRoutes {
    const val CLIENT_IPV4 = "10.7.0.2"
    const val CLIENT_IPV6 = "fd72:1b:07::2" // private IPv6 TUN address
    const val IPV4_CIDR = 32
    const val IPV6_CIDR = 128
    const val ROUTE_IPV4 = "0.0.0.0"
    const val ROUTE_IPV6 = "::"
    const val IPV4_DEFAULT_PREFIX = 0
    const val IPV6_DEFAULT_PREFIX = 0
    const val DNS_IPV4 = "1.1.1.1"
    const val DNS_IPV6 = "2606:4700:4700::1111"
}
