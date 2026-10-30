package com.safenet.android.engine.dns

import android.net.VpnService
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException

class DnsResolver(
    private val vpnService: VpnService
) {

    enum class UpstreamProvider(
        val displayName: String,
        val primaryIpv4: String,
        val secondaryIpv4: String,
        val description: String
    ) {
        CLOUDFLARE_FAMILY(
            "Cloudflare 1.1.1.3 (Malware + Adult Block)",
            "1.1.1.3",
            "1.0.0.3",
            "Automated upstream adult content and malware blocking"
        ),
        QUAD9_SECURITY(
            "Quad9 9.9.9.9 (Malware + Phishing Block)",
            "9.9.9.9",
            "149.112.112.112",
            "High-privacy enterprise threat intelligence"
        ),
        CLEANBROWSING_FAMILY(
            "CleanBrowsing Family (Strict Filter)",
            "185.228.168.168",
            "185.228.169.168",
            "Enforces strict safe search, adult and proxy blocking"
        ),
        CUSTOM(
            "Custom DNS",
            "1.1.1.1",
            "8.8.8.8",
            "User-defined upstream resolver"
        )
    }

    @Volatile
    var currentProvider: UpstreamProvider = UpstreamProvider.CLOUDFLARE_FAMILY

    @Volatile
    var customPrimaryIp: String = "1.1.1.3"

    /**
     * Forwards an allowed DNS query to the trusted upstream resolver using a protected DatagramSocket.
     */
    fun forwardQuery(queryBytes: ByteArray): ByteArray? {
        val targetIp = if (currentProvider == UpstreamProvider.CUSTOM) {
            customPrimaryIp
        } else {
            currentProvider.primaryIpv4
        }

        var socket: DatagramSocket? = null
        try {
            socket = DatagramSocket()
            // CRITICAL: Protect socket from routing through VPN TUN to prevent loops
            val protected = vpnService.protect(socket)
            if (!protected) {
                // If protect fails, do not emit packet to prevent recursion loop
                return null
            }
            socket.soTimeout = 2500 // 2.5 second timeout

            val serverAddr = InetAddress.getByName(targetIp)
            val sendPacket = DatagramPacket(queryBytes, queryBytes.size, serverAddr, 53)
            socket.send(sendPacket)

            val receiveBuf = ByteArray(1500) // Standard MTU buffer
            val receivePacket = DatagramPacket(receiveBuf, receiveBuf.size)
            socket.receive(receivePacket)

            val result = ByteArray(receivePacket.length)
            System.arraycopy(receiveBuf, 0, result, 0, receivePacket.length)
            return result
        } catch (e: SocketTimeoutException) {
            // Upstream timeout, try fallback to secondary if standard provider
            return tryFallbackQuery(queryBytes)
        } catch (e: Exception) {
            return null
        } finally {
            socket?.close()
        }
    }

    private fun tryFallbackQuery(queryBytes: ByteArray): ByteArray? {
        val fallbackIp = currentProvider.secondaryIpv4
        var socket: DatagramSocket? = null
        return try {
            socket = DatagramSocket()
            if (!vpnService.protect(socket)) return null
            socket.soTimeout = 2000
            val serverAddr = InetAddress.getByName(fallbackIp)
            val sendPacket = DatagramPacket(queryBytes, queryBytes.size, serverAddr, 53)
            socket.send(sendPacket)

            val receiveBuf = ByteArray(1500)
            val receivePacket = DatagramPacket(receiveBuf, receiveBuf.size)
            socket.receive(receivePacket)

            val result = ByteArray(receivePacket.length)
            System.arraycopy(receiveBuf, 0, result, 0, receivePacket.length)
            result
        } catch (e: Exception) {
            null
        } finally {
            socket?.close()
        }
    }
}
