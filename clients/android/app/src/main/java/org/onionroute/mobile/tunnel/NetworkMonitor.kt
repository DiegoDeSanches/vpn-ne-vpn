package org.onionroute.mobile.tunnel

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest

class NetworkMonitor(
    private val connectivity: ConnectivityManager,
    private val listener: Listener,
) : AutoCloseable {
    interface Listener {
        fun onUsableNetwork(network: Network, expensive: Boolean, constrained: Boolean)
        fun onCaptiveNetwork(network: Network)
        fun onNoNetwork()
    }

    private var active: Network? = null
    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            active = network
            if (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL) ||
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            ) {
                listener.onCaptiveNetwork(network)
                return
            }
            listener.onUsableNetwork(
                network,
                expensive = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
                constrained = !capabilities.hasCapability(
                    NetworkCapabilities.NET_CAPABILITY_NOT_CONGESTED,
                ),
            )
        }

        override fun onLost(network: Network) {
            if (active == network) {
                active = null
                listener.onNoNetwork()
            }
        }
    }

    fun start() {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        connectivity.registerNetworkCallback(request, callback)
    }

    override fun close() {
        connectivity.unregisterNetworkCallback(callback)
    }
}

