package eu.opencloud.android.next.core.sync

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.StatFs

fun interface NetworkStatus {
    fun isConnected(): Boolean
}

fun interface StorageSpaceProvider {
    fun availableBytes(): Long
}

class AndroidNetworkStatus(
    context: Context,
) : NetworkStatus {
    private val connectivity = context.applicationContext.getSystemService(ConnectivityManager::class.java)

    override fun isConnected(): Boolean =
        supportsServerTraffic(connectivity.getNetworkCapabilities(connectivity.activeNetwork)) ||
            connectivity.allNetworks.any { supportsServerTraffic(connectivity.getNetworkCapabilities(it)) }
}

internal fun supportsServerTraffic(capabilities: NetworkCapabilities?): Boolean =
    capabilities != null &&
        (
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) ||
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) ||
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        )

class AndroidStorageSpaceProvider(
    context: Context,
) : StorageSpaceProvider {
    private val directory = context.applicationContext.filesDir

    override fun availableBytes(): Long = StatFs(directory.absolutePath).availableBytes
}
