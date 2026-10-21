package eu.opencloud.android.next

import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.network.FavoriteSnapshotClient
import eu.opencloud.android.next.core.network.LibreGraphSpacesClient
import eu.opencloud.android.next.core.network.OcsSharingClient
import eu.opencloud.android.next.core.network.OpenCloudApi
import eu.opencloud.android.next.core.network.RemoteDiscoveryClient
import okhttp3.Credentials
import okhttp3.Dns
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.InetAddress
import java.util.concurrent.TimeUnit

/** Opt-in use of the existing debug login, never credential values in test output or persistent state. */
class DevelopmentContractProbeTest {
    @Test fun readServerContracts() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue(args.getString("useDevelopmentLogin") == "true" && BuildConfig.DEBUG)
        val host = args.getString("diagnosticHost")
        assumeTrue(BuildConfig.DEV_SERVER_URL.isNotBlank() && BuildConfig.DEV_SERVER_PASSWORD.isNotBlank())
        val url = BuildConfig.DEV_SERVER_URL.toHttpUrl()
        assumeTrue(url.scheme == "https" && url.host == host)
        val client =
            OkHttpClient
                .Builder()
                .callTimeout(20, TimeUnit.SECONDS)
                .followRedirects(false)
                .followSslRedirects(false)
                .dns(
                    object : Dns {
                        override fun lookup(hostname: String): List<InetAddress> {
                            val ip = args.getString("diagnosticIp")
                            return if (hostname == host &&
                                ip != null
                            ) {
                                listOf(InetAddress.getByName(ip))
                            } else {
                                Dns.SYSTEM.lookup(hostname)
                            }
                        }
                    },
                ).addInterceptor { chain ->
                    val response = chain.proceed(chain.request())
                    Log.i(TAG, "${chain.request().method} HTTP ${response.code}")
                    response
                }.build()
        val authorization = Credentials.basic(BuildConfig.DEV_SERVER_USERNAME, BuildConfig.DEV_SERVER_PASSWORD)
        try {
            val server = url.toString().trimEnd('/')
            val capabilities = OpenCloudApi(client).capabilities(server, authorization)
            val spaces =
                LibreGraphSpacesClient(client).listSpaces(server, authorization).filterNot {
                    it.deleted ||
                        it.disabled
                }
            val roots = spaces.associate { it.id to it.rootWebDavUrl }
            Log.i(TAG, "spaces=${roots.size}")
            val favorites =
                FavoriteSnapshotClient(
                    client,
                ).locations(requireNotNull(capabilities.remoteSearchUrl), authorization, roots)
            Log.i(TAG, "favorites=${favorites.values.sumOf { it.size }}")
            roots.values.take(1).forEach { root ->
                val files = RemoteDiscoveryClient(client).folder(root, "/", authorization)
                files.filterNot { it.folder }.take(1).forEach { file ->
                    OcsSharingClient(client).listShares(server, authorization, resourceId = file.id)
                    Log.i(TAG, "resource share reference accepted")
                }
            }
        } catch (cancelled: java.util.concurrent.CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            Log.i(TAG, "probe failed: ${failure.javaClass.simpleName}")
        }
    }

    private companion object {
        const val TAG = "OpenCloudDevelopmentProbe"
    }
}
