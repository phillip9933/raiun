package eu.opencloud.android.next

import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.network.GraphShareTarget
import eu.opencloud.android.next.core.network.GuestPermissionsClient
import eu.opencloud.android.next.core.network.LibreGraphSpacesClient
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

/** Explicitly opted-in, read-only probe. Never retain transport failures or private metadata in output. */
class GuestServerReadinessProbeTest {
    @Test fun readGuestServerContracts() {
        val args = InstrumentationRegistry.getArguments()
        assumeTrue("Development probe is opt-in", args.getString("useDevelopmentLogin") == "true")
        assumeTrue("Debug configuration required", BuildConfig.DEBUG)
        assumeTrue("Diagnostic host required", args.getString("diagnosticHost") == HOST)
        assumeTrue("Dedicated debug login required", BuildConfig.DEV_SERVER_USERNAME == "chatgpt")
        assumeTrue("Debug configuration missing", BuildConfig.DEV_SERVER_URL.isNotBlank())
        assumeTrue("Debug configuration missing", BuildConfig.DEV_SERVER_PASSWORD.isNotBlank())
        probe {
            val origin = BuildConfig.DEV_SERVER_URL.toHttpUrl()
            check(origin.scheme == "https" && origin.host == HOST && origin.port == 443)
            check(
                origin.username.isEmpty() &&
                    origin.password.isEmpty() &&
                    origin.query == null &&
                    origin.fragment == null,
            )
            var currentCase = "capabilities"
            var requestCount = 0
            val overrideIp = args.getString("diagnosticIp")
            if (overrideIp != null) {
                check(overrideIp.matches(Regex("[0-9.]+|[0-9a-fA-F:]+")))
            }
            val client =
                OkHttpClient
                    .Builder()
                    .callTimeout(20, TimeUnit.SECONDS)
                    .followRedirects(false)
                    .followSslRedirects(false)
                    .retryOnConnectionFailure(false)
                    .dns(
                        object : Dns {
                            override fun lookup(hostname: String): List<InetAddress> {
                                check(hostname == HOST)
                                return overrideIp?.let { listOf(InetAddress.getByName(it)) }
                                    ?: Dns.SYSTEM.lookup(hostname)
                            }
                        },
                    ).addInterceptor { chain ->
                        val request = chain.request()
                        check(
                            request.url.scheme == origin.scheme &&
                                request.url.host == origin.host &&
                                request.url.port == origin.port,
                        )
                        check(request.method in setOf("GET", "PROPFIND") && ++requestCount <= 20)
                        chain.proceed(request).also { Log.i(TAG, "$currentCase HTTP ${it.code}") }
                    }.build()
            try {
                val server = origin.toString().trimEnd('/')
                val auth = Credentials.basic(BuildConfig.DEV_SERVER_USERNAME, BuildConfig.DEV_SERVER_PASSWORD)
                val capabilities = OpenCloudApi(client).capabilities(server, auth)
                check(capabilities.sharingEnabled && capabilities.guestLinksEnabled)
                Log.i(TAG, "capabilities sharing=true guest_links=true")
                currentCase = "spaces"
                val spaces =
                    LibreGraphSpacesClient(client).listSpaces(server, auth).filterNot {
                        it.disabled ||
                            it.deleted
                    }
                Log.i(TAG, "spaces count=${spaces.size}")
                val requestedDrive = args.getString("diagnosticDriveId")
                val space =
                    if (requestedDrive != null) {
                        spaces.single { it.id == requestedDrive }
                    } else {
                        spaces.singleOrNull { it.name == TEST_ROOT } ?: spaces.single { it.type == "personal" }
                    }
                currentCase = "dav_root"
                val dav = RemoteDiscoveryClient(client)
                val root = dav.folder(space.rootWebDavUrl, "/", auth)
                Log.i(TAG, "dav_root count=${root.size}")
                val requestedItem = args.getString("diagnosticItemId")
                val indexed =
                    if (requestedItem != null) {
                        // An explicitly selected target must already be present in this account's root listing.
                        root.single { it.id == requestedItem }
                    } else if (space.name == TEST_ROOT) {
                        root.firstOrNull() ?: error("Missing test resource")
                    } else {
                        root.single { it.folder && it.name == TEST_ROOT }
                    }
                if (indexed.folder) {
                    currentCase = "dav_folder"
                    val children = dav.folder(space.rootWebDavUrl, indexed.path, auth)
                    Log.i(TAG, "dav_folder count=${children.size}")
                }
                currentCase = "guest_permissions"
                // Match the production sender: Graph drive ID plus the opaque DAV resource ID, unmodified.
                val permissions =
                    GuestPermissionsClient(
                        client,
                    ).list(server, auth, GraphShareTarget(space.id, indexed.id))
                Log.i(TAG, "guest_permissions guests=${permissions.guests.size} roles=${permissions.roles.size}")
                Log.i(TAG, "readiness passed requests=$requestCount")
            } finally {
                client.dispatcher.executorService.shutdown()
                client.connectionPool.evictAll()
            }
        }
    }

    @Suppress("SwallowedException") // Network errors can contain URLs, credentials or server metadata.
    private fun probe(action: () -> Unit) {
        try {
            action()
        } catch (_: Exception) {
            throw AssertionError("Guest server readiness failed; inspect fixed probe case status only")
        }
    }

    private companion object {
        const val TAG = "RaiunGuestReadiness"
        const val HOST = "drive.rogers.ltd"
        const val TEST_ROOT = "Raiun Testing"
    }
}
