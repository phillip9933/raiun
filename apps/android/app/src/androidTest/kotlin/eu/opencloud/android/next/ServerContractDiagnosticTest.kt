package eu.opencloud.android.next

import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.model.auth.OidcConfiguration
import eu.opencloud.android.next.core.network.DavOperationClient
import eu.opencloud.android.next.core.network.FavoriteSnapshotClient
import eu.opencloud.android.next.core.network.OcsSharingClient
import eu.opencloud.android.next.core.network.OpenCloudApi
import eu.opencloud.android.next.core.network.RemoteDiscoveryClient
import eu.opencloud.android.next.core.security.AccountSessions
import eu.opencloud.android.next.core.security.KeystoreCredentialStore
import kotlinx.coroutines.runBlocking
import okhttp3.Dns
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.net.InetAddress
import java.util.concurrent.TimeUnit

/** Opt-in, read-only protocol probe. Never logs account identities, paths, bodies or credentials. */
class ServerContractDiagnosticTest {
    @Test fun inspectReadOnlyContracts() =
        runBlocking {
            val args = InstrumentationRegistry.getArguments()
            val host = args.getString("diagnosticHost")
            assumeTrue(host != null)
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val store = FileBrowserStore(FileBrowserDatabase.create(context))
            val credentials = KeystoreCredentialStore(context)
            val account =
                store.activeAccounts().firstOrNull {
                    it.serverUrl.toHttpUrl().host == host &&
                        (
                            credentials.readClientRegistration("account:${it.id}") != null ||
                                (it.authenticationType == "BASIC" && credentials.readBasicPassword(it.id) != null)
                        )
                }
            assumeTrue("No usable authenticated account on this emulator", account != null)
            requireNotNull(account)
            val binding = credentials.readClientRegistration("account:${account.id}")
            val ip = args.getString("diagnosticIp")
            val client =
                OkHttpClient
                    .Builder()
                    .callTimeout(30, TimeUnit.SECONDS)
                    .followRedirects(false)
                    .followSslRedirects(false)
                    .dns(
                        object : Dns {
                            override fun lookup(name: String): List<InetAddress> =
                                if (ip != null && name in setOf(host, binding?.issuer?.toHttpUrl()?.host)) {
                                    listOf(InetAddress.getByName(ip))
                                } else {
                                    Dns.SYSTEM.lookup(name)
                                }
                        },
                    ).addInterceptor { chain ->
                        val response = chain.proceed(chain.request())
                        if (chain.request().method != "POST") {
                            val range = response.header("Content-Range")
                            Log.i(
                                TAG,
                                "method=${chain.request().method} status=${response.code} " +
                                    "range=${range?.takeIf { it.matches(Regex("[A-Za-z0-9 */-]+")) }}",
                            )
                        }
                        response
                    }.build()
            val authorization =
                if (account.authenticationType == "BASIC") {
                    okhttp3.Credentials.basic(
                        credentials.readBasicUsername(account.id) ?: account.userId,
                        requireNotNull(credentials.readBasicPassword(account.id)),
                    )
                } else {
                    requireNotNull(binding)
                    val tokens =
                        AccountSessions.get(context).tokens(account.id) { current ->
                            OpenCloudApi(client).refresh(
                                OidcConfiguration(
                                    binding.issuer,
                                    binding.authorizationEndpoint,
                                    binding.tokenEndpoint,
                                    null,
                                    binding.clientId,
                                    emptyList(),
                                ),
                                requireNotNull(current.refreshToken),
                            )
                        }
                    "${tokens.tokenType} ${tokens.accessToken}"
                }
            val spaces = store.spaces(account.id).filterNot { it.isDeleted || it.isDisabled }
            val roots = spaces.associate { it.driveId to requireNotNull(it.rootWebDavUrl) }
            probe("favorites") {
                val result =
                    FavoriteSnapshotClient(
                        client,
                    ).locations(requireNotNull(account.remoteSearchUrl), authorization, roots)
                Log.i(TAG, "favoriteCount=${result.values.sumOf { it.size }}")
            }
            probe("shares") { OcsSharingClient(client).listShares(account.serverUrl, authorization) }
            roots.values.take(1).forEach { root ->
                probe("folder") {
                    val resources = RemoteDiscoveryClient(client).folder(root, "/", authorization)
                    Log.i(
                        TAG,
                        "resourceCount=${resources.size} quotedEtags=${resources.count {
                            it.eTag?.startsWith(
                                '"',
                            ) == true
                        }}",
                    )
                    resources.filterNot { it.folder }.take(3).forEach { resource ->
                        probe("stat") {
                            val url =
                                root
                                    .toHttpUrl()
                                    .newBuilder()
                                    .addPathSegment(resource.name)
                                    .build()
                                    .toString()
                            val stat = requireNotNull(DavOperationClient(client).stat(url, authorization))
                            Log.i(
                                TAG,
                                "etagMatches=${stat.eTag == resource.eTag} sizeMatches=${stat.size == resource.size}",
                            )
                        }
                        probe("resourceShares") {
                            OcsSharingClient(
                                client,
                            ).listShares(account.serverUrl, authorization, resourceId = resource.id)
                        }
                    }
                }
            }
        }

    private fun probe(
        stage: String,
        block: () -> Unit,
    ) {
        try {
            block()
            Log.i(TAG, "$stage=ok")
        } catch (failure: Exception) {
            Log.i(TAG, "$stage=${failure.javaClass.simpleName}")
        }
    }

    private companion object {
        const val TAG = "OpenCloudContractProbe"
    }
}
