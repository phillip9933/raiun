package eu.opencloud.android.next.feature.search

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.VaultExclusion
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.RemoteSearchResource
import eu.opencloud.android.next.core.sync.RoomSearchRepository
import eu.opencloud.android.next.core.sync.SearchRepositoryResult
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.take
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class RoomSearchRepositoryTest {
    @Test fun `local results emit immediately before debounced remote results`() =
        runTest {
            var remoteCalls = 0
            val repository =
                repository(
                    account = account(remoteSearchUrl = "https://cloud.test/remote.php/dav/spaces/"),
                    remoteSearch = { _, _ ->
                        remoteCalls++
                        listOf(remote("remote"))
                    },
                )
            val emissions = mutableListOf<SearchRepositoryResult>()
            val job = launch { repository.search("account", "plan").take(3).toList(emissions) }

            runCurrent()
            assertEquals(2, emissions.size)
            assertFalse(emissions.first().remoteSupported)
            assertTrue(emissions.last().remoteLoading)
            assertEquals(listOf("local"), emissions.first().resources.map(ResourceEntity::remoteId))
            assertEquals(0, remoteCalls)

            advanceTimeBy(350)
            runCurrent()
            job.join()
            assertEquals(1, remoteCalls)
            assertEquals(listOf("local", "remote"), emissions.last().resources.map(ResourceEntity::remoteId))
        }

    @Test fun `unsupported capability never invokes remote search`() =
        runTest {
            var remoteCalls = 0
            val result =
                repository(
                    account = account(remoteSearchUrl = null),
                    remoteSearch = { _, _ ->
                        remoteCalls++
                        emptyList()
                    },
                ).search("account", "plan").toList().last()

            assertFalse(result.remoteSupported)
            assertEquals(0, remoteCalls)
            assertEquals(listOf("local"), result.resources.map(ResourceEntity::remoteId))
        }

    @Test fun `remote result sentinel detects truncation without turning it into a server error`() =
        runTest {
            val results = (1..51).map { remote("remote-$it") }
            val repository =
                repository(
                    account = account(remoteSearchUrl = "https://cloud.test/remote.php/dav/spaces/"),
                    remoteSearch = { _, _ -> results },
                )

            val result = repository.search("account", "plan").toList().last()

            assertTrue(result.remoteResultsCapped)
            assertEquals(null, result.remoteError)
            assertEquals(51, result.resources.size) // 50 remote results plus one local result.
            assertTrue(result.resources.any { it.remoteId == "remote-50" })
        }

    @Test fun `exactly the visible remote result limit is not marked as truncated`() =
        runTest {
            val repository =
                repository(
                    account = account(remoteSearchUrl = "https://cloud.test/remote.php/dav/spaces/"),
                    remoteSearch = { _, _ -> (1..50).map { remote("remote-$it") } },
                )

            val result = repository.search("account", "plan").toList().last()

            assertFalse(result.remoteResultsCapped)
        }

    @Test fun `cancelling obsolete query prevents remote invocation`() =
        runTest {
            var remoteCalls = 0
            val repository =
                repository(
                    account = account(remoteSearchUrl = "https://cloud.test/remote.php/dav/spaces/"),
                    remoteSearch = { _, _ ->
                        remoteCalls++
                        emptyList()
                    },
                )
            val job = launch { repository.search("account", "old query").toList() }
            runCurrent()
            job.cancel()
            advanceTimeBy(350)
            runCurrent()

            assertEquals(0, remoteCalls)
        }

    @Test fun searchResultsTrackLiveLiteralVaultExclusions() =
        runTest {
            val exclusions = MutableStateFlow(emptyList<VaultExclusion>())
            val repository =
                repository(
                    account = account(remoteSearchUrl = "https://cloud.test/remote.php/dav/spaces/"),
                    remoteSearch = { _, _ ->
                        listOf(
                            remote("inside", path = "/Secure/sub/file", spaceId = "space"),
                            remote("prefix-neighbor", path = "/Secureish/file", spaceId = "space"),
                            remote("other-drive", path = "/OtherDenied/file", spaceId = "other-space"),
                        )
                    },
                    remoteDelayMillis = 0,
                    exclusionFlow = { exclusions },
                    localPath = "/Secure/local",
                )
            var latest = SearchRepositoryResult(emptyList(), remoteSupported = false)
            val job = launch { repository.search("account", "file").collect { latest = it } }

            runCurrent()
            assertEquals(
                setOf("inside", "prefix-neighbor", "other-drive", "local"),
                latest.resources.map { it.remoteId }.toSet(),
            )
            exclusions.value =
                listOf(
                    VaultExclusion("account", "space", "/Secure"),
                    VaultExclusion("account", "other-space", "/OtherDenied"),
                )
            runCurrent()
            assertEquals(setOf("prefix-neighbor"), latest.resources.map { it.remoteId }.toSet())
            exclusions.value = listOf(VaultExclusion("account", "other-space", "/OtherDenied"))
            runCurrent()
            assertEquals(
                setOf("inside", "prefix-neighbor", "local"),
                latest.resources.map { it.remoteId }.toSet(),
            )
            exclusions.value = emptyList()
            runCurrent()
            assertEquals(
                setOf("inside", "prefix-neighbor", "other-drive", "local"),
                latest.resources.map { it.remoteId }.toSet(),
            )
            job.cancel()
        }

    @Test fun excludedResultsDoNotClearTheServerCapSignal() =
        runTest {
            val repository =
                repository(
                    account = account(remoteSearchUrl = "https://cloud.test/remote.php/dav/spaces/"),
                    remoteSearch = { _, _ ->
                        (1..51).map { index ->
                            val path = if (index <= 50) "/Secret/file-" + index else "/Visible/file"
                            remote("remote-" + index, path = path)
                        }
                    },
                    remoteDelayMillis = 0,
                    exclusionFlow = {
                        flowOf(listOf(VaultExclusion("account", "space", "/Secret")))
                    },
                )

            val result = repository.search("account", "file").toList().last()

            assertTrue(result.remoteResultsCapped)
            assertEquals(listOf("local"), result.resources.map { it.remoteId })
        }

    private fun repository(
        account: AccountEntity,
        remoteSearch: suspend (AccountEntity, String) -> List<RemoteSearchResource>,
        remoteDelayMillis: Long = 350,
        exclusionFlow: (String) -> kotlinx.coroutines.flow.Flow<List<VaultExclusion>> = { flowOf(emptyList()) },
        localPath: String = "/Plan.pdf",
    ) = RoomSearchRepository(
        localSearch = { _, _ -> flowOf(listOf(localResource(localPath))) },
        accountProvider = { account },
        remoteSearch = remoteSearch,
        remoteDelayMillis = remoteDelayMillis,
        exclusionFlow = exclusionFlow,
    )

    private fun account(remoteSearchUrl: String?) =
        AccountEntity(
            "account",
            "https://cloud.test",
            "alice",
            "Alice",
            "BASIC",
            false,
            remoteSearchUrl = remoteSearchUrl,
        )

    private fun localResource(path: String = "/Plan.pdf") =
        ResourceEntity(
            "account",
            "space",
            "local",
            null,
            path,
            "Plan.pdf",
            ResourceKind.FILE,
            null,
            1,
            null,
            0,
            0,
        )

    private fun remote(
        id: String,
        path: String = "/Remote.pdf",
        spaceId: String = "space",
    ) = RemoteSearchResource(id, spaceId, path, path.substringAfterLast('/'), false, null, 1, null, 0)
}
