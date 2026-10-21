package eu.opencloud.android.next.feature.search

import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.RemoteSearchResource
import eu.opencloud.android.next.core.sync.mergeSearchResults
import org.junit.Assert.assertEquals
import org.junit.Test

class SearchMergeTest {
    @Test fun `local result wins when remote contains same resource`() {
        val local = resource("same", "Local name")
        val remote = RemoteSearchResource("same", "space", "/Remote name", "Remote name", false, null, 1, null, 0)
        val result = mergeSearchResults(listOf(local), listOf(remote), "account")
        assertEquals(1, result.size)
        assertEquals("Local name", result.single().name)
    }

    private fun resource(
        id: String,
        name: String,
    ) = ResourceEntity("account", "space", id, null, "/$name", name, ResourceKind.FILE, null, 1, null, 0, 0)
}
