package eu.opencloud.android.next.core.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class SharedFolderShortcutTargetTest {
    private val request = SharedFolderRequest("account/a", "share", "scope", "id!日本語", "/Nested/日本語")

    @Test fun roundTripPreservesShareScopeAndNestedPath() {
        val target = SharedFolderShortcutTarget(request)
        assertEquals(target, SharedFolderShortcutTarget.parse(target.uri().toString()))
        assertEquals(target.shortcutId(), target.copy().shortcutId())
        listOf(
            request.copy(account = "other"),
            request.copy(share = "other"),
            request.copy(scope = "other"),
            request.copy(remoteId = "other"),
            request.copy(path = "/Other"),
        ).forEach {
            assertNotEquals(target.shortcutId(), SharedFolderShortcutTarget(it).shortcutId())
        }
        val root = SharedFolderShortcutTarget(request.copy(path = "/"))
        assertEquals(root, SharedFolderShortcutTarget.parse(root.uri().toString()))
        assertNull(FolderShortcutTarget.parse(target.uri().toString()))
    }

    @Test fun rejectsTraversalForeignSchemesQueriesAndMalformedTargets() {
        listOf("/../secret", "/a/../../secret", "relative", "/a//b", "/a/./b", "/a/\\b").forEach {
            assertNull(
                SharedFolderShortcutTarget.parse(SharedFolderShortcutTarget(request.copy(path = it)).uri().toString()),
            )
        }
        val uri = SharedFolderShortcutTarget(request).uri().toString()
        listOf(
            null,
            uri.replace("raiun-folder:", "https:"),
            uri + "?token=bad",
            uri + "#bad",
            "raiun-folder://shared/v1/account/share/scope/id",
            "raiun-folder://shared/v2/account/share/scope/id/%2F",
        ).forEach { assertNull(SharedFolderShortcutTarget.parse(it)) }
    }
}
