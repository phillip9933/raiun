package eu.opencloud.android.next.core.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class FolderShortcutTargetTest {
    @Test fun `identities round trip and isolate accounts and spaces`() {
        val target = FolderShortcutTarget("account/a", "space!root", "folder 日本語")
        assertEquals(target, FolderShortcutTarget.parse(target.uri().toString()))
        assertEquals(target.shortcutId(), target.copy().shortcutId())
        assertNotEquals(target.shortcutId(), target.copy(account = "other").shortcutId())
        assertNotEquals(target.shortcutId(), target.copy(space = "other").shortcutId())
    }

    @Test fun `malformed and unrelated links cannot route to a folder`() {
        listOf(
            null,
            "https://example.test/folder/v1/a/s/r",
            "raiun-folder://folder/v2/a/s/r",
            "raiun-folder://folder/v1/a/s",
            "raiun-folder://folder/v1/a/s/r?token=bad",
            "raiun-folder://folder/v1/a/s/%00",
            "raiun-folder://other/v1/a/s/r",
        ).forEach {
            assertNull(FolderShortcutTarget.parse(it))
        }
    }
}
