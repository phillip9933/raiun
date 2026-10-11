package eu.opencloud.android.next.core.sync

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class BackupExclusionsTest {
    @Test
    fun `basename rules apply at every depth and remain case sensitive`() {
        val matcher = BackupExclusions.parse("*.tmp\ncache/")
        assertTrue(matcher.excludes("folder/file.tmp", false))
        assertFalse(matcher.excludes("folder/file.TMP", false))
        assertTrue(matcher.excludes("a/cache/deep/photo.jpg", false))
        assertFalse(matcher.excludes("a/cache", false))
        assertTrue(matcher.excludes("a/cache", true))
    }

    @Test
    fun `slash rules anchor to source root and globstar spans folders`() {
        val matcher = BackupExclusions.parse("private/*.jpg\nimages/**/draft?.jpg")
        assertTrue(matcher.excludes("private/a.jpg", false))
        assertFalse(matcher.excludes("nested/private/a.jpg", false))
        assertFalse(matcher.excludes("private/deep/a.jpg", false))
        assertTrue(matcher.excludes("images/draft1.jpg", false))
        assertTrue(matcher.excludes("images/2026/oct/draft2.jpg", false))
        assertFalse(matcher.excludes("images/2026/oct/draft22.jpg", false))
    }

    @Test
    fun `excluded directory prunes its entire subtree and thumbnail literal matches`() {
        val matcher = BackupExclusions.parse("private/\n.thumbnail")
        assertTrue(matcher.excludes("private", true))
        assertTrue(matcher.excludes("private/deep/file.jpg", false))
        assertFalse(matcher.excludes("private", false))
        assertTrue(matcher.excludes("nested/.thumbnail", true))
        assertTrue(matcher.excludes("nested/.thumbnail/x.jpg", false))
        assertTrue(matcher.excludes("nested/.thumbnail", false))
        assertFalse(matcher.excludes("nested/.THUMBNAIL", true))
        assertFalse(BackupExclusions.parse("").excludes("nested/.thumbnail", true))
    }

    @Test
    fun `invalid input has user readable errors`() {
        assertNull(BackupExclusions.validate("\nimages/**/*.jpg\n"))
        assertNotNull(BackupExclusions.validate("/absolute"))
        assertNotNull(BackupExclusions.validate("folder//file"))
        assertNotNull(BackupExclusions.validate("a/../b"))
        assertNotNull(BackupExclusions.validate("a\\b"))
        assertNotNull(BackupExclusions.validate("a".repeat(256)))
    }

    @Test
    fun `many stars remain bounded on a long filename`() {
        val rule =
            buildString {
                repeat(80) { append("*a") }
                append('b')
            }
        assertFalse(BackupExclusions.parse(rule).excludes("a".repeat(4_000), false))
    }
}
