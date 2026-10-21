package eu.opencloud.android.next.core.documentsprovider

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.FileNotFoundException

class SharedDocumentHierarchyTest {
    private val parent = SharedDocumentId("a", "share", "scope", "parent")
    private val child = parent.copy(remote = "child")

    @Test fun lockDuringFinalEvidenceCheckRejectsResult() {
        var allowed = true
        val hierarchy =
            SharedDocumentHierarchy({ id ->
                if (id == parent) {
                    SharedHierarchyNode("/", true) { true }
                } else {
                    SharedHierarchyNode("/file", false) {
                        allowed = false
                        true
                    }
                }
            }, { allowed })
        assertThrows(FileNotFoundException::class.java) { runBlocking { hierarchy.isChild(parent, child) } }
    }

    @Test fun checksDirectoryBoundariesAndRootContainment() =
        runBlocking {
            var folderPath = "/Photos"
            var childPath = "/Photos/nested/photo.jpg"
            var folder = true
            val hierarchy =
                SharedDocumentHierarchy({ id ->
                    if (id == parent) {
                        SharedHierarchyNode(folderPath, folder) { true }
                    } else {
                        SharedHierarchyNode(childPath, false) { true }
                    }
                }, { true })
            assertTrue(hierarchy.isChild(parent, child))
            childPath = "/Photos-other/photo.jpg"
            assertFalse(hierarchy.isChild(parent, child))
            childPath = "/Photos"
            assertFalse(hierarchy.isChild(parent, child))
            folderPath = "/"
            assertTrue(hierarchy.isChild(parent, child))
            folder = false
            assertFalse(hierarchy.isChild(parent, child))
        }

    @Test fun rejectsDifferentBindingsAndSelfWithoutResolving() =
        runBlocking {
            val hierarchy = SharedDocumentHierarchy({ error("Must not resolve another scope") }, { true })
            assertFalse(hierarchy.isChild(parent, parent))
            for (other in listOf(child.copy(account = "b"), child.copy(share = "other"), child.copy(scope = "other"))) {
                assertFalse(hierarchy.isChild(parent, other))
            }
        }

    @Test fun rechecksParentEvidenceAndLockAfterChildResolution() =
        runBlocking<Unit> {
            var parentCurrent = true
            var permitted = true
            val hierarchy =
                SharedDocumentHierarchy({ id ->
                    if (id == parent) {
                        SharedHierarchyNode("/", true) { parentCurrent }
                    } else {
                        parentCurrent = false
                        SharedHierarchyNode("/file", false) { true }
                    }
                }, { permitted })
            assertThrows(FileNotFoundException::class.java) { runBlocking { hierarchy.isChild(parent, child) } }
            permitted = false
            assertThrows(FileNotFoundException::class.java) { runBlocking { hierarchy.isChild(parent, child) } }
            val cancelled = SharedDocumentHierarchy({ throw CancellationException() }, { true })
            assertThrows(CancellationException::class.java) { runBlocking { cancelled.isChild(parent, child) } }
        }
}
