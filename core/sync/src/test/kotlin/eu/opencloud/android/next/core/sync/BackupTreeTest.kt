package eu.opencloud.android.next.core.sync

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.provider.DocumentsContract
import eu.opencloud.android.next.core.network.OpenCloudException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.shadows.ShadowContentResolver

@RunWith(RobolectricTestRunner::class)
class BackupTreeTest {
    @Test fun `nested duplicate filenames keep their parents and trash entries are excluded`() {
        register(TreeProvider())
        val files = queryBackupTree(RuntimeEnvironment.getApplication(), tree)
        assertEquals(listOf("Camera", "Edited"), files.map { it.relativeParent })
        assertEquals(listOf("image.jpg", "image.jpg"), files.map { it.name })
        assertEquals(listOf(0L, 0L), files.map { it.modified })
    }

    @Test fun `provider query failure and cycles do not become successful empty scans`() {
        listOf(TreeProvider(fail = true), TreeProvider(cycle = true)).forEach { provider ->
            register(provider)
            assertThrows(OpenCloudException::class.java) { queryBackupTree(RuntimeEnvironment.getApplication(), tree) }
        }
    }

    @Test fun `excluded directories are never queried and allowed siblings remain`() {
        val provider = TreeProvider(exclusionFixture = true)
        register(provider)
        val files =
            queryBackupTree(
                RuntimeEnvironment.getApplication(),
                tree,
                exclusions = BackupExclusions.parse("Private/\n*.tmp"),
            )
        assertEquals(listOf("root", "public"), provider.queriedIds)
        assertEquals(listOf("Public"), files.map { it.relativeParent })
        assertEquals(listOf("photo.jpg"), files.map { it.name })
    }

    private val tree = DocumentsContract.buildTreeDocumentUri("backup.test", "root")

    private fun register(provider: TreeProvider) {
        provider.attachInfo(
            RuntimeEnvironment.getApplication(),
            android.content.pm.ProviderInfo().apply {
                authority = "backup.test"
            },
        )
        ShadowContentResolver.registerProviderInternal("backup.test", provider)
    }

    private class TreeProvider(
        private val fail: Boolean = false,
        private val cycle: Boolean = false,
        private val exclusionFixture: Boolean = false,
    ) : ContentProvider() {
        val queriedIds = mutableListOf<String>()

        override fun onCreate() = true

        override fun getType(uri: Uri) = DocumentsContract.Document.MIME_TYPE_DIR

        override fun query(
            uri: Uri,
            projection: Array<out String>?,
            selection: String?,
            selectionArgs: Array<out String>?,
            sortOrder: String?,
        ): Cursor? {
            if (fail) return null
            return MatrixCursor(projection).apply {
                val id = DocumentsContract.getDocumentId(uri)
                queriedIds += id
                if (exclusionFixture) {
                    when (id) {
                        "root" -> {
                            addRow(arrayOf("private", "Private", getType(uri), 0L, null))
                            addRow(arrayOf("public", "Public", getType(uri), 0L, null))
                            addRow(arrayOf("root-temp", "notes.tmp", "text/plain", 0L, 5L))
                        }
                        "public" -> {
                            addRow(arrayOf("public-file", "photo.jpg", "image/jpeg", 0L, 5L))
                            addRow(arrayOf("public-temp", "draft.tmp", "text/plain", 0L, 5L))
                        }
                        "private" -> addRow(arrayOf("private-file", "secret.jpg", "image/jpeg", 0L, 5L))
                    }
                    return@apply
                }
                if (id == "root") {
                    addRow(arrayOf(if (cycle) "root" else "camera", "Camera", getType(uri), 0L, null))
                    addRow(arrayOf("edited", "Edited", getType(uri), 0L, null))
                } else {
                    addRow(arrayOf("$id-file", "image.jpg", "image/jpeg", null, 5L))
                    addRow(arrayOf("$id-trash", ".trashed-image.jpg", "image/jpeg", null, 5L))
                }
            }
        }

        override fun insert(
            uri: Uri,
            values: ContentValues?,
        ): Uri? = null

        override fun delete(
            uri: Uri,
            selection: String?,
            selectionArgs: Array<out String>?,
        ) = 0

        override fun update(
            uri: Uri,
            values: ContentValues?,
            selection: String?,
            selectionArgs: Array<out String>?,
        ) = 0
    }
}
