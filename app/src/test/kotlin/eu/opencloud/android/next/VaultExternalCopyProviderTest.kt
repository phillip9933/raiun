package eu.opencloud.android.next

import android.app.Application
import android.content.pm.ProviderInfo
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import androidx.work.Configuration
import androidx.work.testing.SynchronousExecutor
import androidx.work.testing.WorkManagerTestInitHelper
import eu.opencloud.android.next.core.sync.VaultExternalCopyStore
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.FileNotFoundException

@RunWith(RobolectricTestRunner::class)
@Config(application = VaultExternalCopyTestApplication::class)
class VaultExternalCopyProviderTest {
    private val context = RuntimeEnvironment.getApplication()
    private lateinit var provider: VaultExternalCopyProvider

    @Before
    fun setUp() {
        VaultExternalCopyStore.initializeProcess(context)
        WorkManagerTestInitHelper.initializeTestWorkManager(
            context,
            Configuration.Builder().setExecutor(SynchronousExecutor()).build(),
        )
        provider =
            VaultExternalCopyProvider().apply {
                attachInfo(
                    this@VaultExternalCopyProviderTest.context,
                    ProviderInfo().apply {
                        authority = "${this@VaultExternalCopyProviderTest.context.packageName}.vault-export"
                    },
                )
            }
    }

    @After
    fun tearDown() {
        WorkManagerTestInitHelper.closeWorkDatabase()
        VaultExternalCopyStore.initializeProcess(context)
    }

    @Test
    fun providerServesOnlyLiveReadOnlyLeasesWithDisplayMetadata() {
        val lease =
            kotlinx.coroutines.runBlocking {
                VaultExternalCopyStore.create(context, "report.txt", "text/plain") { output ->
                    output.write("exported bytes".encodeToByteArray())
                }
            }
        val cursor =
            provider.query(
                lease.uri,
                arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE),
                null,
                null,
                null,
            )
        assertNotNull(cursor)
        cursor.use {
            assertTrue(it!!.moveToFirst())
            assertEquals("report.txt", it.getString(it.getColumnIndexOrThrow(OpenableColumns.DISPLAY_NAME)))
            assertEquals(14L, it.getLong(it.getColumnIndexOrThrow(OpenableColumns.SIZE)))
        }
        assertEquals("text/plain", provider.getType(lease.uri))
        val descriptor = provider.openFile(lease.uri, "r")
        val content = ParcelFileDescriptor.AutoCloseInputStream(descriptor).bufferedReader().readText()
        assertEquals("exported bytes", content)
        assertThrows(FileNotFoundException::class.java) { provider.openFile(lease.uri, "rw") }

        lease.cleanup()

        assertTrue(provider.query(lease.uri, null, null, null, null) == null)
        assertThrows(FileNotFoundException::class.java) { provider.openFile(lease.uri, "r") }
    }

    @Test
    fun providerRejectsForgedPathsAndTypes() {
        val forged = Uri.parse("content://${context.packageName}.vault-export/../private")
        assertEquals(null, provider.getType(forged))
        assertEquals(null, provider.query(forged, null, null, null, null))
        assertThrows(FileNotFoundException::class.java) { provider.openFile(forged, "r") }
        val providerInfo =
            context.packageManager.getProviderInfo(
                android.content.ComponentName(context, VaultExternalCopyProvider::class.java),
                0,
            )
        assertFalse(providerInfo.exported)
        assertTrue(providerInfo.grantUriPermissions)
    }
}

class VaultExternalCopyTestApplication : Application()
