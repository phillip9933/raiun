package eu.opencloud.android.next.core.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.work.Configuration
import androidx.work.WorkInfo
import androidx.work.WorkManager
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.AccountRemovalAdmission
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.storedAccountForAdmission
import eu.opencloud.android.next.core.datastore.SettingsRepository
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.security.KeystoreCredentialStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID
import java.util.concurrent.TimeUnit

/** Real local WorkManager execution, Keystore credentials and Room; synthetic identities and no network. */
@RunWith(AndroidJUnit4::class)
class AccountRemovalAndroidTest {
    @Test fun queuedRemovalCompletesWithoutCancellingItselfAndPreservesOtherAccount() =
        runBlocking(Dispatchers.IO) {
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val work =
                try {
                    WorkManager.getInstance(context)
                } catch (_: IllegalStateException) {
                    WorkManager.initialize(context, Configuration.Builder().build())
                    WorkManager.getInstance(context)
                }
            val database = FileBrowserDatabase.create(context)
            val store = FileBrowserStore(database)
            val credentials = KeystoreCredentialStore(context)
            val settings = SettingsRepository.create(context)
            val previousSelection = settings.settings.first().activeAccountId
            val suffix = UUID.randomUUID().toString()
            val removed = AccountEntity("remove-$suffix", "https://removal.example", "one", "One", "BASIC", false)
            val retained = removed.copy(id = "retain-$suffix", userId = "two", displayName = "Two")
            val ownDirectory = resourceCacheDirectory(context.filesDir, removed.id, "synthetic-space")
            val otherDirectory = resourceCacheDirectory(context.filesDir, retained.id, "synthetic-space")
            val ownFile = File(ownDirectory, "synthetic.txt")
            val otherFile = File(otherDirectory, "synthetic.txt")
            val workName = "account-removal-${removed.id}"
            var replacementSelection: String? = removed.id
            try {
                database.accountDao().upsert(removed)
                database.accountDao().upsert(retained)
                credentials.saveBasicCredentials(removed.id, "one", "synthetic-removed-password")
                credentials.saveBasicCredentials(retained.id, "two", "synthetic-retained-password")
                check(ownDirectory.mkdirs())
                check(otherDirectory.mkdirs())
                ownFile.writeText("synthetic removed bytes")
                otherFile.writeText("synthetic retained bytes")
                settings.setActiveAccountId(removed.id)
                replacementSelection = AccountRemovalCoordinator(context).request(removed.id)
                withTimeout(30_000) {
                    while (store.storedAccountForAdmission(removed.id) != null) delay(100)
                    while (true) {
                        val attempts = work.getWorkInfosForUniqueWork(workName).get(5, TimeUnit.SECONDS)
                        if (attempts.all { it.state.isFinished }) break
                        delay(100)
                    }
                }
                val completed = work.getWorkInfosForUniqueWork(workName).get(5, TimeUnit.SECONDS)
                assertTrue(completed.any { it.state == WorkInfo.State.SUCCEEDED })
                assertFalse(completed.any { it.state == WorkInfo.State.CANCELLED })
                assertNull(store.storedAccountForAdmission(removed.id))
                assertNull(credentials.readBasicPassword(removed.id))
                assertNull(credentials.readBasicUsername(removed.id))
                assertFalse(ownFile.exists())
                assertEquals(retained, store.account(retained.id))
                assertEquals("synthetic-retained-password", credentials.readBasicPassword(retained.id))
                assertEquals("two", credentials.readBasicUsername(retained.id))
                assertEquals("synthetic retained bytes", otherFile.readText())
            } finally {
                work.cancelUniqueWork(workName).result.get(5, TimeUnit.SECONDS)
                AccountRemovalAdmission.withLock {
                    // Also wait for any in-flight cleanup to leave its admission gate before fixture disposal.
                    store.removeAccount(removed.id)
                    store.removeAccount(retained.id)
                    credentials.remove(removed.id)
                    credentials.remove(retained.id)
                    ownDirectory.parentFile?.deleteRecursively()
                    otherDirectory.parentFile?.deleteRecursively()
                    replacementSelection?.let { settings.replaceActiveAccountIfCurrent(it, previousSelection) }
                    settings.replaceActiveAccountIfCurrent(removed.id, previousSelection)
                }
            }
        }
}
