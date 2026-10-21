package eu.opencloud.android.next.core.security

import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class VaultPreferencesTest {
    @Test
    fun remembersAndDeclinesPerIdentityAndCanResetOneOrAllOfferMarkers() {
        val context: Context = RuntimeEnvironment.getApplication()
        val preferences = VaultPreferences(context)
        preferences.reset()
        val remembered = identity("vault-a")
        val declined = identity("vault-b")

        preferences.remember(remembered, "Alpha", VaultPreferenceTargetKind.SPACE)
        preferences.decline(declined, "Beta", VaultPreferenceTargetKind.FOLDER)
        val reopenedPreferences = VaultPreferences(context)

        assertEquals(VaultPreferenceStatus.REMEMBERED, reopenedPreferences.status(remembered))
        assertEquals(VaultPreferenceStatus.DECLINED, reopenedPreferences.status(declined))
        assertEquals(
            setOf(
                VaultPreferenceEntry(
                    remembered,
                    "Alpha",
                    VaultPreferenceTargetKind.SPACE,
                    VaultPreferenceStatus.REMEMBERED,
                ),
                VaultPreferenceEntry(
                    declined,
                    "Beta",
                    VaultPreferenceTargetKind.FOLDER,
                    VaultPreferenceStatus.DECLINED,
                ),
            ),
            reopenedPreferences.entries().toSet(),
        )

        reopenedPreferences.remove(declined)
        assertNull(reopenedPreferences.status(declined))
        assertEquals(listOf(remembered), reopenedPreferences.entries().map { it.identity })

        reopenedPreferences.reset()
        assertEquals(emptyList<VaultPreferenceEntry>(), reopenedPreferences.entries())
    }

    @Test
    fun forgettingAccountRemovesOnlyItsValidatedMarkers() {
        val context: Context = RuntimeEnvironment.getApplication()
        val preferences = VaultPreferences(context)
        preferences.reset()
        val first = identity("account-a", "vault-a")
        val second = identity("account-a", "vault-b")
        val other = identity("account-b", "vault-c")
        preferences.remember(first, "Alpha")
        val directory = File(context.noBackupFilesDir, "vault-preferences")
        val firstRecord = requireNotNull(directory.listFiles()).single { it.extension == "preference" }
        assertTrue(firstRecord.renameTo(File(firstRecord.path + ".bak")))
        preferences.decline(second, "Beta")
        preferences.remember(other, "Other")

        VaultPreferences(context).forgetAccount("account-a")

        assertNull(preferences.status(first))
        assertNull(preferences.status(second))
        assertEquals(VaultPreferenceStatus.REMEMBERED, preferences.status(other))
        assertEquals(listOf(other), preferences.entries().map { it.identity })
        preferences.reset()
    }

    @Test
    fun corruptMarkerFailsClosedBeforeDeletingAnotherAccountsChoices() {
        val context: Context = RuntimeEnvironment.getApplication()
        val preferences = VaultPreferences(context)
        preferences.reset()
        val removed = identity("account-a", "vault-a")
        val other = identity("account-b", "vault-b")
        preferences.remember(removed, "Removed account")
        preferences.decline(other, "Other account")
        val invalid = File(context.noBackupFilesDir, "vault-preferences/invalid.preference")
        invalid.writeText("invalid local marker")
        try {
            assertThrows(VaultPreferencesException::class.java) {
                preferences.forgetAccount("account-a")
            }
            assertEquals(VaultPreferenceStatus.REMEMBERED, preferences.status(removed))
            assertEquals(VaultPreferenceStatus.DECLINED, preferences.status(other))
        } finally {
            invalid.delete()
            preferences.reset()
        }
    }

    private fun identity(vaultId: String) = VaultIdentity("account", "https://cloud.example", "drive", vaultId)

    private fun identity(
        accountId: String,
        vaultId: String,
    ) = VaultIdentity(accountId, "https://cloud.example", "drive", vaultId)
}
