package eu.opencloud.android.next.feature.settings

import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.security.VaultPreferenceEntry
import eu.opencloud.android.next.core.security.VaultPreferenceStatus
import eu.opencloud.android.next.core.security.VaultPreferenceTargetKind
import eu.opencloud.android.next.core.security.VaultRememberChoice
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class EncryptedPreferenceInventoryTest {
    @Test
    fun inventoryMergesDeviceChoicesWithoutHidingOrConvertingLegacyRecords() {
        val legacyIdentity = identity("legacy")
        val rememberedIdentity = identity("remembered")
        val declinedIdentity = identity("declined")
        val rows =
            mergeEncryptedPreferenceRows(
                known =
                    listOf(
                        VaultPreferenceEntry(
                            legacyIdentity,
                            "Named legacy folder",
                            VaultPreferenceTargetKind.FOLDER,
                            VaultPreferenceStatus.REMEMBERED,
                        ),
                    ),
                biometric = setOf(legacyIdentity),
                deviceChoices =
                    mapOf(
                        rememberedIdentity to VaultRememberChoice.REMEMBERED,
                        declinedIdentity to VaultRememberChoice.DECLINED,
                    ),
            ).associateBy { it.identity }

        assertEquals(3, rows.size)
        val legacy = requireNotNull(rows[legacyIdentity])
        assertEquals("Named legacy folder", legacy.entry?.title)
        assertEquals(true, legacy.enrolled)
        assertNull(legacy.deviceChoice)
        assertEquals(VaultRememberChoice.REMEMBERED, rows[rememberedIdentity]?.deviceChoice)
        assertEquals(VaultRememberChoice.DECLINED, rows[declinedIdentity]?.deviceChoice)
    }

    private fun identity(id: String) = VaultIdentity("account", "https://cloud.example", "drive", id)
}
