package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.ShareRecipient
import eu.opencloud.android.next.core.network.SpaceMember
import eu.opencloud.android.next.core.network.SpaceMemberRole
import eu.opencloud.android.next.core.network.SpaceMembers
import eu.opencloud.android.next.core.sync.EncryptedSpaceDetails
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import eu.opencloud.android.next.ui.EncryptedSpaceManagementActions
import eu.opencloud.android.next.ui.EncryptedSpaceManagementDialog
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class EncryptedSpaceManagementDialogTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun compactManagementDialogRendersSyntheticSpaceAndMembers() {
        val actions = FakeManagementActions()
        showDialog(actions)
        compose.waitUntil(5_000) { compose.onAllNodesWithText("Secure team files").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithText("Owner: Casey Owner").assertExists()
        compose.onNodeWithText("Members").assertExists()
        compose.onNodeWithText("Avery Reader · Reader").assertExists()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/encrypted_space_management.png")
    }

    @Test fun memberRemovalRequiresExplicitConfirmation() {
        val actions = FakeManagementActions()
        showDialog(actions)
        compose.waitUntil(
            5_000,
        ) { compose.onAllNodesWithText("Avery Reader · Reader").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithText("Avery Reader · Reader").performClick()
        compose.onNodeWithText("Remove member").performClick()
        compose.onNodeWithText("Remove Avery Reader from this Space?").assertExists()
        compose
            .onNodeWithText(
                "Membership does not provide the encryption password. Removing someone cannot revoke keys they already know.",
            ).assertExists()
        assertEquals(0, actions.removeCalls)
        compose.onNodeWithText("Remove member").performClick()
        compose.waitUntil(5_000) { actions.removeCalls == 1 }
        assertEquals(1, actions.removeCalls)
    }

    @Test fun unadvertisedLegacyRoleCannotBeSaved() {
        val actions = FakeManagementActions(memberRole = "legacy-owner")
        showDialog(actions)
        compose.waitUntil(5_000) {
            compose.onAllNodesWithText("Avery Reader · legacy-owner").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithText("Avery Reader · legacy-owner").performClick()
        compose.onNodeWithText("Save").assertIsNotEnabled()
    }

    @Test fun revokedUnlockLeaseCannotWriteAndInvalidatesParentSession() {
        val actions = FakeManagementActions()
        val unlocked = AtomicBoolean(true)
        var invalidations = 0
        showDialog(actions, { unlocked.get() }, { invalidations++ })
        compose.waitUntil(
            5_000,
        ) { compose.onAllNodesWithText("Avery Reader · Reader").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithText("Avery Reader · Reader").performClick()
        compose.onNodeWithText("Manager").performClick()
        unlocked.set(false)
        compose.onNodeWithText("Save").performClick()
        compose.waitUntil(5_000) { invalidations == 1 }
        assertEquals(0, actions.successfulWrites)
    }

    @Test fun disablingUsesSeparateConfirmationAndReportsLifecycleChange() {
        val actions = FakeManagementActions()
        val lifecycleChange = AtomicReference<VaultLocation?>(null)
        compose.setContent {
            OpenCloudTheme {
                EncryptedSpaceManagementDialog(
                    ACCOUNT_ID,
                    location,
                    { true },
                    onClose = {},
                    onChange = {},
                    actionsOverride = actions,
                    onLifecycleChange = { lifecycleChange.set(it) },
                )
            }
        }
        compose.waitUntil(5_000) { compose.onAllNodesWithText("Secure team files").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithText("Disable encrypted Space").performClick()
        compose
            .onNodeWithText(
                "This Space will become inaccessible until a manager restores it. Its encrypted content remains stored.",
            ).assertExists()
        assertEquals(0, actions.disableCalls)
        compose.onNodeWithText("Cancel").performClick()
        assertEquals(0, actions.disableCalls)
        compose.onNodeWithText("Disable encrypted Space").performClick()
        compose.onNodeWithText("Disable Space").performClick()
        compose.waitUntil(5_000) { actions.disableCalls == 1 }
        compose.waitUntil(5_000) { lifecycleChange.get() != null }
        assertEquals(true, lifecycleChange.get()?.isDisabled)
        assertTrue(actions.disableCalls == 1)
    }

    private fun showDialog(
        actions: FakeManagementActions,
        isUnlocked: () -> Boolean = { true },
        onInvalidate: () -> Unit = {},
    ) {
        compose.setContent {
            OpenCloudTheme {
                EncryptedSpaceManagementDialog(
                    accountId = ACCOUNT_ID,
                    location = location,
                    isUnlocked = isUnlocked,
                    onClose = {},
                    onChange = {},
                    actionsOverride = actions,
                    onInvalidate = onInvalidate,
                )
            }
        }
    }

    private class FakeManagementActions(
        memberRole: String = "reader",
    ) : EncryptedSpaceManagementActions {
        var removeCalls = 0
        var successfulWrites = 0
        var disableCalls = 0
        private val roleOptions = listOf(SpaceMemberRole("reader", "Reader"), SpaceMemberRole("manager", "Manager"))
        private var currentMembers = listOf(SpaceMember("permission-1", "Avery Reader", listOf(memberRole), false))

        override suspend fun spaceDetails(
            accountId: String,
            location: VaultLocation,
            isUnlocked: () -> Boolean,
        ) = details

        override suspend fun disableSpace(
            accountId: String,
            location: VaultLocation,
            isUnlocked: () -> Boolean,
        ): VaultLocation {
            if (!isUnlocked()) throw OpenCloudException(OpenCloudError.AccessDenied)
            disableCalls++
            return location.copy(isDisabled = true)
        }

        override suspend fun updateSpace(
            accountId: String,
            location: VaultLocation,
            isUnlocked: () -> Boolean,
            name: String?,
            subtitle: String?,
            quotaBytes: Long?,
        ) = details.copy(name = name ?: details.name, subtitle = subtitle ?: details.subtitle)

        override suspend fun listMembers(
            accountId: String,
            location: VaultLocation,
            isUnlocked: () -> Boolean,
        ) = SpaceMembers(currentMembers, roleOptions)

        override suspend fun searchRecipients(
            accountId: String,
            location: VaultLocation,
            query: String,
            isUnlocked: () -> Boolean,
        ): List<ShareRecipient> = emptyList()

        override suspend fun addMember(
            accountId: String,
            location: VaultLocation,
            recipient: ShareRecipient,
            role: String,
            isUnlocked: () -> Boolean,
        ) {
            if (!isUnlocked()) throw OpenCloudException(OpenCloudError.AccessDenied)
            successfulWrites++
        }

        override suspend fun changeMemberRole(
            accountId: String,
            location: VaultLocation,
            permissionId: String,
            role: String,
            isUnlocked: () -> Boolean,
        ) {
            if (!isUnlocked()) throw OpenCloudException(OpenCloudError.AccessDenied)
            successfulWrites++
            currentMembers = currentMembers.map { if (it.id == permissionId) it.copy(roles = listOf(role)) else it }
        }

        override suspend fun removeMember(
            accountId: String,
            location: VaultLocation,
            permissionId: String,
            isUnlocked: () -> Boolean,
        ) {
            if (!isUnlocked()) throw OpenCloudException(OpenCloudError.AccessDenied)
            removeCalls++
            successfulWrites++
            currentMembers = currentMembers.filterNot { it.id == permissionId }
        }
    }

    private companion object {
        const val ACCOUNT_ID = "management-dialog-test"
        val location =
            VaultLocation(
                accountId = ACCOUNT_ID,
                title = "Secure team files",
                kind = VaultLocationKind.SPACE_VAULT,
                driveId = "space-drive",
                remoteVaultId = "vault-root",
                sourceRootId = "graph-root",
                canonicalServer = "https://cloud.example",
                rootWebDavUrl = "https://cloud.example/dav/root",
                vaultPath = "",
                isVaultRoot = true,
            )
        val details =
            EncryptedSpaceDetails(
                location = location,
                name = "Secure team files",
                subtitle = "Quarterly planning",
                ownerName = "Casey Owner",
                quotaBytes = 5L * 1_048_576L,
                quotaUsedBytes = 2L * 1_048_576L,
                quotaRemainingBytes = 3L * 1_048_576L,
            )
    }
}
