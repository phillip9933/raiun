package eu.opencloud.android.next.feature.shares

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.GraphShareTarget
import eu.opencloud.android.next.core.network.GuestPermission
import eu.opencloud.android.next.core.network.GuestPermissions
import eu.opencloud.android.next.core.network.GuestRole
import kotlinx.coroutines.CompletableDeferred
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.atomic.AtomicInteger

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class GuestInvitationsScreenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test
    fun invitationWaitsForExplicitSendConfirmation() {
        val actions = FakeGuestInvitationActions()
        setScreen(actions)

        assertEquals(0, actions.inviteCalls.get())
        compose.onNodeWithText("Invite an external guest").assertIsEnabled().performClick()
        compose.onNodeWithText("Email address").performTextInput("guest@example.test")
        compose.onNode(hasText("Reader") and hasClickAction()).performClick()
        compose.onNodeWithText("Review invitation").performClick()

        compose.onNodeWithText("Send invitation email").assertExists()
        assertEquals(0, actions.inviteCalls.get())

        compose.onNodeWithText("Send invitation email").performClick()
        compose.waitUntil(5_000) { actions.inviteCalls.get() == 1 }
        assertEquals(1, actions.inviteCalls.get())
    }

    @Test
    fun inviteButtonDisablesWhileSavingAndRevokeRequiresConfirmation() {
        val actions = FakeGuestInvitationActions()
        val inviteGate = CompletableDeferred<Unit>()
        actions.inviteGate = inviteGate
        setScreen(actions)

        compose.onAllNodesWithContentDescription("Revoke access").onFirst().performClick()
        compose.onNodeWithText("Revoke guest access?").assertExists()
        assertEquals(0, actions.removeCalls.get())
        compose.onNodeWithText("Cancel").performClick()
        assertEquals(0, actions.removeCalls.get())

        compose.onNodeWithText("Invite an external guest").performClick()
        compose.onNodeWithText("Email address").performTextInput("guest@example.test")
        compose.onNode(hasText("Reader") and hasClickAction()).performClick()
        compose.onNodeWithText("Review invitation").performClick()
        compose.onNodeWithText("Send invitation email").performClick()
        compose.waitUntil(5_000) { actions.inviteCalls.get() == 1 }
        compose.onNodeWithText("Invite an external guest").assertIsNotEnabled()

        compose.runOnUiThread { inviteGate.complete(Unit) }
        compose.waitUntil(5_000) { actions.listCalls.get() >= 2 }

        compose.onAllNodesWithContentDescription("Revoke access").onFirst().performClick()
        compose.onNodeWithText("Revoke guest access?").assertExists()
        assertEquals(0, actions.removeCalls.get())
        compose.onNodeWithText("Revoke access").performClick()
        compose.waitUntil(5_000) { actions.removeCalls.get() == 1 }
        assertEquals(1, actions.removeCalls.get())
    }

    @Test fun emptyGuestListStillAllowsPreparingAnInvitation() {
        val actions = FakeGuestInvitationActions(initialGuests = emptyList())
        compose.setContent {
            OpenCloudTheme {
                GuestInvitationsScreen(
                    accountId = "account",
                    resource = resource,
                    onNavigateBack = {},
                    actions = actions,
                )
            }
        }
        val emptyText = "No external guests have access to this item."
        compose.waitUntil(5_000) { compose.onAllNodesWithText(emptyText).fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithText("Invite an external guest").assertIsEnabled().performClick()
        compose.onNodeWithText("Email address").assertExists()
        assertEquals(0, actions.inviteCalls.get())
    }

    private fun setScreen(actions: FakeGuestInvitationActions) {
        compose.setContent {
            OpenCloudTheme {
                GuestInvitationsScreen(
                    accountId = "account",
                    resource = resource,
                    onNavigateBack = {},
                    actions = actions,
                )
            }
        }
        compose.waitUntil(5_000) { actions.listCalls.get() >= 1 }
        compose.onNodeWithText("existing@example.test").assertExists()
    }

    private class FakeGuestInvitationActions(
        initialGuests: List<GuestPermission> =
            listOf(GuestPermission("permission-1", "existing@example.test", listOf("reader"), null)),
    ) : GuestInvitationActions {
        private var guests = initialGuests.toMutableList()
        val inviteCalls = AtomicInteger()
        val removeCalls = AtomicInteger()
        val listCalls = AtomicInteger()
        var inviteGate: CompletableDeferred<Unit>? = null

        override suspend fun list(
            accountId: String,
            target: GraphShareTarget,
        ): GuestPermissions {
            listCalls.incrementAndGet()
            return GuestPermissions(guests.toList(), listOf(GuestRole("reader", "Reader")))
        }

        override suspend fun invite(
            accountId: String,
            target: GraphShareTarget,
            email: String,
            roleId: String,
            expirationDateTime: String?,
        ): GuestPermission {
            inviteCalls.incrementAndGet()
            inviteGate?.await()
            return GuestPermission("permission-new", email, listOf(roleId), expirationDateTime)
                .also(guests::add)
        }

        override suspend fun update(
            accountId: String,
            target: GraphShareTarget,
            permissionId: String,
            roleId: String,
            expirationDateTime: String?,
        ): GuestPermission = GuestPermission(permissionId, "guest@example.test", listOf(roleId), expirationDateTime)

        override suspend fun remove(
            accountId: String,
            target: GraphShareTarget,
            permissionId: String,
        ) {
            removeCalls.incrementAndGet()
            guests.removeAll { it.id == permissionId }
        }
    }

    private companion object {
        val resource =
            ResourceEntity(
                accountId = "account",
                spaceId = "drive",
                remoteId = "item",
                parentId = "parent",
                path = "/folder/report.pdf",
                name = "report.pdf",
                kind = ResourceKind.FILE,
                mimeType = "application/pdf",
                sizeBytes = 12,
                eTag = null,
                modifiedAtEpochMillis = 0,
                createdAtEpochMillis = 0,
            )
    }
}
