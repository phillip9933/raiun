package eu.opencloud.android.next.feature.shares

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.GraphShareTarget
import eu.opencloud.android.next.core.network.GuestPermission
import eu.opencloud.android.next.core.network.GuestPermissions
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class GuestInvitationErrorTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun unsupportedCapabilityIsNotPresentedAsPermissionDenial() {
        render(OpenCloudError.Unsupported)
        waitFor(UNSUPPORTED)
        compose.onNodeWithText(DENIED).assertDoesNotExist()
    }

    @Test fun actualPermissionDenialIsNotPresentedAsDisabledGuestSupport() {
        render(OpenCloudError.AccessDenied)
        waitFor(DENIED)
        compose.onNodeWithText(UNSUPPORTED).assertDoesNotExist()
    }

    private fun waitFor(text: String) {
        compose.waitUntil(5_000) { compose.onAllNodesWithText(text).fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithText(text).assertExists()
    }

    private fun render(error: OpenCloudError) {
        compose.setContent {
            OpenCloudTheme {
                GuestInvitationsScreen(
                    accountId = "test",
                    resource =
                        ResourceEntity(
                            "test",
                            "space",
                            "item",
                            null,
                            "/file.txt",
                            "file.txt",
                            ResourceKind.FILE,
                            "text/plain",
                            1,
                            null,
                            0,
                            0,
                        ),
                    onNavigateBack = {},
                    actions = FailedGuestActions(error),
                )
            }
        }
    }

    private class FailedGuestActions(
        private val failure: OpenCloudError,
    ) : GuestInvitationActions {
        override suspend fun list(
            accountId: String,
            target: GraphShareTarget,
        ): GuestPermissions = throw OpenCloudException(failure)

        override suspend fun invite(
            accountId: String,
            target: GraphShareTarget,
            email: String,
            roleId: String,
            expirationDateTime: String?,
        ): GuestPermission = error("No mutation is allowed while guest metadata is unavailable")

        override suspend fun update(
            accountId: String,
            target: GraphShareTarget,
            permissionId: String,
            roleId: String,
            expirationDateTime: String?,
        ): GuestPermission = error("No mutation is allowed while guest metadata is unavailable")

        override suspend fun remove(
            accountId: String,
            target: GraphShareTarget,
            permissionId: String,
        ): Unit = error("No mutation is allowed while guest metadata is unavailable")
    }

    private companion object {
        const val DENIED = "You do not have permission to manage guest access for this item."
        const val UNSUPPORTED = "Guest invitations are unavailable or disabled on this server."
    }
}
