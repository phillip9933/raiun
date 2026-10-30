package eu.opencloud.android.next.feature.shares

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasScrollAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.model.ResourceKind
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class GuestAccessSectionTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test
    fun guestAccessIsSeparateFromInternalAndExternalSharing() {
        var guestOpens = 0
        compose.setContent {
            OpenCloudTheme {
                ResourceSharesScreen(
                    state =
                        SharesUiState(
                            account =
                                AccountEntity(
                                    "a",
                                    "https://cloud.test",
                                    "u",
                                    "User",
                                    "oidc",
                                    true,
                                    sharingEnabled = true,
                                    publicSharingEnabled = true,
                                ),
                            resource =
                                ResourceEntity(
                                    accountId = "a",
                                    spaceId = "space-1",
                                    remoteId = "item-1",
                                    parentId = null,
                                    path = "Documents/report.pdf",
                                    name = "report.pdf",
                                    kind = ResourceKind.FILE,
                                    mimeType = "application/pdf",
                                    sizeBytes = 1,
                                    eTag = null,
                                    modifiedAtEpochMillis = 0,
                                    createdAtEpochMillis = 0,
                                ),
                        ),
                    onNavigateBack = {},
                    onSearch = {},
                    onCreateRecipient = { _, _ -> },
                    onCreatePublic = { _, _, _, _ -> },
                    onUpdatePermissions = { _, _ -> },
                    onRevoke = {},
                    onDismissNotice = {},
                    onGuests = { guestOpens++ },
                )
            }
        }

        compose.onNodeWithText("Internal sharing").assertExists()
        compose.onNode(hasScrollAction()).performScrollToNode(hasText("Guest access"))
        compose.onNodeWithText("Guest access").assertExists()
        compose.onNode(hasScrollAction()).performScrollToNode(hasText("External sharing"))
        compose.onNodeWithText("External sharing").assertExists()
        compose.onNode(hasScrollAction()).performScrollToNode(hasText("Manage guest access"))
        compose.onNode(hasText("Manage guest access") and hasClickAction()).performClick()
        assertEquals(1, guestOpens)
        compose.onNode(hasText("Manage guest access") and hasClickAction()).assertExists()
    }
}
