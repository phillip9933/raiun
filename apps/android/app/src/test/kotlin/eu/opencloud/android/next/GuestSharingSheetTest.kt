package eu.opencloud.android.next

import android.app.Application
import androidx.activity.ComponentActivity
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasScrollAction
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performSemanticsAction
import com.github.takahirom.roborazzi.RoborazziOptions
import com.github.takahirom.roborazzi.RoborazziTaskType
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.feature.shares.ResourceSharesScreen
import eu.opencloud.android.next.feature.shares.SharesUiState
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [26, 35], qualifiers = "w360dp-h800dp", application = Application::class)
class GuestSharingSheetTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @OptIn(com.github.takahirom.roborazzi.ExperimentalRoborazziApi::class)
    @Test
    fun guestAccessAppearsAsItsOwnSectionBetweenInternalAndExternalSharing() {
        val account =
            AccountEntity(
                id = "guest-sheet-account",
                serverUrl = "https://guest-sheet.example.test",
                userId = "owner",
                displayName = "Owner",
                authenticationType = "OIDC",
                tusSupported = false,
                sharingEnabled = true,
                publicSharingEnabled = true,
            )
        val resource =
            ResourceEntity(
                accountId = account.id,
                spaceId = "space-1",
                remoteId = "file-1",
                parentId = null,
                path = "Documents/brief.pdf",
                name = "brief.pdf",
                kind = ResourceKind.FILE,
                mimeType = "application/pdf",
                sizeBytes = 1024,
                eTag = null,
                modifiedAtEpochMillis = 0,
                createdAtEpochMillis = 0,
            )
        compose.setContent {
            OpenCloudTheme {
                ResourceSharesScreen(
                    state = SharesUiState(account = account, resource = resource),
                    onNavigateBack = {},
                    onSearch = {},
                    onCreateRecipient = { _, _ -> },
                    onCreatePublic = { _, _, _, _ -> },
                    onUpdatePermissions = { _, _ -> },
                    onRevoke = {},
                    onDismissNotice = {},
                    onGuests = {},
                )
            }
        }
        compose.waitForIdle()
        compose
            .onNode(SemanticsMatcher.keyIsDefined(SemanticsActions.Expand))
            .performSemanticsAction(SemanticsActions.Expand) { it() }
        compose.waitForIdle()

        compose.onRoot().captureRoboImage(
            "build/reports/guest-sharing-sheet-api${android.os.Build.VERSION.SDK_INT}.png",
            roborazziOptions = RoborazziOptions(taskType = RoborazziTaskType.Record),
        )

        compose.onNodeWithText("Internal sharing").assertIsDisplayed()
        compose.onNode(hasScrollAction()).performScrollToNode(hasText("Guest access"))
        compose.onNodeWithText("Guest access").assertIsDisplayed()
        compose.onNode(hasScrollAction()).performScrollToNode(hasText("External sharing"))
        compose.onNodeWithText("External sharing").assertIsDisplayed()
        compose.onNode(hasScrollAction()).performScrollToNode(hasText("Manage guest access"))
        compose.onNodeWithText("Manage guest access").assertIsDisplayed()
    }
}
