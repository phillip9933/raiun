package eu.opencloud.android.next.feature.files

import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.sync.IncomingShareReview
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35], qualifiers = "w360dp-h800dp")
class IncomingUploadReviewTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun `known and unknown sources and sender disclaimer are visible before upload confirmation`() {
        var uploads = 0
        val state =
            IncomingUploadState(
                sourceCount = 2,
                review = listOf(IncomingShareReview("photo.jpg", "example.provider"), IncomingShareReview()),
                accountId = "account",
                spaceId = "space",
                busy = false,
            )
        compose.setContent {
            OpenCloudTheme {
                Column(Modifier.fillMaxSize()) {
                    IncomingShareReviewWarning()
                    IncomingDestinationChoices(state, {}, {}, {}, {})
                    IncomingUploadConfirmationButton(state) { uploads++ }
                }
            }
        }
        compose.onNodeWithText("Original sender unknown.", substring = true).assertIsDisplayed()
        compose.onNodeWithText("File names are untrusted.", substring = true).assertIsDisplayed()
        compose.onNodeWithText("not proof of who shared it", substring = true).assertIsDisplayed()
        compose.onNodeWithText("photo.jpg").assertIsDisplayed()
        compose.onNodeWithText("Content provider package: example.provider").assertIsDisplayed()
        compose.onNodeWithText("Unknown file name (2)").assertIsDisplayed()
        compose.onNodeWithText("Content provider unknown").assertIsDisplayed()
        compose.runOnIdle { assertEquals(0, uploads) }
        compose.onNodeWithText(compose.activity.getString(R.string.document_upload_here)).performClick()
        compose.runOnIdle { assertEquals(1, uploads) }
    }

    @Test fun `confirmation stays disabled until metadata preparation and destination selection finish`() {
        compose.setContent {
            OpenCloudTheme {
                Column {
                    IncomingShareReviewWarning()
                    IncomingUploadConfirmationButton(IncomingUploadState(sourceCount = 1, spaceId = "space")) {
                        error("Busy preparation must not confirm an upload")
                    }
                }
            }
        }
        compose.onNodeWithText(compose.activity.getString(R.string.document_upload_here)).assertIsNotEnabled()
    }
}
