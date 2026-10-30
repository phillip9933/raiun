package eu.opencloud.android.next.ui

import androidx.activity.ComponentActivity
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.text.TextLayoutResult
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "w320dp-h800dp")
class BoundaryDestinationDialogPagingTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun largeFontDialogKeepsPagingAndPlacementFooterVisibleAndClickable() {
        RuntimeEnvironment.setFontScale(2f)
        val fixture = BoundaryDestinationPagingFixture(total = 9_000_000_000)
        val controller = fixture.controller()
        controller.select(fixture.first)
        var show by mutableStateOf(true)
        compose.setContent {
            OpenCloudTheme {
                if (show) BoundaryDestinationDialog(fixture.request, { show = false }, controller)
            }
        }
        val layouts = mutableListOf<TextLayoutResult>()
        val action =
            compose
                .onNodeWithText("Previous", useUnmergedTree = true)
                .fetchSemanticsNode()
                .config[SemanticsActions.GetTextLayoutResult]
                .action
        compose.runOnIdle { assertTrue(requireNotNull(action).invoke(layouts)) }
        val density = layouts.single().layoutInput.density
        assertEquals(2f, density.fontScale, 0f)
        assertEquals(
            320f,
            compose
                .onNode(isDialog())
                .fetchSemanticsNode()
                .boundsInRoot.width / density.density,
            1f,
        )
        compose.onNodeWithText("1–37 of 9000000000").assertIsDisplayed()
        compose.onNodeWithText("Previous").assertIsDisplayed().assertIsNotEnabled()
        compose.onNodeWithText("Next").assertIsDisplayed().performClick()
        compose.onNodeWithText("38–74 of 9000000000").assertIsDisplayed()
        compose.onNodeWithText("Previous").assertIsDisplayed().performClick()
        compose.onNodeWithText("1–37 of 9000000000").assertIsDisplayed()
        compose.onNodeWithText("Copy here").assertIsDisplayed().assertIsEnabled()
        compose.onNodeWithText("Cancel").assertIsDisplayed().performClick()
        compose.onNode(isDialog()).assertDoesNotExist()
        compose.runOnIdle { assertEquals(1, fixture.snapshot.closes) }
    }

    @Test fun failedRootDoesNotExposeAnEmptyFolderClaimOrAnEnabledPlacementAction() {
        val fixture = BoundaryDestinationPagingFixture(failSecond = true)
        val controller = fixture.controller()
        controller.select(fixture.first)
        controller.select(fixture.second)
        compose.setContent { OpenCloudTheme { BoundaryDestinationDialog(fixture.request, {}, controller) } }
        compose.onNodeWithText("Copy here").assertIsNotEnabled()
        compose.onNodeWithText("No folders here. You can choose this location.").assertDoesNotExist()
        compose.onNodeWithText("Next").assertDoesNotExist()
        compose.onNodeWithText("Cancel").assertIsDisplayed().performClick()
        compose.runOnIdle { assertEquals(0, fixture.nameCaptures) }
    }
}
