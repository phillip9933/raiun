package eu.opencloud.android.next

import android.app.Application
import android.content.Context
import androidx.activity.ComponentActivity
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.isEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.text.TextLayoutResult
import androidx.test.core.app.ApplicationProvider
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.model.AccountColor
import eu.opencloud.android.next.core.sync.AccountProfiles
import eu.opencloud.android.next.feature.account.AccountColorPicker
import eu.opencloud.android.next.feature.account.AccountDetailsScreen
import eu.opencloud.android.next.feature.account.AccountDetailsState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [26, 35], qualifiers = "w320dp-h640dp", application = Application::class)
class AccountColorPickerTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val fixtureId = UUID.randomUUID().toString()
    private val first = account("first")
    private val second = account("second")

    @Before
    fun seedAccounts() =
        runBlocking(Dispatchers.IO) {
            listOf(first, second).forEach { FileBrowserDatabase.create(context).accountDao().upsert(it) }
        }

    @After
    fun removeOnlyFixtureAccounts() =
        runBlocking(Dispatchers.IO) {
            listOf(first, second).forEach {
                AccountProfiles.clear(context, it.id)
                FileBrowserDatabase.create(context).accountDao().delete(it.id)
            }
        }

    @Test
    fun cancelDiscardsDraftWhileSavePersistsAcrossReopenAndStaysPerAccount() {
        val selected = mutableStateOf(first)
        compose.setContent {
            OpenCloudTheme {
                AccountDetailsScreen(selected.value, AccountDetailsState(), {}, {}, {}, {})
            }
        }
        openPicker()
        compose.onNodeWithText("Light").assertExists()
        compose.onNodeWithText("Dark").assertExists()
        choose("Purple")
        compose.onNodeWithText("Cancel").performClick()
        assertNull(choice(first.id))

        openPicker()
        compose.onNode(hasText("Automatic") and hasAnyAncestor(isDialog())).assertIsSelected()
        choose("Purple")
        compose.onNodeWithText("Save").performClick()
        awaitChoice(first.id, AccountColor.PURPLE)
        openPicker()
        compose.onNode(hasText("Purple") and hasAnyAncestor(isDialog())).assertIsSelected()
        compose.onNodeWithText("Cancel").performClick()

        compose.runOnIdle { selected.value = second }
        openPicker()
        compose.onNode(hasText("Automatic") and hasAnyAncestor(isDialog())).assertIsSelected()
        choose("Jade")
        compose.onNodeWithText("Save").performClick()
        awaitChoice(second.id, AccountColor.JADE)
        assertEquals(AccountColor.PURPLE, choice(first.id))
    }

    @Test
    fun switchingAccountsDiscardsOpenDraftAndAutomaticCanBeRestored() {
        runBlocking(Dispatchers.IO) { AccountProfiles.setColorChoice(context, first.id, AccountColor.BLUE) }
        val selected = mutableStateOf(first)
        compose.setContent {
            OpenCloudTheme {
                AccountDetailsScreen(selected.value, AccountDetailsState(), {}, {}, {}, {})
            }
        }
        openPicker()
        choose("Rose")
        compose.runOnIdle { selected.value = second }
        compose.onNodeWithText("Save").assertDoesNotExist()
        assertEquals(AccountColor.BLUE, choice(first.id))
        compose.runOnIdle { selected.value = first }
        openPicker()
        choose("Automatic")
        compose.onNodeWithText("Save").performClick()
        awaitChoice(first.id, null)
        assertNull(choice(second.id))
    }

    @Test
    @Config(sdk = [35])
    fun lightAndDarkPreviewsMatchGolden() {
        compose.setContent {
            OpenCloudTheme {
                AccountColorPicker(
                    first.copy(id = "account-color-preview-stable", displayName = "Test account"),
                    AccountColor.PURPLE,
                    busy = false,
                    failed = false,
                    onDismiss = {},
                    onSave = {},
                )
            }
        }
        compose.onNode(isDialog()).captureRoboImage("src/test/snapshots/rendered/account_color_picker.png")
    }

    @Test
    @Config(sdk = [35])
    fun actualLargeTextDarkDialogKeepsChoicesAndSaveReachable() {
        RuntimeEnvironment.setFontScale(2f)
        var saved: AccountColor? = null
        compose.setContent {
            OpenCloudTheme(darkTheme = true) {
                AccountColorPicker(
                    first.copy(id = "account-color-preview-stable", displayName = "Test account"),
                    AccountColor.PURPLE,
                    busy = false,
                    failed = false,
                    onDismiss = {},
                    onSave = { saved = it },
                )
            }
        }
        compose.onNodeWithText("Account color").performSemanticsAction(SemanticsActions.GetTextLayoutResult) { action ->
            val results = mutableListOf<TextLayoutResult>()
            org.junit.Assert.assertTrue(action(results))
            assertEquals(
                2f,
                results
                    .single()
                    .layoutInput.density.fontScale,
                0.01f,
            )
        }
        compose.onNode(isDialog()).captureRoboImage("src/test/snapshots/rendered/account_color_picker_dark_large.png")
        choose("Plum")
        compose.onNodeWithText("Save").assertIsDisplayed().performClick()
        assertEquals(AccountColor.PLUM, saved)
    }

    private fun openPicker() {
        compose.waitUntil(timeoutMillis = 10_000) {
            compose.onAllNodes(hasText("Edit") and isEnabled()).fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithText("Edit").performScrollTo().performClick()
    }

    private fun choose(label: String) {
        compose.onNode(hasText(label) and hasAnyAncestor(isDialog())).performScrollTo().performClick()
    }

    private fun awaitChoice(
        accountId: String,
        color: AccountColor?,
    ) {
        compose.waitUntil(timeoutMillis = 10_000) { choice(accountId) == color }
        compose.waitUntil(timeoutMillis = 10_000) {
            compose.onAllNodes(hasText("Save")).fetchSemanticsNodes().isEmpty()
        }
        compose.onNodeWithText("Save").assertDoesNotExist()
    }

    private fun choice(accountId: String): AccountColor? =
        runBlocking(Dispatchers.IO) {
            AccountProfiles.colorChoice(context, accountId)
        }

    private fun account(suffix: String) =
        AccountEntity(
            id = "account-color-$fixtureId-$suffix",
            serverUrl = "https://$suffix.color.example.test/",
            userId = "synthetic-$suffix",
            displayName = "Test account $suffix",
            authenticationType = "OIDC",
            tusSupported = false,
        )
}
