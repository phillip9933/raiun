package eu.opencloud.android.next

import android.app.Application
import android.content.Context
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.test.assertHeightIsEqualTo
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.unit.dp
import androidx.test.core.app.ApplicationProvider
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.sync.AccountProfiles
import eu.opencloud.android.next.core.ui.ProfileAvatar
import eu.opencloud.android.next.core.ui.accountIdentityDescription
import eu.opencloud.android.next.core.ui.accountServerLabel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [26, 35], qualifiers = "w360dp-h800dp", application = Application::class)
class AccountIdentityStyleTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val fixtureId = UUID.randomUUID().toString()
    private val first = account("a", "https://first.identity.example.test/")
    private val second = account("b", "https://second.identity.example.test/")

    @Test
    fun serverLabelOmitsLegacyCredentialsAndUrlSecrets() {
        assertEquals(
            "cloud.example.test:8443/team",
            accountServerLabel("https://user:synthetic-password@cloud.example.test:8443/team?token=synthetic#fragment"),
        )
        assertEquals("", accountServerLabel("not a valid server URL"))
    }

    @After
    fun removeOnlyFixtureAccounts() =
        runBlocking(Dispatchers.IO) {
            val accounts = FileBrowserDatabase.create(context).accountDao()
            listOf(first, second).forEach { account ->
                accounts.delete(account.id)
                AccountProfiles.clear(context, account.id)
            }
        }

    @OptIn(ExperimentalMaterial3Api::class)
    @Test
    fun switchingSameNameAccountsChangesServerAndClickContextWithoutRetainingInactiveIdentity() {
        runBlocking(Dispatchers.IO) {
            val accounts = FileBrowserDatabase.create(context).accountDao()
            accounts.upsert(first)
            accounts.upsert(second)
        }
        val selectedId = mutableStateOf(first.id)
        val clicked = mutableListOf<String>()
        compose.setContent {
            OpenCloudTheme {
                val description = accountIdentityDescription(selectedId.value)
                TopAppBar(
                    title = { Text("Search") },
                    modifier = Modifier.testTag("account-top-bar"),
                    windowInsets = WindowInsets(0),
                    actions = {
                        IconButton(
                            onClick = { clicked += selectedId.value },
                            modifier = Modifier.semantics { contentDescription = description },
                        ) {
                            ProfileAvatar(selectedId.value)
                        }
                    },
                )
            }
        }
        awaitDescription("first.identity.example.test")
        compose.onNodeWithTag("account-top-bar").assertHeightIsEqualTo(64.dp)
        compose.onNodeWithText("Same display name", useUnmergedTree = true).assertDoesNotExist()
        compose.onNodeWithText("first.identity.example.test", useUnmergedTree = true).assertDoesNotExist()
        compose.onNodeWithContentDescription("Same display name, first.identity.example.test").performClick()
        assertEquals(listOf(first.id), clicked)

        compose.runOnIdle { selectedId.value = second.id }
        awaitDescription("second.identity.example.test")
        compose.onNodeWithText("first.identity.example.test", useUnmergedTree = true).assertDoesNotExist()
        compose.onNodeWithContentDescription("Same display name, first.identity.example.test").assertDoesNotExist()
        compose.onNodeWithContentDescription("Same display name, second.identity.example.test").performClick()
        assertEquals(listOf(first.id, second.id), clicked)

        runBlocking(Dispatchers.IO) {
            FileBrowserDatabase.create(context).accountDao().upsert(second.copy(isActive = false))
            AccountProfiles.refreshAppearance(context, second.id)
        }
        awaitDescription("Account")
        compose.onNodeWithContentDescription("second.identity.example.test", substring = true).assertDoesNotExist()
        compose.onNodeWithText("Same display name", useUnmergedTree = true).assertDoesNotExist()

        compose.runOnIdle { selectedId.value = first.id }
        awaitDescription("first.identity.example.test")
        runBlocking(Dispatchers.IO) {
            FileBrowserDatabase.create(context).accountDao().delete(first.id)
            AccountProfiles.refreshAppearance(context, first.id)
        }
        awaitDescription("Account")
        compose.onNodeWithContentDescription("first.identity.example.test", substring = true).assertDoesNotExist()
        compose.onNodeWithText("Same display name", useUnmergedTree = true).assertDoesNotExist()
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Test
    fun topBarKeepsNativeThemeColorsAcrossThemes() {
        val darkTheme = mutableStateOf(false)
        compose.setContent {
            OpenCloudTheme(darkTheme = darkTheme.value) {
                val colors = TopAppBarDefaults.topAppBarColors()
                assertEquals(MaterialTheme.colorScheme.surface, colors.containerColor)
                assertEquals(MaterialTheme.colorScheme.onSurface, colors.titleContentColor)
                assertEquals(MaterialTheme.colorScheme.onSurfaceVariant, colors.actionIconContentColor)
            }
        }
        compose.runOnIdle { darkTheme.value = true }
        compose.waitForIdle()
    }

    private fun awaitDescription(text: String) {
        compose.waitUntil(timeoutMillis = 10_000) {
            compose.onAllNodesWithContentDescription(text, substring = true).fetchSemanticsNodes().isNotEmpty()
        }
    }

    private fun account(
        suffix: String,
        server: String,
    ) = AccountEntity(
        id = "account-identity-style-$fixtureId-$suffix",
        serverUrl = server,
        userId = "synthetic-$suffix",
        displayName = "Same display name",
        authenticationType = "OIDC",
        tusSupported = false,
    )
}
