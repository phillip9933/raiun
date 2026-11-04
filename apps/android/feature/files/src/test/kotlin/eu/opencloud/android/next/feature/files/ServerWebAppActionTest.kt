package eu.opencloud.android.next.feature.files

import androidx.activity.ComponentActivity
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.VaultExclusion
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.security.AccountSessions
import eu.opencloud.android.next.core.security.CredentialStore
import eu.opencloud.android.next.core.sync.ServerWebApps
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows
import org.robolectric.annotation.Config

/** Exercises the product sheet and real chooser/service; only synthetic credentials and local fixtures are used. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35], qualifiers = "w360dp-h800dp")
class ServerWebAppActionTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private var localOpens = 0
    private val sessionField = AccountSessions::class.java.getDeclaredField("instance").apply { isAccessible = true }
    private var previousSessions: Any? = null

    @Before fun admitSyntheticLease() {
        previousSessions = sessionField.get(null)
        // Robolectric does not grant the library test package's merged signature permission.
        // Keep the product receiver private while allowing its actual registration in this fixture.
        Shadows.shadowOf(compose.activity.application).grantPermissions(
            "${compose.activity.application.packageName}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
        )
        // A valid lease ensures the encrypted-path case reaches the real database boundary,
        // rather than passing because credentials are absent. No network credentials are stored.
        sessionField.set(null, AccountSessions(LeaseCredentials()))
    }

    @After fun restoreSessions() {
        sessionField.set(null, previousSessions)
    }

    @Test fun `file actions distinguish local opening from server chooser and missing account is denied`() {
        val file = resource()
        var state by mutableStateOf(FileBrowserUiState(resources = listOf(file)))
        compose.setContent {
            Browser("account", state, { state = state.copy(actionResource = it) }, {
                state = state.copy(actionResource = null)
            })
        }
        compose.onNodeWithContentDescription("Actions for note.txt").performClick()
        compose.onNodeWithText("Open with").assertIsDisplayed().performClick()
        compose.runOnIdle { assertEquals(1, localOpens) }
        compose.onNodeWithContentDescription("Actions for note.txt").performClick()
        compose.onNodeWithText("Open in web app").assertIsDisplayed().performClick()
        compose.onNodeWithText("This opens the server file.", substring = true).assertIsDisplayed()
        // Real service refuses the missing/removed account before any provider request.
        compose.waitUntil(5_000) {
            compose
                .onAllNodes(
                    androidx.compose.ui.test
                        .hasText("Access was denied."),
                ).fetchSemanticsNodes()
                .isNotEmpty()
        }
        compose.onNodeWithText("Access was denied.").assertIsDisplayed()
        compose.onNodeWithText("No compatible web apps are available on this server.").assertDoesNotExist()
        compose.runOnIdle { assertEquals(1, localOpens) }
        compose.onNodeWithText("Close").performClick()
        compose.onNodeWithText("This opens the server file.", substring = true).assertDoesNotExist()
    }

    @Test fun `stale ordinary file inside encrypted path reaches vault denial rather than provider launch`() {
        val file = resource().copy(path = "/vault/note.txt")
        val database = FileBrowserDatabase.create(compose.activity)
        runBlocking {
            database.accountDao().upsert(
                AccountEntity("account", "https://synthetic.invalid", "user", "User", "BASIC", false),
            )
            database.spaceDao().upsertAll(
                listOf(SpaceEntity("account", "space", "Personal", "personal", null, null, "root", null, null, null)),
            )
            database.resourceDao().upsert(file)
            database.vaultExclusionDao().record(VaultExclusion("account", "space", "/vault"))
        }
        // Assert the exact service boundary before checking its sanitized UI presentation.
        // Missing credentials/provider failures must not satisfy this regression.
        val rejection =
            assertThrows(IllegalStateException::class.java) {
                runBlocking { ServerWebApps(compose.activity).choices(file) }
            }
        assertEquals("Encrypted vault locations are unavailable.", rejection.message)
        var state by mutableStateOf(FileBrowserUiState(actionResource = file))
        compose.setContent { Browser("account", state, {}, { state = state.copy(actionResource = null) }) }
        compose.onNodeWithText("Open in web app").performClick()
        compose.waitUntil(5_000) {
            compose
                .onAllNodes(
                    androidx.compose.ui.test
                        .hasText("The operation could not be completed."),
                ).fetchSemanticsNodes()
                .isNotEmpty()
        }
        compose.onNodeWithText("The operation could not be completed.").assertIsDisplayed()
        compose.runOnIdle { assertEquals(0, localOpens) }
    }

    @Test fun `account switch clears server chooser and stale other-account or folder menus cannot reopen it`() {
        val file = resource()
        var account by mutableStateOf("account")
        var state by mutableStateOf(FileBrowserUiState(actionResource = file))
        compose.setContent { Browser(account, state, {}, { state = state.copy(actionResource = null) }) }
        compose.onNodeWithText("Open in web app").performClick()
        compose.onNodeWithText("This opens the server file.", substring = true).assertIsDisplayed()
        compose.runOnIdle {
            account = "other-account"
            state = state.copy(actionResource = file)
        }
        compose.onNodeWithText("This opens the server file.", substring = true).assertDoesNotExist()
        compose.onNodeWithText("Open in web app").assertDoesNotExist()
        compose.runOnIdle {
            account = "account"
            state = state.copy(actionResource = file.copy(kind = ResourceKind.FOLDER))
        }
        compose.onNodeWithText("Open in web app").assertDoesNotExist()
    }

    @Composable
    @Suppress("LongMethod") // Explicit callbacks keep this fixture on the actual browser action wiring.
    private fun Browser(
        account: String,
        state: FileBrowserUiState,
        onActions: (ResourceEntity) -> Unit,
        onDismiss: () -> Unit,
    ) = OpenCloudTheme {
        FileBrowserScreen(
            accountId = account,
            releaseVersion = "test",
            state = state,
            onSelectSpace = {},
            onOpen = {},
            onOpenWith = { localOpens++ },
            onNavigateUp = {},
            onSetLayout = {},
            onToggleSelection = {},
            onClearSelection = {},
            onDownloadSelection = {},
            onDeleteSelection = {},
            onShowActions = { it?.let(onActions) },
            onDismissActions = onDismiss,
            onCreateFolder = {},
            onCreateSpace = {},
            onRename = { _, _ -> },
            onMove = {},
            onCopy = {},
            onDelete = {},
            onUpload = {},
            onDownloadForOffline = {},
            onToggleFavorite = {},
            onResolveConflict = { _, _ -> },
            onClearMessage = {},
            onSearchQueryChange = {},
            onOpenTransfers = {},
            onOpenDeletedFiles = {},
            onOpenSettings = {},
            onOpenAccount = {},
            onShareResource = {},
        )
    }

    private class LeaseCredentials : CredentialStore {
        override fun readBasicUsername(accountId: String): String = "synthetic"

        override fun readBasicPassword(accountId: String): String = "synthetic"

        override fun readTokens(accountId: String): AuthTokens? = null

        override fun saveBasicUsername(
            accountId: String,
            username: String,
        ): Unit = error("Read-only fixture")

        override fun saveBasicPassword(
            accountId: String,
            password: String,
        ): Unit = error("Read-only fixture")

        override fun saveTokens(
            accountId: String,
            tokens: AuthTokens,
        ): Unit = error("Read-only fixture")

        override fun remove(accountId: String): Unit = error("Read-only fixture")
    }

    private fun resource() =
        ResourceEntity(
            "account",
            "space",
            "file",
            null,
            "/note.txt",
            "note.txt",
            ResourceKind.FILE,
            "text/plain",
            1,
            "tag",
            1,
            1,
        )
}
