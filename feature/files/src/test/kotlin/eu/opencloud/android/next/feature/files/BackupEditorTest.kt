package eu.opencloud.android.next.feature.files

import androidx.activity.ComponentActivity
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import eu.opencloud.android.next.core.database.FolderBackupEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class BackupEditorTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun choosingSourceDoesNotSaveUntilSaveIsPressed() {
        var sourceName by mutableStateOf<String?>(null)
        var pickerCalls = 0
        var saved: BackupDraft? = null
        compose.setContent {
            OpenCloudTheme {
                FolderBackupSettingsContent(
                    backups = emptyList(),
                    onDismiss = {},
                    onAdd = { saved = it },
                    onDelete = {},
                    sourceDisplayName = sourceName,
                    onChooseSource = { pickerCalls++ },
                )
            }
        }

        compose.onNodeWithText("Save").assertIsNotEnabled()
        compose.onNodeWithText("Choose source folder").performClick()
        assertEquals(1, pickerCalls)
        assertNull(saved)

        compose.runOnUiThread { sourceName = "Camera" }
        compose.onNodeWithText("Save").assertIsEnabled()
        compose.onNodeWithText("Save").performClick()
        assertEquals("/Camera Uploads", saved?.destinationPath)
        assertEquals("IMAGE", saved?.mediaType)
        assertEquals("NONE", saved?.dateOrganization)
    }

    @Test fun cancelDoesNotSubmitSelectedSource() {
        var dismissCalls = 0
        var saved: BackupDraft? = null
        compose.setContent {
            OpenCloudTheme {
                FolderBackupSettingsContent(
                    backups = emptyList(),
                    onDismiss = { dismissCalls++ },
                    onAdd = { saved = it },
                    onDelete = {},
                    sourceDisplayName = "Camera",
                )
            }
        }

        compose.onNodeWithText("Cancel").performClick()
        assertEquals(1, dismissCalls)
        assertNull(saved)
    }

    @Test fun dateOrganizationShowsCustomPatternAndPreviewWhenEditing() {
        var saved: BackupDraft? = null
        val backup =
            FolderBackupEntity(
                id = "backup",
                accountId = "account",
                spaceId = "personal",
                sourceTreeUri = "content://provider/tree/camera",
                sourceDisplayName = "Camera",
                destinationPath = "/Pictures",
                mediaType = "IMAGE",
                wifiOnly = true,
                chargingOnly = false,
                deleteAfterUpload = false,
                dateOrganization = "[DD]/[MMM]",
            )
        compose.setContent {
            OpenCloudTheme {
                FolderBackupSettingsContent(
                    backups = emptyList(),
                    onDismiss = {},
                    onAdd = { saved = it },
                    onDelete = {},
                    initialBackup = backup,
                )
            }
        }

        compose.onNodeWithText("Date folder pattern").assertExists()
        compose.onNodeWithText("Use [YYYY], [YY]", substring = true).performScrollTo().assertExists()
        compose.onNodeWithText("Save").performClick()
        assertEquals("[DD]/[MMM]", saved?.dateOrganization)
    }

    @Test fun editingExistingBackupSavesSettingsWithoutReplacingSource() {
        val backup =
            FolderBackupEntity(
                id = "backup",
                accountId = "account",
                spaceId = "personal",
                sourceTreeUri = "content://provider/tree/primary%3ADCIM",
                sourceDisplayName = "DCIM",
                destinationPath = "/Pictures",
                mediaType = "VIDEO",
                wifiOnly = false,
                chargingOnly = true,
                deleteAfterUpload = false,
            )
        var saved: BackupDraft? = null
        var sourcePickerCalls = 0
        compose.setContent {
            OpenCloudTheme {
                FolderBackupSettingsContent(
                    backups = emptyList(),
                    initialBackup = backup,
                    onDismiss = {},
                    onAdd = { saved = it },
                    onDelete = {},
                    onChooseSource = { sourcePickerCalls++ },
                )
            }
        }

        compose.onNodeWithText("DCIM").assertExists()
        compose.onNodeWithText("Choose source folder").assertDoesNotExist()
        compose.onNodeWithText("Save").performClick()
        assertEquals("/Pictures", saved?.destinationPath)
        assertEquals("VIDEO", saved?.mediaType)
        assertEquals(0, sourcePickerCalls)
        assertEquals("content://provider/tree/primary%3ADCIM", backup.sourceTreeUri)
    }

    @Test fun selectedSharedDestinationIsSavedOnlyAfterPickerConfirmation() {
        var picker by mutableStateOf(FileBrowserUiState())
        var saved: BackupDraft? = null
        compose.setContent {
            OpenCloudTheme {
                FolderBackupSettingsContent(
                    backups = emptyList(),
                    onDismiss = {},
                    onAdd = { saved = it },
                    onDelete = {},
                    sourceDisplayName = "Camera",
                    pickerState = picker,
                    defaultSpaceId = "personal-drive",
                    requireDestinationBinding = true,
                    onOpenPicker = {},
                    onOpenPickerShare = { root ->
                        picker =
                            picker.copy(
                                backupPickerDestination =
                                    BackupDestination(
                                        root.scopeId,
                                        "/",
                                        "SHARED_FOLDER",
                                        root.shareId,
                                        root.rootItemId,
                                        root.name,
                                    ),
                                backupPickerCanSelect = true,
                            )
                    },
                )
            }
        }
        compose.runOnUiThread {
            picker =
                picker.copy(
                    backupPickerSharedRoots =
                        listOf(
                            BackupSharedRoot("Team Photos", "share-1", "shared-folder:scope", "root-1"),
                        ),
                )
        }
        compose.onNodeWithText("Select folder").performClick()
        compose.onNodeWithText("Team Photos").performClick()
        compose.onNodeWithText("Select this folder").performClick()
        compose.onNodeWithText("Save").performClick()
        assertEquals("shared-folder:scope", saved?.spaceId)
        assertEquals("SHARED_FOLDER", saved?.destinationKind)
        assertEquals("share-1", saved?.sharedShareId)
        assertEquals("root-1", saved?.sharedFolderId)
    }

    @Test fun cancellingDestinationPickerKeepsExistingBinding() {
        val backup =
            FolderBackupEntity(
                id = "backup",
                accountId = "account",
                spaceId = "space-a",
                sourceTreeUri = "content://provider/tree/camera",
                sourceDisplayName = "Camera",
                destinationPath = "/Pictures",
                mediaType = "IMAGE",
                wifiOnly = true,
                chargingOnly = false,
                deleteAfterUpload = false,
            )
        var saved: BackupDraft? = null
        compose.setContent {
            OpenCloudTheme {
                FolderBackupSettingsContent(
                    backups = emptyList(),
                    initialBackup = backup,
                    onDismiss = {},
                    onAdd = { saved = it },
                    onDelete = {},
                    pickerState =
                        FileBrowserUiState(
                            spaces =
                                listOf(
                                    SpaceEntity(
                                        "account",
                                        "space-a",
                                        "Alpha",
                                        "project",
                                        null,
                                        null,
                                        "root",
                                        null,
                                        null,
                                        null,
                                    ),
                                ),
                        ),
                )
            }
        }
        compose.onNodeWithText("Select folder").performClick()
        compose.onAllNodesWithText("Cancel")[1].performClick()
        compose.onNodeWithText("Save").performClick()
        assertEquals("space-a", saved?.spaceId)
        assertEquals("/Pictures", saved?.destinationPath)
    }

    @Test fun ordinarySpaceSelectionSavesItsDriveInsteadOfBrowserDrive() {
        val target = SpaceEntity("account", "project-drive", "Project", "project", null, null, "root", null, null, null)
        var picker by mutableStateOf(FileBrowserUiState(spaces = listOf(target), spaceId = "other-browser-drive"))
        var saved: BackupDraft? = null
        compose.setContent {
            OpenCloudTheme {
                FolderBackupSettingsContent(
                    backups = emptyList(),
                    onDismiss = {},
                    onAdd = { saved = it },
                    onDelete = {},
                    sourceDisplayName = "Camera",
                    pickerState = picker,
                    requireDestinationBinding = true,
                    onOpenPickerSpace = { space ->
                        picker =
                            picker.copy(
                                backupPickerDestination =
                                    BackupDestination(
                                        space.driveId,
                                        "/",
                                        "SPACE",
                                        null,
                                        null,
                                        space.name,
                                    ),
                                backupPickerCanSelect = true,
                            )
                    },
                )
            }
        }
        compose.onNodeWithText("Select folder").performClick()
        compose.onNodeWithText("Project").performClick()
        compose.onNodeWithText("Select this folder").performClick()
        compose.onNodeWithText("Save").performClick()
        assertEquals("project-drive", saved?.spaceId)
        assertEquals("SPACE", saved?.destinationKind)
        assertNull(saved?.sharedShareId)
    }
}
