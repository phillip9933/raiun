package eu.opencloud.android.next.core.datastore

import androidx.datastore.core.DataStore
import androidx.datastore.core.DataStoreFactory
import eu.opencloud.android.next.core.datastore.proto.AppSettings
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.File

@OptIn(ExperimentalCoroutinesApi::class)
class SettingsRepositoryTest {
    @Test fun `file opening preferences persist independently and default to preview`() =
        runTest {
            val dataStore = InMemoryDataStore()
            val repository = SettingsRepository.create(dataStore)
            assertEquals(FileOpening(), repository.settings.first().fileOpening)
            repository.setFileOpening(FileOpening(externalPdf = true))
            repository.setAppearance(Appearance.DARK)
            val reloaded =
                SettingsRepository
                    .create(dataStore)
                    .settings
                    .first()
                    .fileOpening
            assertEquals(true, reloaded.usesPreview(PreviewKind.TEXT))
            assertEquals(false, reloaded.usesPreview(PreviewKind.PDF))
            assertEquals(true, reloaded.usesPreview(PreviewKind.IMAGE))
            assertEquals(false, reloaded.usesPreview(null))
        }

    @Test fun `preview detection covers common server mime and filename variants`() {
        assertEquals(PreviewKind.TEXT, previewKind("notes", "text/plain; charset=utf-8"))
        assertEquals(PreviewKind.TEXT, previewKind("NOTES.MD", "application/octet-stream"))
        assertEquals(PreviewKind.PDF, previewKind("Scan.PDF", null))
        assertEquals(PreviewKind.IMAGE, previewKind("photo.HEIC", null))
        assertNull(previewKind("backup.zip", "application/zip"))
    }

    @Test fun `appearance survives unrelated settings and a repository reload`() =
        runTest {
            val dataStore = InMemoryDataStore()
            val repository = SettingsRepository.create(dataStore)
            assertEquals(Appearance.SYSTEM, repository.settings.first().appearance)
            repository.setAppearance(Appearance.DARK)
            repository.setCacheRetentionDays(7)
            assertEquals(
                Appearance.DARK,
                SettingsRepository
                    .create(dataStore)
                    .settings
                    .first()
                    .appearance,
            )
            repository.setAppearance(Appearance.LIGHT)
            assertEquals(Appearance.LIGHT, repository.settings.first().appearance)
        }

    @Test fun `invalid persisted values map to canonical defaults`() =
        runTest {
            val file = temporaryFile()
            file.outputStream().use {
                AppSettings
                    .newBuilder()
                    .setCacheRetentionDays(-10)
                    .setActiveAccountId("   ")
                    .build()
                    .writeTo(it)
            }
            val repository =
                SettingsRepository.create(
                    DataStoreFactory.create(
                        serializer = AppSettingsSerializer,
                        scope = backgroundScope,
                        produceFile = { file },
                    ),
                )
            val settings = repository.settings.first()
            assertEquals(SettingsBrowserLayout.DEFAULT_TABLE, settings.browserLayout)
            assertEquals(DEFAULT_CACHE_RETENTION_DAYS, settings.cacheRetentionDays)
            assertNull(settings.activeAccountId)
        }

    @Test fun `updates persist validated settings`() =
        runTest {
            val repository = SettingsRepository.create(InMemoryDataStore())
            repository.setBrowserLayout(SettingsBrowserLayout.TILES)
            repository.setActiveAccountId(" account-2 ")
            repository.setCacheRetentionDays(999)
            val settings = repository.settings.first()
            assertEquals(SettingsBrowserLayout.TILES, settings.browserLayout)
            assertEquals("account-2", settings.activeAccountId)
            assertEquals(365, settings.cacheRetentionDays)
        }

    @Test fun `diagnostics are opt in and unrelated settings preserve the choice`() =
        runTest {
            val repository = SettingsRepository.create(InMemoryDataStore())
            assertEquals(false, repository.settings.first().localDiagnosticsEnabled)
            repository.setLocalDiagnosticsEnabled(true)
            repository.setCacheRetentionDays(7)
            assertEquals(true, repository.settings.first().localDiagnosticsEnabled)
            repository.setLocalDiagnosticsEnabled(false)
            assertEquals(false, repository.settings.first().localDiagnosticsEnabled)
        }

    @Test fun `temporary copy cleanup is opt in and persists independently of orphan cleanup`() =
        runTest {
            val dataStore = InMemoryDataStore()
            val repository = SettingsRepository.create(dataStore)
            assertEquals(0, repository.settings.first().temporaryCopyRetentionHours)
            repository.setTemporaryCopyRetentionHours(12)
            repository.setCacheRetentionDays(7)
            repository.setAppearance(Appearance.DARK)
            assertEquals(
                12,
                SettingsRepository
                    .create(dataStore)
                    .settings
                    .first()
                    .temporaryCopyRetentionHours,
            )
            repository.setTemporaryCopyRetentionHours(0)
            assertEquals(0, repository.settings.first().temporaryCopyRetentionHours)
        }

    @Test fun `display options keep existing defaults and survive reload`() =
        runTest {
            val dataStore = InMemoryDataStore()
            val repository = SettingsRepository.create(dataStore)
            assertEquals(FileDisplayOptions(), repository.settings.first().fileDisplay)
            val changed = FileDisplayOptions(false, false, false, true)
            repository.setFileDisplay(changed)
            repository.setAppearance(Appearance.DARK)
            assertEquals(
                changed,
                SettingsRepository
                    .create(dataStore)
                    .settings
                    .first()
                    .fileDisplay,
            )
        }

    @Test fun `navigation pins survive unrelated updates and reload`() =
        runTest {
            val dataStore = InMemoryDataStore()
            val repository = SettingsRepository.create(dataStore)
            assertEquals(DEFAULT_PINNED_NAVIGATION_ITEMS, repository.settings.first().pinnedNavigationItems)
            val pins = listOf(NavigationItem.TRANSFERS, NavigationItem.PERSONAL, NavigationItem.OFFLINE)
            repository.setPinnedNavigationItems(pins)
            repository.setAppearance(Appearance.DARK)
            assertEquals(
                pins,
                SettingsRepository
                    .create(dataStore)
                    .settings
                    .first()
                    .pinnedNavigationItems,
            )
        }

    @Test fun `unknown stored navigation names fall back safely`() =
        runTest {
            val file = temporaryFile()
            file.outputStream().use {
                AppSettings
                    .newBuilder()
                    .addPinnedNavigationItems("FUTURE_ITEM")
                    .build()
                    .writeTo(it)
            }
            val repository =
                SettingsRepository.create(
                    DataStoreFactory.create(
                        serializer = AppSettingsSerializer,
                        scope = backgroundScope,
                        produceFile = { file },
                    ),
                )
            assertEquals(DEFAULT_PINNED_NAVIGATION_ITEMS, repository.settings.first().pinnedNavigationItems)
        }

    private fun temporaryFile(): File = File.createTempFile("opencloud-settings", ".pb").apply { delete() }

    private class InMemoryDataStore : DataStore<AppSettings> {
        private val state = MutableStateFlow(AppSettings.getDefaultInstance())
        override val data: Flow<AppSettings> = state

        override suspend fun updateData(transform: suspend (t: AppSettings) -> AppSettings): AppSettings =
            transform(state.value).also { state.value = it }
    }
}
