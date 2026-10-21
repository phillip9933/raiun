package eu.opencloud.android.next.core.datastore

import android.content.Context
import androidx.datastore.core.CorruptionException
import androidx.datastore.core.DataStore
import androidx.datastore.core.DataStoreFactory
import androidx.datastore.core.Serializer
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.dataStoreFile
import com.google.protobuf.InvalidProtocolBufferException
import eu.opencloud.android.next.core.datastore.proto.AppSettings
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import java.io.InputStream
import java.io.OutputStream
import kotlin.coroutines.cancellation.CancellationException

enum class SettingsBrowserLayout { DEFAULT_TABLE, CONDENSED_TABLE, TILES }

enum class Appearance { SYSTEM, LIGHT, DARK }

data class UserSettings(
    val browserLayout: SettingsBrowserLayout = SettingsBrowserLayout.DEFAULT_TABLE,
    val activeAccountId: String? = null,
    val cacheRetentionDays: Int = DEFAULT_CACHE_RETENTION_DAYS,
    val localDiagnosticsEnabled: Boolean = false,
    val appearance: Appearance = Appearance.SYSTEM,
    val temporaryCopyRetentionHours: Int = 0,
    val fileDisplay: FileDisplayOptions = FileDisplayOptions(),
    val fileOpening: FileOpening = FileOpening(),
    val pinnedNavigationItems: List<NavigationItem> = DEFAULT_PINNED_NAVIGATION_ITEMS,
)

class SettingsRepository private constructor(
    private val dataStore: DataStore<AppSettings>,
    private val context: Context? = null,
) {
    val settings: Flow<UserSettings> =
        dataStore.data
            .catch {
                if (it is CancellationException) throw it
                emit(
                    AppSettings.getDefaultInstance(),
                )
            }.map(AppSettings::validated)
            .distinctUntilChanged()

    suspend fun setBrowserLayout(layout: SettingsBrowserLayout) =
        update {
            it.toBuilder().setBrowserLayout(layout.toProto()).build()
        }

    suspend fun setActiveAccountId(accountId: String?) =
        update {
            it.toBuilder().setActiveAccountId(accountId?.trim().orEmpty()).build()
        }

    suspend fun setCacheRetentionDays(days: Int) =
        update {
            it.toBuilder().setCacheRetentionDays(days.coerceIn(MIN_CACHE_DAYS, MAX_CACHE_DAYS)).build()
        }

    suspend fun setTemporaryCopyRetentionHours(hours: Int) =
        update {
            require(hours in listOf(0, 1, 12, 24, 720))
            it.toBuilder().setTemporaryCopyRetentionHours(hours).build()
        }

    suspend fun setFileDisplay(options: FileDisplayOptions) =
        update {
            it
                .toBuilder()
                .setHideFileSize(!options.showSize)
                .setHideModifiedDate(!options.showModified)
                .setHideFileExtensions(!options.showExtensions)
                .setShowHiddenFiles(options.showHidden)
                .build()
        }

    suspend fun setLocalDiagnosticsEnabled(enabled: Boolean) =
        update { it.toBuilder().setLocalDiagnosticsEnabled(enabled).build() }

    suspend fun setFileOpening(options: FileOpening) =
        update {
            it
                .toBuilder()
                .setExternalText(options.externalText)
                .setExternalPdf(options.externalPdf)
                .setExternalImages(options.externalImages)
                .build()
        }

    suspend fun setPinnedNavigationItems(items: List<NavigationItem>) =
        update {
            it
                .toBuilder()
                .clearPinnedNavigationItems()
                .addAllPinnedNavigationItems(normalizePinnedNavigationItems(items).map { item -> item.name })
                .build()
        }

    suspend fun setAppearance(appearance: Appearance) {
        update { it.toBuilder().setAppearance(AppSettings.Appearance.valueOf(appearance.name)).build() }
        context
            ?.getSharedPreferences("window-appearance", Context.MODE_PRIVATE)
            ?.edit()
            ?.putString("appearance", appearance.name)
            ?.apply()
    }

    private suspend fun update(transform: (AppSettings) -> AppSettings) {
        dataStore.updateData { transform(it.repaired()) }
    }

    companion object {
        @Volatile private var instance: SettingsRepository? = null

        fun create(context: Context): SettingsRepository =
            instance ?: synchronized(this) {
                instance ?: SettingsRepository(
                    context = context.applicationContext,
                    dataStore =
                        DataStoreFactory.create(
                            serializer = AppSettingsSerializer,
                            corruptionHandler = ReplaceFileCorruptionHandler { AppSettings.getDefaultInstance() },
                            produceFile = { context.applicationContext.dataStoreFile("opencloud-settings.pb") },
                        ),
                ).also { instance = it }
            }

        internal fun create(dataStore: DataStore<AppSettings>) = SettingsRepository(dataStore)
    }
}

internal object AppSettingsSerializer : Serializer<AppSettings> {
    override val defaultValue: AppSettings = AppSettings.getDefaultInstance()

    override suspend fun readFrom(input: InputStream): AppSettings =
        try {
            AppSettings.parseFrom(input)
        } catch (exception: InvalidProtocolBufferException) {
            throw CorruptionException("The settings file is not valid protobuf.", exception)
        }

    override suspend fun writeTo(
        t: AppSettings,
        output: OutputStream,
    ) = t.writeTo(output)
}

private fun AppSettings.validated() =
    UserSettings(
        pinnedNavigationItems =
            normalizePinnedNavigationItems(
                pinnedNavigationItemsList.mapNotNull { name -> NavigationItem.entries.firstOrNull { it.name == name } },
            ),
        browserLayout = browserLayout.toDomain(),
        activeAccountId = activeAccountId.trim().takeIf(String::isNotBlank),
        localDiagnosticsEnabled = localDiagnosticsEnabled,
        fileDisplay = FileDisplayOptions(!hideFileSize, !hideModifiedDate, !hideFileExtensions, showHiddenFiles),
        fileOpening = FileOpening(externalText, externalPdf, externalImages),
        temporaryCopyRetentionHours = temporaryCopyRetentionHours.takeIf { it in listOf(0, 1, 12, 24, 720) } ?: 0,
        appearance = Appearance.entries.firstOrNull { it.name == appearance.name } ?: Appearance.SYSTEM,
        cacheRetentionDays =
            cacheRetentionDays.takeIf { it in MIN_CACHE_DAYS..MAX_CACHE_DAYS } ?: DEFAULT_CACHE_RETENTION_DAYS,
    )

private fun AppSettings.repaired(): AppSettings {
    val valid = validated()
    return toBuilder()
        .setBrowserLayout(
            valid.browserLayout.toProto(),
        ).setActiveAccountId(valid.activeAccountId.orEmpty())
        .setCacheRetentionDays(valid.cacheRetentionDays)
        .build()
}

private fun AppSettings.BrowserLayout.toDomain() =
    when (this) {
        AppSettings.BrowserLayout.CONDENSED_TABLE -> SettingsBrowserLayout.CONDENSED_TABLE
        AppSettings.BrowserLayout.TILES -> SettingsBrowserLayout.TILES
        else -> SettingsBrowserLayout.DEFAULT_TABLE
    }

private fun SettingsBrowserLayout.toProto() =
    when (this) {
        SettingsBrowserLayout.DEFAULT_TABLE -> AppSettings.BrowserLayout.DEFAULT_TABLE
        SettingsBrowserLayout.CONDENSED_TABLE -> AppSettings.BrowserLayout.CONDENSED_TABLE
        SettingsBrowserLayout.TILES -> AppSettings.BrowserLayout.TILES
    }

const val DEFAULT_CACHE_RETENTION_DAYS = 30
private const val MIN_CACHE_DAYS = 1
private const val MAX_CACHE_DAYS = 365
