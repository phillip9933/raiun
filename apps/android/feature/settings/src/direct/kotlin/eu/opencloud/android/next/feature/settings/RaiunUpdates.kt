package eu.opencloud.android.next.feature.settings

import android.content.Context
import io.github.phillip9933.appupdater.UpdateConfig
import io.github.phillip9933.appupdater.UpdateManager

/** Raiun owns release naming and UI; the pinned library owns download/verification/install policy. */
object RaiunUpdates {
    const val PROJECT_URL = "https://github.com/phillip9933/raiun"

    private val config =
        UpdateConfig(
            owner = "phillip9933",
            repository = "raiun",
            tagPrefix = "android-v",
            assetPrefix = "raiun-android-",
            legacyVersions = setOf("0.9.3"),
            legacyAssetPrefix = "raiun-",
        )

    fun get(context: Context): UpdateManager = UpdateManager.get(context, config)

    /** Only configured Android tags can become a link; the version is never used as a raw URL. */
    fun installedReleaseUrl(versionName: String): String? {
        val version = versionName.removeSuffix("-debug")
        val tag = if (version == "0.9.3") "v$version" else "android-v$version"
        return tag.takeIf { config.versionFromTag(it) == version }?.let { "$PROJECT_URL/releases/tag/$it" }
    }
}
