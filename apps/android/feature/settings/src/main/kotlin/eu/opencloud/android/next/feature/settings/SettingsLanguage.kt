package eu.opencloud.android.next.feature.settings

internal data class SettingsLanguage(
    val tag: String,
    val onSelect: (String) -> Unit,
)
