package eu.opencloud.android.next

import android.app.Activity
import android.app.ActivityManager
import android.content.res.Configuration
import android.graphics.drawable.ColorDrawable
import android.os.Build

/** A synchronous theme mirror is needed before onCreate, including the private picker-unlock activity. */
internal fun Activity.applyStoredWindowTheme(): Boolean {
    val appearance =
        getSharedPreferences(
            "window-appearance",
            android.content.Context.MODE_PRIVATE,
        ).getString("appearance", "SYSTEM")
    val dark =
        when (appearance) {
            "DARK" -> true
            "LIGHT" -> false
            else ->
                resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK ==
                    Configuration.UI_MODE_NIGHT_YES
        }
    setTheme(if (dark) R.style.OpenCloudWindowDark else R.style.OpenCloudWindowLight)
    return dark
}

internal fun Activity.updateTaskBackground(
    dark: Boolean,
    color: Int,
) {
    setTheme(if (dark) R.style.OpenCloudWindowDark else R.style.OpenCloudWindowLight)
    window.setBackgroundDrawable(ColorDrawable(color))
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        setTaskDescription(
            ActivityManager.TaskDescription
                .Builder()
                .setLabel(
                    "Raiun",
                ).setIcon(R.mipmap.ic_launcher)
                .setPrimaryColor(color)
                .setBackgroundColor(color)
                .build(),
        )
    }
}

/** Restore our task colors after Android's credential activity temporarily owns the task. */
internal fun Activity.restoreStoredTaskAppearance() {
    val dark = applyStoredWindowTheme()
    val background = android.util.TypedValue()
    if (theme.resolveAttribute(android.R.attr.colorBackground, background, true)) {
        updateTaskBackground(dark, background.data)
    }
}
