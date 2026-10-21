package eu.opencloud.android.next.core.designsystem

import android.content.Context
import androidx.annotation.PluralsRes
import androidx.annotation.StringRes
import androidx.core.content.ContextCompat

/** Includes the saved app-language override when called with an application context on Android 12 or older. */
fun Context.localizedString(
    @StringRes id: Int,
    vararg arguments: Any,
): String = ContextCompat.getContextForLanguage(this).getString(id, *arguments)

fun Context.localizedQuantityString(
    @PluralsRes id: Int,
    count: Int,
    vararg arguments: Any,
): String = ContextCompat.getContextForLanguage(this).resources.getQuantityString(id, count, *arguments)
