package eu.opencloud.android.next

import android.app.Activity
import android.content.Context
import android.graphics.Color
import android.util.TypedValue
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class WindowAppearanceTest {
    @Test fun darkSecureTaskUsesAnOpaqueDarkBackground() {
        val controller = Robolectric.buildActivity(Activity::class.java).setup()
        val activity = controller.get()
        try {
            val dark = Color.rgb(16, 20, 22)
            activity.updateTaskBackground(true, dark)
            activity
                .getSharedPreferences(
                    "window-appearance",
                    Context.MODE_PRIVATE,
                ).edit()
                .putString("appearance", "DARK")
                .commit()
            activity.applyStoredWindowTheme()
            val value = TypedValue()
            activity.theme.resolveAttribute(android.R.attr.colorBackground, value, true)
            assertEquals(dark, value.data)
        } finally {
            activity
                .getSharedPreferences("window-appearance", Context.MODE_PRIVATE)
                .edit()
                .clear()
                .commit()
            controller.pause().stop().destroy()
        }
    }
}
