package eu.opencloud.android.next.core.designsystem.theme

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.lerp
import eu.opencloud.android.next.core.model.AccountColor

/** Account identity markers; toolbar surfaces and normal controls retain the app theme. */
object AccountAccent {
    val onAccent = Color.White
    internal val palette = AccountColor.entries.map(::color)

    fun forAccount(
        accountId: String,
        choice: AccountColor? = null,
    ): Color = choice?.let(::color) ?: palette[Math.floorMod(accountId.hashCode(), palette.size)]

    fun indicator(
        accountId: String,
        dark: Boolean,
        choice: AccountColor? = null,
    ): Color {
        val seed = forAccount(accountId, choice)
        return if (dark) lerp(seed, Color.White, 0.35f) else seed
    }

    fun container(
        surface: Color,
        accountId: String,
        dark: Boolean,
        choice: AccountColor? = null,
    ): Color = lerp(surface, forAccount(accountId, choice), if (dark) 0.12f else 0.08f)

    private fun color(choice: AccountColor): Color =
        when (choice) {
            AccountColor.TEAL -> Color(0xFF00677F)
            AccountColor.JADE -> Color(0xFF267A68)
            AccountColor.PURPLE -> Color(0xFF7057A5)
            AccountColor.ROSE -> Color(0xFFA94F6D)
            AccountColor.AMBER -> Color(0xFF9A6416)
            AccountColor.BLUE -> Color(0xFF345B9E)
            AccountColor.FOREST -> Color(0xFF34634D)
            AccountColor.PLUM -> Color(0xFF843E75)
        }
}
