package eu.opencloud.android.next.core.designsystem.theme

import androidx.compose.ui.graphics.toArgb
import org.junit.Assert.assertEquals
import org.junit.Test

class OpenCloudColorTest {
    @Test
    fun `primary matches the extracted web token`() {
        assertEquals(0xFF00677F.toInt(), OpenCloudColor.Primary.toArgb())
    }

    @Test
    fun `surface container matches the extracted web token`() {
        assertEquals(0xFFF6F8FA.toInt(), OpenCloudColor.SurfaceContainer.toArgb())
    }
}
