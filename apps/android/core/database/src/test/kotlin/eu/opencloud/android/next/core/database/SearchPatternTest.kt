package eu.opencloud.android.next.core.database

import org.junit.Assert.assertEquals
import org.junit.Test

class SearchPatternTest {
    @Test fun `like pattern escapes wildcard characters`() {
        assertEquals("%100\\%\\_done\\\\today%", "100%_done\\today".toLikePattern())
    }
}
