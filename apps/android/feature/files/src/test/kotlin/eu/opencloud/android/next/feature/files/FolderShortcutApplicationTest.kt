package eu.opencloud.android.next.feature.files

import androidx.activity.ComponentActivity
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35])
class FolderShortcutApplicationTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun waitsForSpacesAndRejectsReplacedRequestBeforeNavigationOrAcknowledgement() {
        var spaces by mutableStateOf(emptyList<SpaceEntity>())
        var visibleId by mutableLongStateOf(1L)
        var admittedId = 1L
        val applied = mutableListOf<Long>()
        val resource =
            ResourceEntity(
                "account",
                "space",
                "folder",
                null,
                "/folder",
                "folder",
                ResourceKind.FOLDER,
                null,
                0,
                null,
                0,
                0,
            )
        compose.setContent {
            val id = visibleId
            val application = remember(id) { FolderShortcutApplication({ admittedId == id }) { applied += id } }
            ApplyFolderShortcut(resource, spaces, "account", application)
        }
        compose.runOnIdle {
            assertEquals(emptyList<Long>(), applied)
            // The host has admitted B while this composition still presents resolved A.
            admittedId = 2L
            spaces =
                listOf(SpaceEntity("account", "space", "Personal", "personal", null, null, "root", null, null, null))
        }
        compose.runOnIdle {
            assertEquals(emptyList<Long>(), applied)
            // B resolves to the same resource; its distinct ID must still trigger application.
            visibleId = 2L
        }
        compose.runOnIdle { assertEquals(listOf(2L), applied) }
    }
}
