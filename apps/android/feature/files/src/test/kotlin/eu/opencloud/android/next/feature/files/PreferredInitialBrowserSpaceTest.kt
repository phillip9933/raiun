package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.SpaceEntity
import org.junit.Assert.assertEquals
import org.junit.Test

class PreferredInitialBrowserSpaceTest {
    @Test
    fun prefersPersonalWhenProjectSpaceWasPersistedFirst() {
        val project = space("project-drive", "project")
        val personal = space("personal-drive", "personal")

        assertEquals(personal, preferredInitialBrowserSpace(listOf(project, personal)))
    }

    @Test
    fun waitsForPersonalWhenOnlyProjectSpacesAreAvailable() {
        val project = space("project-drive", "project")

        assertEquals(null, preferredInitialBrowserSpace(listOf(project)))
    }

    private fun space(
        driveId: String,
        type: String,
    ) = SpaceEntity(
        accountId = "account",
        driveId = driveId,
        name = driveId,
        type = type,
        description = null,
        ownerName = null,
        rootId = "root-$driveId",
        rootWebDavUrl = null,
        rootETag = null,
        quotaBytes = null,
    )
}
