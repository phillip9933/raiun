package eu.opencloud.android.next.feature.files

import androidx.work.WorkInfo
import org.junit.Assert.assertEquals
import org.junit.Test

class FavoritesSyncStatusTest {
    @Test fun `partial unknown and failed scans stay distinct from completion`() {
        assertEquals(FavoritesSyncStatus.RUNNING, favoriteSyncStatus(WorkInfo.State.ENQUEUED, 0))
        assertEquals(FavoritesSyncStatus.RUNNING, favoriteSyncStatus(WorkInfo.State.RUNNING, 12))
        assertEquals(FavoritesSyncStatus.MORE, favoriteSyncStatus(WorkInfo.State.SUCCEEDED, 12))
        assertEquals(FavoritesSyncStatus.UNAVAILABLE, favoriteSyncStatus(WorkInfo.State.SUCCEEDED, -1))
        assertEquals(FavoritesSyncStatus.FAILED, favoriteSyncStatus(WorkInfo.State.FAILED, 0))
        assertEquals(FavoritesSyncStatus.IDLE, favoriteSyncStatus(WorkInfo.State.SUCCEEDED, 0))
        assertEquals(FavoritesSyncStatus.IDLE, favoriteSyncStatus(WorkInfo.State.CANCELLED, 12))
    }
}
