package eu.opencloud.android.next.core.sync

import androidx.work.NetworkType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BackupExecutionPolicyTest {
    @Test
    fun `debug backup also honors persisted charging and unmetered requirements`() {
        assertFalse(
            BackupExecutionPolicy.canRun(
                debug = true,
                wifiOnly = true,
                chargingOnly = true,
                unmetered = false,
                charging = false,
            ),
        )
    }

    @Test
    fun `release backup honors persisted charging and unmetered requirements`() {
        assertFalse(
            BackupExecutionPolicy.canRun(
                debug = false,
                wifiOnly = true,
                chargingOnly = true,
                unmetered = false,
                charging = false,
            ),
        )
    }

    @Test
    fun `debug work request has no strict backup constraints`() {
        val constraints = backupConstraints(debug = true)
        assertEquals(NetworkType.NOT_REQUIRED, constraints.requiredNetworkType)
        assertFalse(constraints.requiresCharging())
    }

    @Test
    fun `release scanner does not impose charging or wifi on unrestricted pairs`() {
        val constraints = backupConstraints(debug = false)
        assertEquals(NetworkType.NOT_REQUIRED, constraints.requiredNetworkType)
        assertFalse(constraints.requiresCharging())
    }

    @Test fun `unrestricted release pair runs without charging or unmetered connection`() {
        assertTrue(BackupExecutionPolicy.canRun(false, false, false, false, false))
        assertTrue(BackupExecutionPolicy.canRun(false, true, false, true, false))
        assertFalse(BackupExecutionPolicy.canRun(false, false, true, true, false))
    }
}
