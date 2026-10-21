package eu.opencloud.android.next.ui

import org.junit.Assert.assertEquals
import org.junit.Test

class VaultPickerLeaseTest {
    @Test fun onlyExplicitPickerGetsABoundedNonExtendingLease() {
        var now = 10L
        val lease = VaultPickerLease { now }
        assertEquals(0L, lease.remainingMillis())
        lease.arm()
        assertEquals(120_000L, lease.remainingMillis())
        now += 30_000
        assertEquals(90_000L, lease.remainingMillis())
        now += 90_000
        assertEquals(0L, lease.remainingMillis())
        now += 10
        assertEquals(0L, lease.remainingMillis())
        lease.arm()
        lease.clear()
        assertEquals(0L, lease.remainingMillis())
    }
}
