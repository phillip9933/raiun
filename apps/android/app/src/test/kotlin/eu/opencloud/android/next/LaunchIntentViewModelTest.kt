package eu.opencloud.android.next

import android.content.Intent
import android.os.Bundle
import android.os.Parcel
import androidx.activity.ComponentActivity
import androidx.core.net.toUri
import androidx.lifecycle.ViewModelProvider
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35])
class LaunchIntentViewModelTest {
    @Test fun unprocessedCallbackSurvivesRecreationWithoutEnteringSavedState() {
        val controller = Robolectric.buildActivity(ComponentActivity::class.java, callback()).setup()
        try {
            val first = ViewModelProvider(controller.get())[LaunchIntentViewModel::class.java]
            first.acceptInitial(controller.get().intent)
            val request = requireNotNull(first.pending)
            val saved = Bundle()
            controller.saveInstanceState(saved)
            val parcel = Parcel.obtain()
            try {
                saved.writeToParcel(parcel, 0)
                assertFalse(String(parcel.marshall(), Charsets.UTF_16LE).contains("synthetic-secret-code"))
                assertFalse(String(parcel.marshall(), Charsets.UTF_16LE).contains("synthetic-state"))
            } finally {
                parcel.recycle()
            }
            controller.recreate()
            val recreated = ViewModelProvider(controller.get())[LaunchIntentViewModel::class.java]
            recreated.acceptInitial(controller.get().intent)
            assertSame(first, recreated)
            assertSame(request, recreated.pending)
            assertTrue(controller.get().consumeLaunchRequest(recreated, request.id))
            assertNull(controller.get().intent.data)
            controller.recreate()
            val consumed = ViewModelProvider(controller.get())[LaunchIntentViewModel::class.java]
            consumed.acceptInitial(callback())
            assertNull(consumed.pending)
        } finally {
            controller.pause().stop().destroy()
        }
    }

    @Test fun launcherAndHistoryCannotErasePendingAndFreshProcessStillAdmitsRawIntent() {
        val owner = LaunchIntentViewModel()
        owner.acceptInitial(callback())
        val pending = owner.pending
        assertFalse(owner.acceptNew(Intent(Intent.ACTION_MAIN)))
        assertFalse(owner.acceptNew(callback().addFlags(Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY)))
        owner.acceptInitial(Intent(Intent.ACTION_MAIN))
        assertSame(pending, owner.pending)
        val freshProcess = LaunchIntentViewModel()
        freshProcess.acceptInitial(callback())
        assertEquals(callback().dataString, freshProcess.pending?.uri)
        val historicalProcess = LaunchIntentViewModel()
        historicalProcess.acceptInitial(callback().addFlags(Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY))
        assertNull(historicalProcess.pending)
    }

    @Test fun freshOwnerRejectsOnlyConsumedSnapshotAndGenuineSameUriPendingAdmissionClearsMarker() {
        val owner = LaunchIntentViewModel()
        owner.acceptInitial(callback())
        owner.consume(requireNotNull(owner.pending).id)
        val saved = Bundle()
        owner.saveReplayMarker(saved)
        val parcel = Parcel.obtain()
        try {
            saved.writeToParcel(parcel, 0)
            val serialized = String(parcel.marshall(), Charsets.UTF_16LE)
            assertFalse(serialized.contains("synthetic-secret-code"))
            assertFalse(serialized.contains("synthetic-state"))
            assertFalse(serialized.contains("app.raiun.cloud://oauth"))
        } finally {
            parcel.recycle()
        }
        val consumedProcess = LaunchIntentViewModel()
        consumedProcess.acceptInitial(callback(), saved)
        assertNull(consumedProcess.pending)
        val differentCallback = Intent(Intent.ACTION_VIEW, "app.raiun.cloud://oauth?code=new&state=new".toUri())
        val newerProcess = LaunchIntentViewModel()
        newerProcess.acceptInitial(differentCallback, saved)
        assertEquals(differentCallback.dataString, newerProcess.pending?.uri)
        // A true new delivery with identical data invalidates the previous consumed marker.
        assertTrue(owner.acceptNew(callback()))
        owner.saveReplayMarker(saved)
        val pendingProcess = LaunchIntentViewModel()
        pendingProcess.acceptInitial(callback(), saved)
        assertEquals(callback().dataString, pendingProcess.pending?.uri)
        assertFalse(pendingProcess.acceptNew(Intent(Intent.ACTION_MAIN)))
        assertFalse(pendingProcess.acceptNew(callback().addFlags(Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY)))
        assertEquals(callback().dataString, pendingProcess.pending?.uri)
    }

    @Test fun oldAcknowledgementCannotClearNewerSameUriOrActivityIntent() {
        val controller = Robolectric.buildActivity(ComponentActivity::class.java, callback()).setup()
        try {
            val owner = LaunchIntentViewModel()
            owner.acceptInitial(controller.get().intent)
            val first = requireNotNull(owner.pending)
            assertTrue(owner.acceptNew(callback()))
            controller.get().intent = callback()
            val second = requireNotNull(owner.pending)
            assertTrue(first.id != second.id)
            assertFalse(controller.get().consumeLaunchRequest(owner, first.id))
            assertSame(second, owner.pending)
            assertEquals(callback().dataString, controller.get().intent.dataString)
            assertTrue(controller.get().consumeLaunchRequest(owner, second.id))
            assertNull(controller.get().intent.data)
            assertFalse(controller.get().consumeLaunchRequest(owner, second.id))
        } finally {
            controller.pause().stop().destroy()
        }
    }

    @Test fun malformedReplayMarkerLengthsAndTypesDoNotSuppressOrPersistPendingCallback() {
        val saltKey = "launch-consumed-salt-v1"
        val digestKey = "launch-consumed-digest-v1"
        val consumed = LaunchIntentViewModel()
        consumed.acceptInitial(callback())
        consumed.consume(requireNotNull(consumed.pending).id)
        val valid = Bundle().also(consumed::saveReplayMarker)
        val malformed =
            listOf(
                Bundle(valid).apply { remove(saltKey) },
                Bundle(valid).apply { remove(digestKey) },
                Bundle(valid).apply { putByteArray(saltKey, ByteArray(0)) },
                Bundle(valid).apply { putByteArray(saltKey, ByteArray(31)) },
                Bundle(valid).apply { putByteArray(saltKey, ByteArray(33)) },
                Bundle(valid).apply { putByteArray(digestKey, ByteArray(0)) },
                Bundle(valid).apply { putByteArray(digestKey, ByteArray(31)) },
                Bundle(valid).apply { putByteArray(digestKey, ByteArray(33)) },
                Bundle(valid).apply { putString(saltKey, requireNotNull(callback().dataString)) },
                Bundle(valid).apply { putString(digestKey, requireNotNull(callback().dataString)) },
                Bundle(valid).apply { putLong(saltKey, 32L) },
                Bundle(valid).apply { putStringArray(digestKey, arrayOf("synthetic-secret-code", "synthetic-state")) },
            )
        malformed.forEachIndexed { index, saved ->
            val fresh = LaunchIntentViewModel()
            fresh.acceptInitial(callback(), saved)
            assertEquals("Malformed marker case $index", callback().dataString, fresh.pending?.uri)
            fresh.saveReplayMarker(saved)
            // Saving an unconsumed admission removes even malformed marker payloads.
            assertEquals("Malformed marker case $index", 0, saved.size())
            val parcel = Parcel.obtain()
            try {
                saved.writeToParcel(parcel, 0)
                val serialized = String(parcel.marshall(), Charsets.UTF_16LE)
                assertFalse(serialized.contains("synthetic-secret-code"))
                assertFalse(serialized.contains("synthetic-state"))
                assertFalse(serialized.contains("app.raiun.cloud://oauth"))
            } finally {
                parcel.recycle()
            }
        }
    }

    @Test fun resolvedButUnappliedFolderSurvivesRecreationAndRejectsLateOldResults() {
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup()
        try {
            val owner = ViewModelProvider(controller.get())[LaunchIntentViewModel::class.java]
            owner.acceptInitial(folder("first"))
            val first = requireNotNull(owner.pending)
            owner.openFolder(first.id, resource("first"))
            val navigation = owner.folderNavigation
            controller.recreate()
            val recreated = ViewModelProvider(controller.get())[LaunchIntentViewModel::class.java]
            recreated.acceptInitial(folder("first"))
            assertSame(navigation, recreated.folderNavigation)
            assertSame(first, recreated.pending)
            assertFalse(recreated.acceptNew(Intent(Intent.ACTION_MAIN)))
            assertSame(navigation, recreated.folderNavigation)
            recreated.acceptNew(folder("second"))
            val second = requireNotNull(recreated.pending)
            assertNull(recreated.folderNavigation)
            recreated.openFolder(first.id, resource("first"))
            assertNull(recreated.folderNavigation)
            recreated.openFolder(second.id, resource("second"))
            assertFalse(recreated.consume(first.id))
            assertEquals("second", recreated.folderNavigation?.resource?.remoteId)
            assertTrue(recreated.consume(second.id))
            assertNull(recreated.folderNavigation)
        } finally {
            controller.pause().stop().destroy()
        }
    }

    private fun callback() =
        Intent(Intent.ACTION_VIEW, "app.raiun.cloud://oauth?code=synthetic-secret-code&state=synthetic-state".toUri())

    private fun folder(id: String) = Intent(Intent.ACTION_VIEW, "raiun-folder://folder/v1/account/space/$id".toUri())

    private fun resource(id: String) =
        ResourceEntity("account", "space", id, null, "/$id", id, ResourceKind.FOLDER, null, 0, null, 0, 0)
}
