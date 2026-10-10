package eu.opencloud.android.next.feature.files

import android.net.Uri
import androidx.work.Configuration
import androidx.work.WorkManager
import eu.opencloud.android.next.core.sync.IncomingShareStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
class IncomingUploadViewModelTest {
    @Test fun loadingUnconfirmedShareDoesNotOpenProviderOrStageBytes() =
        runBlocking {
            val context = RuntimeEnvironment.getApplication()
            WorkManager.initialize(context, Configuration.Builder().build())
            val batch = UUID.randomUUID().toString()
            val viewModel = IncomingUploadViewModel(context)
            viewModel.load(batch, listOf(Uri.parse("content://unregistered.test/source")))

            val state = withTimeout(5_000) { viewModel.state.first { !it.busy } }
            assertEquals(1, state.sourceCount)
            assertTrue(state.files.isEmpty())
            assertFalse(IncomingShareStore(context).isStaged(batch))
        }
}
