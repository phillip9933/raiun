package eu.opencloud.android.next.feature.files

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertSame
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference

/** Real, distinct admission/IO threads exercise the same dispatch boundaries as the browser. */
internal class BrowserCommandTestFixture : AutoCloseable {
    private val mainThread = AtomicReference<Thread>()
    private val ioThread = AtomicReference<Thread>()
    val main =
        Executors
            .newSingleThreadExecutor { task -> Thread(task, "command-main").also { mainThread.set(it) } }
            .asCoroutineDispatcher()
    val io =
        Executors
            .newSingleThreadExecutor { task -> Thread(task, "command-io").also { ioThread.set(it) } }
            .asCoroutineDispatcher()
    val scope = CoroutineScope(SupervisorJob() + main)
    val context = BrowserAccountContext(main)
    val state = MutableStateFlow(FileBrowserUiState())

    fun reduce(transform: FileBrowserUiState.() -> FileBrowserUiState) {
        assertMain()
        state.value = state.value.transform()
    }

    fun assertMain() = assertSame(mainThread.get(), Thread.currentThread())

    fun assertIO() = assertSame(ioThread.get(), Thread.currentThread())

    suspend fun account(id: String) = onMain { state.value = state.value.forAccountLoad(context.beginAccount(id)) }

    suspend fun <T> onMain(action: () -> T): T = withContext(main) { action() }

    suspend fun jobs(): List<Job> = onMain { requireNotNull(scope.coroutineContext[Job]).children.toList() }

    suspend fun idle() {
        withTimeout(5000) { jobs().joinAll() }
    }

    override fun close() {
        scope.cancel()
        main.close()
        io.close()
    }
}
