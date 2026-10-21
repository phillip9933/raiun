package eu.opencloud.android.next.core.sync

import android.content.Context
import androidx.concurrent.futures.CallbackToFutureAdapter
import androidx.work.Configuration
import androidx.work.ListenableWorker
import androidx.work.WorkInfo
import androidx.work.WorkManager
import androidx.work.WorkerFactory
import androidx.work.WorkerParameters
import androidx.work.testing.SynchronousExecutor
import androidx.work.testing.WorkManagerTestInitHelper
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.IOException

@RunWith(RobolectricTestRunner::class)
class SharedDownloadCleanupWorkerTest {
    @Test fun refreshDuringCleanupQueuesFollowUp() {
        val context = RuntimeEnvironment.getApplication()
        // Keep cleanup pending explicitly: this test exercises queue chaining, not coroutine dispatch.
        val pending = mutableListOf<CallbackToFutureAdapter.Completer<ListenableWorker.Result>>()
        val factory =
            object : WorkerFactory() {
                override fun createWorker(
                    appContext: Context,
                    workerClassName: String,
                    workerParameters: WorkerParameters,
                ): ListenableWorker =
                    object : ListenableWorker(appContext, workerParameters) {
                        override fun startWork() =
                            CallbackToFutureAdapter.getFuture<Result> { completer ->
                                pending.add(completer)
                                "Pending cleanup for queue chaining test"
                            }
                    }
            }
        WorkManagerTestInitHelper.initializeTestWorkManager(
            context,
            Configuration
                .Builder()
                .setExecutor(SynchronousExecutor())
                .setTaskExecutor(SynchronousExecutor())
                .setWorkerFactory(factory)
                .build(),
        )
        val manager = WorkManager.getInstance(context)
        try {
            scheduleSharedDownloadCleanup(context).result.get()
            scheduleSharedDownloadCleanup(context).result.get()
            val work = manager.getWorkInfosForUniqueWork("shared-download-cleanup").get()
            assertEquals(2, work.size)
            assertEquals(work.map { it.state }.toString(), 1, work.count { it.state == WorkInfo.State.BLOCKED })
            scheduleExcludedCacheCleanup(context).result.get()
            scheduleExcludedCacheCleanup(context).result.get()
            val excluded = manager.getWorkInfosForUniqueWork("excluded-cache-cleanup").get()
            assertEquals(2, excluded.size)
            assertEquals(1, excluded.count { it.state == WorkInfo.State.BLOCKED })
        } finally {
            manager.cancelAllWork().result.get()
            pending.forEach { it.setCancelled() }
            WorkManagerTestInitHelper.closeWorkDatabase()
        }
    }

    @Test fun ioFailureRetries() =
        runBlocking {
            assertEquals(ListenableWorker.Result.success(), runSharedDownloadCleanup {})
            assertEquals(ListenableWorker.Result.retry(), runSharedDownloadCleanup { throw IOException() })
        }

    @Test fun cancellationIsNotRetry() {
        assertThrows(CancellationException::class.java) {
            runBlocking { runSharedDownloadCleanup { throw CancellationException() } }
        }
    }
}
