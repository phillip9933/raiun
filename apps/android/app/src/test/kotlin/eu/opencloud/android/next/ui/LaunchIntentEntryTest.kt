package eu.opencloud.android.next.ui

import android.app.Activity
import android.app.Application
import android.app.KeyguardManager
import android.content.Intent
import android.os.Build
import androidx.activity.ComponentActivity
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.core.net.toUri
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.test.core.app.ApplicationProvider
import eu.opencloud.android.next.DeviceLockGate
import eu.opencloud.android.next.DeviceUnlockActivity
import eu.opencloud.android.next.LaunchIntentViewModel
import eu.opencloud.android.next.consumeLaunchRequest
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.sync.FolderShortcutTarget
import eu.opencloud.android.next.core.sync.SharedFolderRequest
import eu.opencloud.android.next.core.sync.SharedFolderShortcutTarget
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import org.robolectric.annotation.SQLiteMode
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

// Admission/lifecycle semantics do not assert native rasterization, fonts or SQLite behavior.
@GraphicsMode(GraphicsMode.Mode.LEGACY)
@SQLiteMode(SQLiteMode.Mode.LEGACY)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35])
class LaunchIntentEntryTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Before fun grantDeclaredLegacyReceiverPermission() {
        if (Build.VERSION.SDK_INT == 26) {
            Shadows.shadowOf(ApplicationProvider.getApplicationContext<Application>()).grantPermissions(
                "${compose.activity.packageName}.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION",
            )
        }
    }

    @Test fun callbackWaitsForRestoreAndRetainedJobIsNotReplayedAfterRealLockReentry() {
        val scenarioIntent = Intent(compose.activity.intent)
        val owner = ViewModelProvider(compose.activity)[LaunchIntentViewModel::class.java]
        val jobs = ViewModelProvider(compose.activity)[CallbackJobs::class.java]
        val lock = AppLock(compose.activity)
        Shadows.shadowOf(compose.activity.getSystemService(KeyguardManager::class.java)).setIsDeviceSecure(true)
        lock.preferences
            .edit()
            .clear()
            .commit()
        lock.authenticated()
        lock.setEnabled(true)
        lock.background()
        var restoring by mutableStateOf(true)
        owner.acceptInitial(Intent(Intent.ACTION_VIEW, "app.raiun.cloud://oauth?code=test&state=test".toUri()))
        compose.activity.intent = Intent(Intent.ACTION_VIEW, owner.pending?.uri?.toUri())
        try {
            compose.setContent {
                DeviceLockGate(compose.activity) {
                    OidcLaunchEntry(
                        owner.pending,
                        restoring,
                        { compose.activity.consumeLaunchRequest(owner, it) },
                        jobs::complete,
                    )
                }
            }
            compose.runOnIdle {
                assertEquals(0, jobs.started)
                assertTrue(owner.pending != null)
                completeDeviceUnlock(lock)
            }
            compose.runOnIdle {
                assertEquals(0, jobs.started)
                assertTrue(owner.pending != null)
                restoring = false
            }
            compose.runOnIdle {
                assertEquals(1, jobs.started)
                assertNull(owner.pending)
                assertNull(compose.activity.intent.data)
                // ActivityScenario matches lifecycle callbacks against its original launch intent.
                compose.activity.intent = scenarioIntent
            }
            compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
            compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
            compose.waitForIdle()
            compose.runOnIdle {
                assertEquals(1, jobs.started)
                assertEquals(0, jobs.finished)
                completeDeviceUnlock(lock)
            }
            compose.runOnIdle {
                assertEquals(1, jobs.started)
                jobs.release.complete(Unit)
            }
            compose.runOnIdle {
                assertEquals(1, jobs.finished)
                assertEquals(1, jobs.started)
            }
        } finally {
            jobs.release.complete(Unit)
            compose.runOnIdle {
                compose.activity.intent = scenarioIntent
                // Complete any fixture-launched prompt before resetting its lock policy.
                repeat(2) {
                    val outstanding = Shadows.shadowOf(compose.activity).nextStartedActivityForResult
                    if (outstanding != null) {
                        compose.activity.activityResultRegistry.dispatchResult(
                            outstanding.requestCode,
                            Activity.RESULT_CANCELED,
                            null,
                        )
                    }
                }
                lock.preferences
                    .edit()
                    .clear()
                    .commit()
                lock.lock()
            }
        }
    }

    @Test fun pendingShortcutWaitsThroughRestoreAndAccountSwitchThenRetainsUnappliedHandoff() {
        val owner = LaunchIntentViewModel()
        owner.acceptInitial(folder("target", "first"))
        val request = requireNotNull(owner.pending)
        assertEquals(FolderShortcutTarget("target", "space", "first"), FolderShortcutTarget.parse(request.uri))
        var restoring by mutableStateOf(true)
        var activeAccount by mutableStateOf("other")
        var unlocked by mutableStateOf(true)
        val resolves = AtomicInteger()
        val switches = mutableListOf<String>()
        val unavailable = AtomicInteger()
        val access =
            access { target ->
                resolves.incrementAndGet()
                resource(target.account, target.folder)
            }
        compose.setContent {
            if (unlocked) {
                val pending = owner.pending?.takeIf { owner.folderNavigation == null }
                FolderShortcutEntry(
                    uri = pending?.uri,
                    requestId = pending?.id,
                    activeAccount = activeAccount,
                    restoringSession = restoring,
                    switchAccount = { switches += it },
                    open = { owner.openFolder(requireNotNull(pending).id, it) },
                    onUnavailable = {
                        unavailable.incrementAndGet()
                        owner.consume(requireNotNull(pending).id)
                    },
                    isCurrent = { owner.isPending(pending?.id) },
                    openShared = {},
                    access = access,
                )
            }
        }
        compose.runOnIdle {
            assertEquals(0, resolves.get())
            restoring = false
        }
        compose.waitForIdle()
        compose.waitUntil { switches.size == 1 || unavailable.get() > 0 }
        compose.runOnIdle {
            assertEquals("Unexpected shortcut rejection", 0, unavailable.get())
            assertEquals(listOf("target"), switches)
            assertTrue(owner.isPending(request.id))
            assertNull(owner.folderNavigation)
            activeAccount = "target"
        }
        compose.waitForIdle()
        compose.waitUntil { owner.folderNavigation != null || unavailable.get() > 0 }
        assertEquals("Unexpected shortcut rejection", 0, unavailable.get())
        val navigation = owner.folderNavigation
        compose.runOnIdle { unlocked = false }
        compose.runOnIdle { unlocked = true }
        compose.runOnIdle {
            assertEquals(2, resolves.get())
            assertTrue(navigation === owner.folderNavigation)
            assertTrue(owner.isPending(request.id))
            assertTrue(owner.consume(request.id))
        }
    }

    @Test fun canceledOldResolutionCannotNavigateSwitchAccountOrConsumeNewerIntent() {
        val owner = LaunchIntentViewModel()
        owner.acceptInitial(folder("old-account", "old"))
        val old = requireNotNull(owner.pending)
        assertEquals(FolderShortcutTarget("old-account", "space", "old"), FolderShortcutTarget.parse(old.uri))
        val started = CompletableDeferred<Unit>()
        val oldResult = CompletableDeferred<Unit>()
        val oldReturned = AtomicBoolean()
        val switches = mutableListOf<String>()
        val unavailable = AtomicInteger()
        val access =
            access { target ->
                if (target.folder == "old") {
                    started.complete(Unit)
                    // A provider can finish after cancellation. The outer admission must reject it.
                    withContext(NonCancellable) { oldResult.await() }
                    oldReturned.set(true)
                }
                resource(target.account, target.folder)
            }
        compose.setContent {
            val pending = owner.pending?.takeIf { owner.folderNavigation == null }
            FolderShortcutEntry(
                uri = pending?.uri,
                requestId = pending?.id,
                activeAccount = "new-account",
                restoringSession = false,
                switchAccount = { switches += it },
                open = { owner.openFolder(requireNotNull(pending).id, it) },
                onUnavailable = {
                    unavailable.incrementAndGet()
                    owner.consume(requireNotNull(pending).id)
                },
                isCurrent = { owner.isPending(pending?.id) },
                openShared = {},
                access = access,
            )
        }
        try {
            compose.waitUntil { started.isCompleted }
            compose.runOnIdle { owner.acceptNew(folder("new-account", "new")) }
            compose.waitForIdle()
            compose.waitUntil { owner.folderNavigation != null || unavailable.get() > 0 }
            assertEquals("Unexpected replacement shortcut rejection", 0, unavailable.get())
            val current = requireNotNull(owner.pending)
            compose.runOnIdle { oldResult.complete(Unit) }
            compose.waitUntil { oldReturned.get() }
            compose.runOnIdle {
                assertEquals(emptyList<String>(), switches)
                assertEquals("new", owner.folderNavigation?.resource?.remoteId)
                assertTrue(owner.isPending(current.id))
                assertTrue(!owner.consume(old.id))
            }
        } finally {
            oldResult.complete(Unit)
        }
    }

    @Test fun sharedShortcutValidatesAfterAccountSwitchAndKeepsMatchingAckForNewerSameUri() {
        val scenarioIntent = Intent(compose.activity.intent)
        val owner = ViewModelProvider(compose.activity)[LaunchIntentViewModel::class.java]
        val expected = SharedFolderRequest("target", "share", "scope", "remote", "/folder")
        val target = SharedFolderShortcutTarget(expected)
        val launch = Intent(Intent.ACTION_VIEW, target.uri())
        owner.acceptInitial(launch)
        compose.activity.intent = launch
        val first = requireNotNull(owner.pending)
        assertEquals(target, SharedFolderShortcutTarget.parse(first.uri))
        var activeAccount by mutableStateOf("other")
        var unlocked by mutableStateOf(true)
        val switches = mutableListOf<String>()
        val unavailable = AtomicInteger()
        val validation = CompletableDeferred<Unit>()
        val resolutions = AtomicInteger()
        val access =
            object : FolderShortcutAccess {
                override suspend fun resolve(target: FolderShortcutTarget): ResourceEntity =
                    error("Expected a shared shortcut")

                override suspend fun resolveShared(target: SharedFolderShortcutTarget) {
                    check(target.request == expected)
                    resolutions.incrementAndGet()
                    validation.await()
                }
            }
        compose.setContent {
            if (unlocked) {
                val pending = owner.pending?.takeIf { owner.folderNavigation == null }
                FolderShortcutEntry(
                    uri = pending?.uri,
                    requestId = pending?.id,
                    activeAccount = activeAccount,
                    restoringSession = false,
                    switchAccount = { switches += it },
                    open = { error("Expected a shared handoff") },
                    onUnavailable = {
                        unavailable.incrementAndGet()
                        owner.consume(requireNotNull(pending).id)
                    },
                    isCurrent = { owner.isPending(pending?.id) },
                    openShared = { owner.openSharedFolder(requireNotNull(pending).id, it) },
                    access = access,
                )
            }
        }
        try {
            compose.waitForIdle()
            compose.waitUntil { switches.size == 1 || unavailable.get() > 0 }
            compose.runOnIdle {
                assertEquals("Unexpected shared shortcut rejection", 0, unavailable.get())
                assertEquals(listOf("target"), switches)
                assertEquals(0, resolutions.get())
                assertNull(owner.folderNavigation)
                assertTrue(owner.isPending(first.id))
                activeAccount = "target"
            }
            compose.waitForIdle()
            compose.waitUntil { resolutions.get() == 1 || unavailable.get() > 0 }
            compose.runOnIdle {
                assertEquals("Unexpected shared shortcut rejection", 0, unavailable.get())
                assertNull(owner.folderNavigation)
                assertTrue(owner.isPending(first.id))
                validation.complete(Unit)
            }
            compose.waitForIdle()
            compose.waitUntil { owner.folderNavigation?.shared == expected }
            compose.runOnIdle { unlocked = false }
            compose.runOnIdle { unlocked = true }
            compose.runOnIdle {
                assertEquals(1, resolutions.get())
                assertTrue(owner.isPending(first.id))
                assertEquals(first.id, owner.folderNavigation?.id)
                // A genuine second delivery uses the same URI but needs a new validation/handoff.
                val newer = Intent(Intent.ACTION_VIEW, target.uri())
                assertTrue(owner.acceptNew(newer))
                compose.activity.intent = newer
            }
            compose.waitForIdle()
            compose.waitUntil { (resolutions.get() == 2 && owner.folderNavigation != null) || unavailable.get() > 0 }
            compose.runOnIdle {
                assertEquals("Unexpected replacement shared shortcut rejection", 0, unavailable.get())
                val second = requireNotNull(owner.pending)
                assertTrue(second.id != first.id)
                assertEquals(second.id, owner.folderNavigation?.id)
                assertEquals(expected, owner.folderNavigation?.shared)
                assertTrue(!compose.activity.consumeLaunchRequest(owner, first.id))
                assertEquals(target.uri(), compose.activity.intent.data)
                assertTrue(owner.isPending(second.id))
                assertTrue(compose.activity.consumeLaunchRequest(owner, second.id))
                assertNull(owner.pending)
                assertNull(owner.folderNavigation)
                assertNull(compose.activity.intent.data)
            }
        } finally {
            validation.complete(Unit)
            compose.runOnIdle { compose.activity.intent = scenarioIntent }
        }
    }

    private fun completeDeviceUnlock(lock: AppLock) {
        val prompt = requireNotNull(Shadows.shadowOf(compose.activity).nextStartedActivityForResult)
        assertEquals(DeviceUnlockActivity::class.java.name, prompt.intent.component?.className)
        lock.authenticated()
        assertTrue(
            compose.activity.activityResultRegistry.dispatchResult(
                prompt.requestCode,
                Activity.RESULT_OK,
                null,
            ),
        )
    }

    private fun folder(
        account: String,
        id: String,
    ) = Intent(Intent.ACTION_VIEW, "raiun-folder://folder/v1/$account/space/$id".toUri())

    private fun resource(
        account: String,
        id: String,
    ) = ResourceEntity(account, "space", id, null, "/$id", id, ResourceKind.FOLDER, null, 0, null, 0, 0)

    private fun access(resolve: suspend (FolderShortcutTarget) -> ResourceEntity) =
        object : FolderShortcutAccess {
            override suspend fun resolve(target: FolderShortcutTarget): ResourceEntity = resolve.invoke(target)

            override suspend fun resolveShared(target: SharedFolderShortcutTarget) = Unit
        }

    class CallbackJobs : ViewModel() {
        val release = CompletableDeferred<Unit>()
        var started = 0
        var finished = 0

        fun complete(callback: String) {
            check(callback.startsWith("app.raiun.cloud://oauth?"))
            started++
            viewModelScope.launch {
                release.await()
                finished++
            }
        }
    }
}
