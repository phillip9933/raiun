package eu.opencloud.android.next.feature.files

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.viewModelScope
import dev.offlinescan.core.ScanOutput
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.designsystem.localizedString
import eu.opencloud.android.next.core.sync.ScanUploadLocation
import eu.opencloud.android.next.core.sync.ScanUploadStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class ScannerViewModel(
    application: Application,
    private val saved: SavedStateHandle,
) : AndroidViewModel(application) {
    private val uploads = ScanUploadStore(application)
    private val mutableState = MutableStateFlow(ScannerState())
    val state = mutableState.asStateFlow()
    private var started = false
    private var pendingOutput: ScanOutput? = null
    private var destination: Triple<String, String, String>? = null

    fun start(
        account: String,
        space: String,
        path: String,
    ) {
        if (started) return
        started = true
        destination = Triple(account, space, path)
        action {
            val id = saved.get<String>(SESSION) ?: uploads.create(account, space, path).also { saved[SESSION] = it }
            if (uploads.hasCompletedOutput(id)) {
                uploads.submit(id)
                mutableState.value = ScannerState(done = true)
            } else {
                showScanner(id)
            }
        }
    }

    suspend fun changeLocation(
        space: String,
        path: String,
    ) = withContext(Dispatchers.IO) {
        val id = requireNotNull(saved.get<String>(SESSION))
        uploads.changeLocation(id, space, path)
        val location = uploads.location(id)
        destination = Triple(location.accountId, location.spaceId, location.parentPath)
        mutableState.value = mutableState.value.copy(location = location, locationLabel = locationLabel(location))
    }

    private suspend fun showScanner(id: String) {
        val location = uploads.location(id)
        mutableState.value =
            ScannerState(
                outputDirectory = uploads.outputDirectory(id),
                busy = false,
                location = location,
                locationLabel = locationLabel(location),
            )
    }

    private suspend fun locationLabel(location: ScanUploadLocation): String {
        val space =
            FileBrowserStore(FileBrowserDatabase.create(getApplication()))
                .spaces(location.accountId)
                .firstOrNull { it.driveId == location.spaceId }
        val name =
            if (space?.type ==
                "personal"
            ) {
                getApplication<Application>().localizedString(R.string.browser_personal)
            } else {
                space?.name.orEmpty()
            }
        return "$name / ${location.parentPath.trim('/')}".trimEnd()
    }

    fun completed(output: ScanOutput) {
        if (mutableState.value.busy) return
        pendingOutput = output
        retry()
    }

    fun retry() {
        action {
            val id =
                saved.get<String>(SESSION) ?: requireNotNull(destination).let { target ->
                    uploads.create(target.first, target.second, target.third).also { saved[SESSION] = it }
                }
            if (!uploads.hasCompletedOutput(id)) {
                pendingOutput?.let { uploads.complete(id, it.files, it.mimeType) }
            }
            if (uploads.hasCompletedOutput(id)) {
                uploads.submit(id)
                pendingOutput = null
                mutableState.value = ScannerState(done = true)
            } else {
                showScanner(id)
            }
        }
    }

    fun failed() {
        mutableState.value = mutableState.value.copy(busy = false, failed = true, outputDirectory = null)
    }

    fun discard() {
        action {
            saved.get<String>(SESSION)?.let { uploads.discard(it) }
            mutableState.value = ScannerState(done = true)
        }
    }

    private fun action(block: suspend () -> Unit) {
        mutableState.value = mutableState.value.copy(busy = true, failed = false, outputDirectory = null)
        viewModelScope.launch(Dispatchers.IO) {
            try {
                block()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                failed()
            }
        }
    }

    private companion object {
        const val SESSION = "scanner-session"
    }
}

data class ScannerState(
    val outputDirectory: File? = null,
    val busy: Boolean = true,
    val failed: Boolean = false,
    val done: Boolean = false,
    val location: ScanUploadLocation? = null,
    val locationLabel: String = "",
)
