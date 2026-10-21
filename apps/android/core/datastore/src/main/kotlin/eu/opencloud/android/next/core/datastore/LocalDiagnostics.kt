package eu.opencloud.android.next.core.datastore

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException

enum class TransferDiagnostic { SUCCEEDED, FAILED, RETRY, AUTHENTICATION_REQUIRED }

/** Deliberately accepts no free-form messages, identifiers, addresses or exceptions. */
internal class DiagnosticHistory(
    private val file: File,
) {
    fun record(
        event: TransferDiagnostic,
        timestamp: Long,
    ) {
        val lines = read().lines().filter(String::isNotBlank).takeLast(99)
        file.parentFile?.mkdirs()
        file.writeText((lines + "$timestamp ${event.name}").joinToString("\n"))
    }

    fun read(): String =
        if (file.isFile && file.length() <= 16_384) {
            file
                .readLines()
                .filter { ENTRY.matches(it) }
                .takeLast(100)
                .joinToString("\n")
        } else {
            ""
        }

    fun clear() {
        if (file.exists() && !file.delete()) throw IOException("Unable to clear diagnostics")
    }

    private companion object {
        val ENTRY = Regex("[0-9]+ (SUCCEEDED|FAILED|RETRY|AUTHENTICATION_REQUIRED)")
    }
}

object LocalDiagnostics {
    private val mutex = Mutex()

    suspend fun setEnabled(
        context: Context,
        enabled: Boolean,
    ) = withContext(Dispatchers.IO) {
        mutex.withLock {
            SettingsRepository.create(context).setLocalDiagnosticsEnabled(enabled)
            if (!enabled) history(context).clear()
        }
    }

    suspend fun read(context: Context): String =
        withContext(Dispatchers.IO) {
            mutex.withLock {
                if (SettingsRepository
                        .create(
                            context,
                        ).settings
                        .first()
                        .localDiagnosticsEnabled
                ) {
                    history(context).read()
                } else {
                    ""
                }
            }
        }

    suspend fun record(
        context: Context,
        event: TransferDiagnostic,
    ) = withContext(Dispatchers.IO) {
        try {
            mutex.withLock {
                val history = history(context)
                if (SettingsRepository
                        .create(context)
                        .settings
                        .first()
                        .localDiagnosticsEnabled
                ) {
                    history.record(event, System.currentTimeMillis())
                } else {
                    history.clear()
                }
            }
        } catch (_: IOException) {
            // Optional diagnostics must not alter transfer outcome; cancellation is not caught.
        }
    }

    private fun history(context: Context) =
        DiagnosticHistory(File(context.noBackupFilesDir, "transfer-diagnostics.txt"))
}
