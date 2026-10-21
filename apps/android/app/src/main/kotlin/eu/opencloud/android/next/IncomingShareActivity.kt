package eu.opencloud.android.next

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.IntentCompat
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.feature.files.IncomingUploadRoute
import java.util.UUID

/** Dedicated task preserves the sender's grants without interrupting an existing browser session. */
class IncomingShareActivity : AppCompatActivity() {
    private var batchId = UUID.randomUUID().toString()

    override fun onCreate(savedInstanceState: Bundle?) {
        val dark = applyStoredWindowTheme()
        super.onCreate(savedInstanceState)
        batchId = savedInstanceState?.getString("batchId") ?: batchId
        val sources = incomingShareUris(intent)
        setContent {
            OpenCloudTheme(darkTheme = dark) {
                DeviceLockGate(this) {
                    IncomingUploadRoute(batchId, sources, onClose = ::finish)
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        restoreStoredTaskAppearance()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        outState.putString("batchId", batchId)
        super.onSaveInstanceState(outState)
    }
}

internal fun incomingShareUris(intent: Intent): List<Uri> {
    val streams =
        when (intent.action) {
            Intent.ACTION_SEND ->
                listOfNotNull(
                    IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java),
                )
            Intent.ACTION_SEND_MULTIPLE ->
                IntentCompat
                    .getParcelableArrayListExtra(
                        intent,
                        Intent.EXTRA_STREAM,
                        Uri::class.java,
                    ).orEmpty()
            else -> emptyList()
        }
    val clips =
        intent.clipData
            ?.let { data ->
                (0 until minOf(data.itemCount, 101)).mapNotNull { data.getItemAt(it).uri }
            }.orEmpty()
    return (streams + clips).distinct().take(101)
}
