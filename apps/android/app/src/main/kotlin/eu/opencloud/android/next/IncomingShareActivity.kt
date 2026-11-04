package eu.opencloud.android.next

import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.ui.res.stringResource
import androidx.core.content.IntentCompat
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.safeMessage
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
        // Recheck against the framework's launch snapshot on every recreation. Never persist a
        // caller-approved boolean or substitute our own (possibly persisted) URI permissions.
        val admitted =
            incomingShareReadAccess(sources, Build.VERSION.SDK_INT) { uri ->
                if (Build.VERSION.SDK_INT >= 35) {
                    caller?.checkContentUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
                        ?: PackageManager.PERMISSION_DENIED
                } else {
                    PackageManager.PERMISSION_DENIED
                }
            }
        setContent {
            OpenCloudTheme(darkTheme = dark) {
                DeviceLockGate(this) {
                    if (admitted) {
                        IncomingUploadRoute(batchId, sources, onClose = ::finish)
                    } else {
                        Column {
                            Text(OpenCloudError.SourcePermissionDenied.safeMessage(this@IncomingShareActivity))
                            TextButton(onClick = ::finish) {
                                Text(stringResource(eu.opencloud.android.next.feature.files.R.string.document_cancel))
                            }
                        }
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // One standard-mode Activity owns one batch. Explicit SINGLE_TOP/CLEAR_TOP redelivery
        // must not replace its sources with a different intent under the original caller's proof.
        // Reject that delivery visibly; the original confirmation/retry remains intact.
        Toast.makeText(this, OpenCloudError.SourcePermissionDenied.safeMessage(this), Toast.LENGTH_LONG).show()
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
    if (intent.action !in setOf(Intent.ACTION_SEND, Intent.ACTION_SEND_MULTIPLE)) return emptyList()
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

/** API 26–34 cannot establish general startActivity sender provenance; retain their existing flow. */
@Suppress("TooGenericExceptionCaught") // Every failed framework permission check refuses the batch.
internal fun incomingShareReadAccess(
    sources: List<Uri>,
    apiLevel: Int,
    senderPermission: (Uri) -> Int,
): Boolean {
    if (apiLevel < 35) return true
    return try {
        sources.all { uri ->
            uri.scheme == "content" && senderPermission(uri) == PackageManager.PERMISSION_GRANTED
        }
    } catch (_: RuntimeException) {
        // Missing receiver access, absent launch metadata, or an unavailable framework service
        // cannot become permission. Do not retain/log exception messages or source URIs.
        false
    }
}
