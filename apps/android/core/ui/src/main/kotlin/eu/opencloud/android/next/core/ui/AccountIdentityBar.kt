package eu.opencloud.android.next.core.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.designsystem.theme.AccountAccent
import eu.opencloud.android.next.core.sync.AccountProfileIdentity
import eu.opencloud.android.next.core.sync.AccountProfiles
import kotlinx.coroutines.CancellationException
import java.net.URI

/** A small identity marker follows the local account choice and the actual app theme. */
@Composable
fun accountAccent(accountId: String): Color {
    val context = LocalContext.current
    val revision by AccountProfiles.colorRevision.collectAsState()
    val choice = remember(accountId, revision) { AccountProfiles.colorChoice(context, accountId) }
    return AccountAccent.indicator(accountId, MaterialTheme.colorScheme.surface.luminance() < 0.5f, choice)
}

@Composable
fun accountAccentContainer(accountId: String): Color {
    val context = LocalContext.current
    val revision by AccountProfiles.colorRevision.collectAsState()
    val choice = remember(accountId, revision) { AccountProfiles.colorChoice(context, accountId) }
    return AccountAccent.container(
        MaterialTheme.colorScheme.surface,
        accountId,
        MaterialTheme.colorScheme.surface.luminance() < 0.5f,
        choice,
    )
}

/** The account key scopes both the load and its initial state, avoiding a stale identity on switching. */
@Composable
fun accountIdentityDescription(accountId: String): String {
    val context = LocalContext.current
    val revision by AccountProfiles.revision.collectAsState()
    val identity by key(accountId, revision) {
        produceState<AccountProfileIdentity?>(null) {
            value =
                try {
                    AccountProfiles.identity(context, accountId)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    null
                }
        }
    }
    return listOfNotNull(
        identity?.name ?: stringResource(R.string.account_identity_fallback),
        identity?.serverUrl?.let(::accountServerLabel)?.takeIf { it.isNotBlank() },
    ).joinToString(", ")
}

/** Show only connection identity, never legacy URL credentials, queries or fragments. */
fun accountServerLabel(value: String): String =
    try {
        val uri = URI(value)
        val host = uri.host.orEmpty()
        if (host.isEmpty()) {
            ""
        } else {
            host + (if (uri.port >= 0) ":${uri.port}" else "") +
                uri.rawPath.orEmpty().trimEnd('/')
        }
    } catch (_: java.net.URISyntaxException) {
        ""
    }
