package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Metadata only: never fetches credentials or starts a connection. */
suspend fun accountServerForConnectionSettings(
    context: Context,
    accountId: String,
): String? =
    withContext(Dispatchers.IO) {
        FileBrowserStore(FileBrowserDatabase.create(context)).account(accountId)?.serverUrl
    }
