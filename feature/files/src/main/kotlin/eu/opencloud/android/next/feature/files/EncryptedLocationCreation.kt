package eu.opencloud.android.next.feature.files

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** One in-flight creation at a time. A failed write is never retried because its outcome can be ambiguous. */
internal class EncryptedLocationCreation(
    context: Context,
    private val store: FileBrowserStore,
    private val scope: CoroutineScope,
    private val onBusy: (Boolean) -> Unit,
    private val onCreated: (VaultLocation, CreationParent?) -> Unit,
    private val onUncertain: (String) -> Unit,
) {
    private val vaults = VaultRepository(context, store)
    private var busy = false

    @Suppress("TooGenericExceptionCaught") // The UI must report a possibly completed remote write without retrying.
    fun folder(
        accountId: String,
        driveId: String,
        folderId: String?,
        name: String,
        password: CharArray,
    ) {
        if (busy) {
            password.fill('\u0000')
            return
        }
        val owned = password.copyOf()
        password.fill('\u0000')
        busy = true
        onBusy(true)
        val operation =
            scope.launch {
                try {
                    val created =
                        withContext(Dispatchers.IO) {
                            val path =
                                folderId
                                    ?.let {
                                        requireNotNull(
                                            store.resource(accountId, driveId, it),
                                        ).path
                                    }.orEmpty()
                            vaults.createFolderVault(accountId, driveId, path.trim('/'), name, owned)
                        }
                    onCreated(created, CreationParent(accountId, driveId, folderId))
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    onUncertain(accountId)
                } finally {
                    owned.fill('\u0000')
                    busy = false
                    onBusy(false)
                }
            }
        operation.invokeOnCompletion { owned.fill('\u0000') }
    }

    @Suppress("TooGenericExceptionCaught") // The UI must report a possibly completed remote write without retrying.
    fun space(
        accountId: String,
        name: String,
        password: CharArray,
    ) {
        if (busy) {
            password.fill('\u0000')
            return
        }
        val owned = password.copyOf()
        password.fill('\u0000')
        busy = true
        onBusy(true)
        val operation =
            scope.launch {
                try {
                    val created = withContext(Dispatchers.IO) { vaults.createVaultSpace(accountId, name, owned) }
                    onCreated(created, null)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    onUncertain(accountId)
                } finally {
                    owned.fill('\u0000')
                    busy = false
                    onBusy(false)
                }
            }
        operation.invokeOnCompletion { owned.fill('\u0000') }
    }
}

internal data class CreationParent(
    val accountId: String,
    val driveId: String,
    val folderId: String?,
)
