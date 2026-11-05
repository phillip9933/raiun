package eu.opencloud.android.next.feature.files

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** One in-flight creation at a time. A failed write is never retried because its outcome can be ambiguous. */
@Suppress("LongParameterList") // Keep admission callbacks and backend/dispatcher independently testable.
internal class EncryptedLocationCreation(
    context: Context,
    private val store: FileBrowserStore,
    private val scope: CoroutineScope,
    private val onBusy: (Boolean) -> Unit,
    private val onCreated: (BrowserAccountBinding, VaultLocation, CreationParent?) -> Unit,
    private val onUncertain: (BrowserAccountBinding) -> Unit,
    private val backend: EncryptedCreationBackend? = null,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    private val vaults = VaultRepository(context, store)
    private var busy = false

    @Suppress("TooGenericExceptionCaught") // The UI must report a possibly completed remote write without retrying.
    fun folder(
        binding: BrowserAccountBinding,
        driveId: String,
        folderId: String?,
        name: String,
        password: CharArray,
    ) {
        if (busy) {
            password.fill('\u0000')
            return
        }
        val accountId = binding.accountId
        val owned = password.copyOf()
        password.fill('\u0000')
        busy = true
        onBusy(true)
        val operation =
            scope.launch {
                try {
                    val created =
                        withContext(ioDispatcher) {
                            if (backend != null) {
                                return@withContext backend.folder(accountId, driveId, folderId, name, owned)
                            }
                            val path =
                                folderId
                                    ?.let {
                                        requireNotNull(
                                            store.resource(accountId, driveId, it),
                                        ).path
                                    }.orEmpty()
                            vaults.createFolderVault(accountId, driveId, path.trim('/'), name, owned)
                        }
                    onCreated(binding, created, CreationParent(accountId, driveId, folderId))
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    onUncertain(binding)
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
        binding: BrowserAccountBinding,
        name: String,
        password: CharArray,
    ) {
        if (busy) {
            password.fill('\u0000')
            return
        }
        val accountId = binding.accountId
        val owned = password.copyOf()
        password.fill('\u0000')
        busy = true
        onBusy(true)
        val operation =
            scope.launch {
                try {
                    val created =
                        withContext(ioDispatcher) {
                            backend?.space(accountId, name, owned) ?: vaults.createVaultSpace(accountId, name, owned)
                        }
                    onCreated(binding, created, null)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    onUncertain(binding)
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

/** Optional test backend; production retains the repository's conditional admission. */
internal interface EncryptedCreationBackend {
    suspend fun folder(
        account: String,
        drive: String,
        parent: String?,
        name: String,
        password: CharArray,
    ): VaultLocation

    suspend fun space(
        account: String,
        name: String,
        password: CharArray,
    ): VaultLocation
}
