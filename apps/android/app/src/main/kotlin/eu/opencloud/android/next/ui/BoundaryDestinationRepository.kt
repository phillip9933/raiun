package eu.opencloud.android.next.ui

import android.content.Context
import eu.opencloud.android.next.core.sync.BoundaryEndpoint
import eu.opencloud.android.next.core.sync.VaultBoundaryEndpoint
import eu.opencloud.android.next.core.sync.VaultFolder
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultRepository
import java.io.Closeable

internal interface BoundaryDestinationRepository {
    suspend fun locations(accountId: String): List<VaultLocation>

    suspend fun ordinaryEndpoint(
        accountId: String,
        location: VaultLocation,
    ): BoundaryEndpoint

    suspend fun folders(
        accountId: String,
        location: VaultLocation,
        path: String,
    ): List<VaultFolder>

    suspend fun unlock(
        accountId: String,
        location: VaultLocation,
        password: CharArray,
    ): BoundaryUnlockedDestination
}

internal class BoundaryUnlockedDestination(
    val endpoint: BoundaryEndpoint,
    private val release: () -> Unit,
) : Closeable {
    override fun close() = release()
}

internal class AndroidBoundaryDestinationRepository(
    private val context: Context,
) : BoundaryDestinationRepository {
    private val repository = VaultRepository(context)

    override suspend fun locations(accountId: String) = repository.locations(accountId)

    override suspend fun ordinaryEndpoint(
        accountId: String,
        location: VaultLocation,
    ) = repository.ordinaryBoundaryEndpoint(context, accountId, location)

    override suspend fun folders(
        accountId: String,
        location: VaultLocation,
        path: String,
    ) = repository.folders(accountId, location, path)

    override suspend fun unlock(
        accountId: String,
        location: VaultLocation,
        password: CharArray,
    ): BoundaryUnlockedDestination {
        val session = repository.unlock(accountId, location, password = password)
        var transferred = false
        return try {
            BoundaryUnlockedDestination(VaultBoundaryEndpoint(session, location), session::close).also {
                transferred =
                    true
            }
        } finally {
            if (!transferred) session.close()
        }
    }
}
