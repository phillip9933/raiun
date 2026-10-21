package eu.opencloud.android.next.core.documentsprovider

import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import eu.opencloud.android.next.core.sync.LocalCopyLease
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import java.io.File

@Suppress("TooGenericExceptionCaught") // Every failed open must release its local reader protection.
internal suspend fun openCachedRead(
    file: File,
    scope: CoroutineScope,
    checkAccess: suspend () -> Unit,
): ParcelFileDescriptor {
    val lease = LocalCopyLease.acquire(file)
    try {
        checkAccess()
        file.setLastModified(System.currentTimeMillis())
        return ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY, Handler(Looper.getMainLooper())) {
            scope.launch { lease.close() }
        }
    } catch (failure: Exception) {
        lease.close()
        throw failure
    }
}
