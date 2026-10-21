package eu.opencloud.android.next.core.sync

import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File
import java.io.IOException
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

/** Account-scoped gates prevent a writer from recreating files after account cleanup. */
internal object SharedDownloadFiles {
    private val gates = ConcurrentHashMap<String, Mutex>()
    private val contentGates = ConcurrentHashMap<String, Mutex>()

    suspend fun <T> guard(
        filesDir: File,
        accountId: String,
        action: suspend () -> T,
    ): T = guardDirectory(accountDirectory(filesDir, accountId), action)

    suspend fun <T> guardDirectory(
        account: File,
        action: suspend () -> T,
    ): T = gates.getOrPut(account.canonicalPath) { Mutex() }.withLock { guardContent(account, action) }

    /** Writers retain lifetime exclusion from cleanup, but only publication needs exclusion from readers. */
    suspend fun <T> guardWriter(
        filesDir: File,
        accountId: String,
        action: suspend () -> T,
    ): T = gates.getOrPut(accountDirectory(filesDir, accountId).canonicalPath) { Mutex() }.withLock { action() }

    suspend fun <T> guardRead(
        filesDir: File,
        accountId: String,
        action: suspend () -> T,
    ): T = guardContent(accountDirectory(filesDir, accountId), action)

    private suspend fun <T> guardContent(
        account: File,
        action: suspend () -> T,
    ): T = contentGates.getOrPut(account.canonicalPath) { Mutex() }.withLock { action() }

    fun accountDirectories(filesDir: File): List<File> {
        val root = child(filesDir, "shared-files-v1")
        val children =
            if (root.exists()) {
                root.listFiles() ?: throw IOException("Private accounts could not be listed.")
            } else {
                emptyArray()
            }
        return children.filter { it.name.matches(Regex("[0-9a-f]{64}")) && it.canonicalFile == it && it.isDirectory }
    }

    fun accountDirectory(
        filesDir: File,
        accountId: String,
    ): File = child(child(filesDir, "shared-files-v1"), hash(accountId))

    fun directory(
        filesDir: File,
        accountId: String,
        scopeId: String,
    ): File = child(accountDirectory(filesDir, accountId), hash(scopeId))

    suspend fun clearAccount(
        filesDir: File,
        accountId: String,
    ) = guard(filesDir, accountId) {
        val directory = accountDirectory(filesDir, accountId)
        check(!directory.exists() || directory.deleteRecursively()) { "Local shared files could not be removed." }
    }

    /** Caller holds the account gate so no staging or publication can race this snapshot. */
    suspend fun pruneUnreferenced(
        filesDir: File,
        accountId: String,
        retainedPaths: Set<String>,
    ): Int = pruneDirectory(accountDirectory(filesDir, accountId), retainedPaths)

    /** Account must be obtained from accountDirectory/accountDirectories and its gate held. */
    suspend fun pruneDirectory(
        account: File,
        retainedPaths: Set<String>,
    ): Int {
        val scopes =
            if (account.exists()) {
                account.listFiles() ?: throw IOException("Private downloads could not be listed.")
            } else {
                emptyArray()
            }
        var removed = 0
        for (scope in scopes) {
            currentCoroutineContext().ensureActive()
            if (scope.name.matches(Regex("[0-9a-f]{64}")) && scope.canonicalFile == scope && scope.isDirectory) {
                removed += pruneScope(scope, retainedPaths)
            }
        }
        return removed
    }

    private suspend fun pruneScope(
        scope: File,
        retainedPaths: Set<String>,
    ): Int {
        var removed = 0
        for (file in scope.listFiles() ?: throw IOException("Private downloads could not be listed.")) {
            currentCoroutineContext().ensureActive()
            val privateFile = file.extension in setOf("part", "blob") && file.canonicalFile == file && file.isFile
            if (privateFile && file.path !in retainedPaths) {
                if (!file.delete()) throw IOException("An unused private download could not be removed.")
                removed++
            }
        }
        // Only empty directories can be removed; never recursively follow unexpected content.
        scope.delete()
        return removed
    }

    private fun child(
        parent: File,
        name: String,
    ): File {
        val directory = File(parent.canonicalFile, name).canonicalFile
        check(directory.parentFile == parent.canonicalFile) { "Invalid private file directory." }
        return directory
    }

    private fun hash(value: String): String =
        MessageDigest
            .getInstance("SHA-256")
            .digest(value.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
}
