package eu.opencloud.android.next.core.sync

import android.content.Context
import android.graphics.Bitmap
import android.net.Uri
import eu.opencloud.android.next.core.security.AppLock
import java.security.MessageDigest

data class SharedFolderShortcutTarget(
    val request: SharedFolderRequest,
) {
    fun uri(): Uri =
        Uri
            .Builder()
            .scheme(FolderShortcutTarget.SCHEME)
            .authority("shared")
            .appendPath("v1")
            .appendPath(request.account)
            .appendPath(request.share)
            .appendPath(request.scope)
            .appendPath(request.remoteId)
            .appendPath(request.path)
            .build()

    fun shortcutId(): String =
        "shared-" +
            MessageDigest
                .getInstance("SHA-256")
                .digest(uri().toString().toByteArray())
                .joinToString("") { "%02x".format(it) }

    companion object {
        fun parse(value: String?): SharedFolderShortcutTarget? {
            val uri = value?.let(Uri::parse) ?: return null
            val parts = uri.pathSegments
            val route = uri.scheme == FolderShortcutTarget.SCHEME && uri.authority == "shared"
            val plain = uri.query == null && uri.fragment == null
            val structure = parts.size == 6 && parts[0] == "v1"
            val safe = parts.drop(1).none { it.isBlank() || it.length > 4096 || it.any(Char::isISOControl) }
            return runCatching {
                require(route && plain && structure && safe)
                requireSharedPath(parts[5])
                SharedFolderShortcutTarget(SharedFolderRequest(parts[1], parts[2], parts[3], parts[4], parts[5]))
            }.getOrNull()
        }
    }
}

class SharedFolderShortcuts(
    private val context: Context,
) {
    suspend fun resolve(target: SharedFolderShortcutTarget): String {
        val permit = AppLock(context).beginAppAction()
        check(permit())
        check(IncomingShareRepository.create(context).refresh(target.request.account))
        val browser = SharedFolderBrowser.create(context)
        val page = browser.openFolder(target.request)
        check(permit() && browser.isCurrent(page))
        return if (page.path == "/") page.location.name else page.path.substringAfterLast('/')
    }

    suspend fun pin(
        request: SharedFolderRequest,
        icon: Bitmap,
    ): Boolean {
        val target = SharedFolderShortcutTarget(request)
        val name = resolve(target)
        return pinFolderShortcut(context, target.shortcutId(), name, target.uri(), icon)
    }
}
