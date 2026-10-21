package eu.opencloud.android.next.core.sync

import android.content.Context
import android.content.Intent
import android.content.pm.ShortcutInfo
import android.content.pm.ShortcutManager
import android.net.Uri
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.security.AppLock
import java.security.MessageDigest

data class FolderShortcutTarget(
    val account: String,
    val space: String,
    val folder: String,
) {
    fun uri(): Uri =
        Uri
            .Builder()
            .scheme(SCHEME)
            .authority("folder")
            .appendPath("v1")
            .appendPath(account)
            .appendPath(space)
            .appendPath(folder)
            .build()

    fun shortcutId(): String =
        "folder-" +
            MessageDigest
                .getInstance("SHA-256")
                .digest(uri().toString().toByteArray())
                .joinToString("") { "%02x".format(it) }

    companion object {
        const val SCHEME = "raiun-folder"

        private fun validId(value: String) =
            value.isNotBlank() && value.length <= 4096 && value.none(Char::isISOControl)

        fun parse(value: String?): FolderShortcutTarget? {
            val uri = value?.let(Uri::parse) ?: return null
            val parts = uri.pathSegments
            val validLocation =
                uri.scheme == SCHEME && uri.authority == "folder" && uri.query == null && uri.fragment == null
            val validPath = parts.size == 4 && parts[0] == "v1" && parts.drop(1).all(::validId)
            return if (validLocation && validPath) FolderShortcutTarget(parts[1], parts[2], parts[3]) else null
        }
    }
}

class FolderShortcuts(
    private val context: Context,
) {
    private val manager = context.getSystemService(ShortcutManager::class.java)
    private val store = FileBrowserStore(FileBrowserDatabase.create(context))

    fun supported(): Boolean = manager.isRequestPinShortcutSupported

    suspend fun resolve(target: FolderShortcutTarget): ResourceEntity {
        check(AppLock(context).canOpenApp())
        val resource = requireNotNull(store.resource(target.account, target.space, target.folder))
        require(resource.kind == ResourceKind.FOLDER)
        val space = requireNotNull(store.space(target.account, target.space))
        require(space.type in setOf("personal", "project"))
        return store.requireCurrentMutableResource(resource, false)
    }

    suspend fun pin(
        resource: ResourceEntity,
        icon: android.graphics.Bitmap? = null,
    ): Boolean {
        val target = FolderShortcutTarget(resource.accountId, resource.spaceId, resource.remoteId)
        val current = resolve(target)
        check(supported())
        return pinFolderShortcut(context, target.shortcutId(), current.name, target.uri(), icon)
    }
}

internal fun pinFolderShortcut(
    context: Context,
    id: String,
    name: String,
    uri: Uri,
    icon: android.graphics.Bitmap?,
): Boolean {
    val manager = context.getSystemService(ShortcutManager::class.java)
    check(manager.isRequestPinShortcutSupported)
    val intent =
        Intent(Intent.ACTION_VIEW, uri)
            .setClassName(context.packageName, "eu.opencloud.android.next.MainActivity")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
    val info =
        ShortcutInfo
            .Builder(context, id)
            .setShortLabel(name.take(80))
            .setLongLabel(
                name.take(200),
            ).setIcon(FolderShortcutIcon.launcherIcon(context, icon))
            .setIntent(intent)
            .build()
    if (manager.pinnedShortcuts.any { it.id == info.id }) return manager.updateShortcuts(listOf(info))
    return manager.requestPinShortcut(info, null)
}
