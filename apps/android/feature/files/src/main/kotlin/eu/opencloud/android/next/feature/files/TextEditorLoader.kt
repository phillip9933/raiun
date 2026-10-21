package eu.opencloud.android.next.feature.files

import android.content.Context
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.model.validatedCachedFile
import eu.opencloud.android.next.core.network.DownloadExpectation
import eu.opencloud.android.next.core.sync.LocalCopyLease
import eu.opencloud.android.next.core.sync.TextDraftStore
import eu.opencloud.android.next.core.sync.prepareLocalResource

internal suspend fun loadTextEditorState(
    context: Context,
    item: ResourceEntity,
    drafts: TextDraftStore,
    prepare: suspend (ResourceEntity) -> ResourceEntity = { prepareLocalResource(context, it) },
): TextEditorState {
    // Check the current server version even when an older durable draft exists.
    val ready = prepare(item)
    require(canEditText(ready))
    val saved = drafts.read(item.accountId, item.spaceId, item.remoteId)
    val draft =
        if (saved != null) {
            drafts.resume(saved)
        } else {
            val file =
                requireNotNull(
                    validatedCachedFile(
                        resourceCacheDirectory(context.filesDir, item.accountId, item.spaceId),
                        ready.localPath,
                        ready.sizeBytes,
                    ),
                )
            LocalCopyLease.read(file) { drafts.create(ready, file) }
        }
    val changed = draft.baseETag != DownloadExpectation(ready.sizeBytes, ready.eTag).strongETag
    return TextEditorState(draft = draft, busy = false, serverChanged = changed, chooseDraft = saved != null && changed)
}
