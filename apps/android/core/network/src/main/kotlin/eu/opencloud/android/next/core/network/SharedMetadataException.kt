package eu.opencloud.android.next.core.network

/** Fixed support codes only: never retain a response, URL, identity, or parser exception. */
class SharedMetadataException(
    val stage: SharedMetadataStage,
) : OpenCloudException(OpenCloudError.InvalidResponse)

enum class SharedMetadataStage(
    val code: String,
) {
    INVENTORY("S01"),
    MOUNT("S02"),
    ITEM_FORMAT("S03"),
    ITEM_IDENTITY("S04"),
    PARENT_IDENTITY("S05"),
    DAV_LISTING("S06"),
    CHILDREN("S07"),
}
