package eu.opencloud.android.next.core.network

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

/** Only selected protocol identifiers are admitted; never echo metadata in failures. */
internal fun oidcMetadataString(value: JsonElement?): String {
    val primitive = value as? JsonPrimitive ?: throw OpenCloudException(OpenCloudError.InvalidResponse)
    if (!primitive.isString ||
        primitive.content.isBlank() ||
        primitive.content.any(Char::isISOControl)
    ) {
        throw OpenCloudException(OpenCloudError.InvalidResponse)
    }
    return primitive.content
}

/** RFC 9207: only an absent support flag defaults to false; supplied values are JSON booleans. */
internal fun oidcResponseIssuerSupported(value: JsonElement?): Boolean {
    if (value == null) return false
    val primitive = value as? JsonPrimitive ?: throw OpenCloudException(OpenCloudError.InvalidResponse)
    return primitive.booleanOrNull?.takeUnless { primitive.isString }
        ?: throw OpenCloudException(OpenCloudError.InvalidResponse)
}
