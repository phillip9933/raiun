package eu.opencloud.android.next.core.network

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject

/** Missing optional capability lists retain legacy discovery; contradictory advertisements do not. */
internal fun validateOidcFlowMetadata(metadata: JsonObject) {
    metadata.requireAdvertisedSupport("response_types_supported", "code")
    metadata.requireAdvertisedSupport("grant_types_supported", "authorization_code")
    metadata.requireAdvertisedSupport("code_challenge_methods_supported", "S256")
}

private fun JsonObject.requireAdvertisedSupport(
    name: String,
    required: String,
) {
    val value = get(name) ?: return
    val array = value as? JsonArray ?: throw OpenCloudException(OpenCloudError.InvalidResponse)
    val supported = array.map(::oidcMetadataString)
    if (required !in supported) throw OpenCloudException(OpenCloudError.Unsupported)
}
