package eu.opencloud.android.next.core.network

import okhttp3.Credentials

/**
 * OpenCloud 8/9 passes Go BasicAuth's decoded bytes into CS3 UTF-8 strings without Latin-1
 * transcoding. Use the same explicit encoding for sign-in and restored workers. RFC 7617 leaves
 * the general Basic default undefined; this is the supported OpenCloud policy, not negotiation
 * with arbitrary legacy servers. Never retry a password using an alternate encoding.
 */
fun openCloudBasicAuthorization(
    username: String,
    password: String,
): String = Credentials.basic(username, password, Charsets.UTF_8)
