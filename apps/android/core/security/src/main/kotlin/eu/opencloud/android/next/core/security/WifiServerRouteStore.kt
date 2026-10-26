package eu.opencloud.android.next.core.security

import android.content.Context
import android.util.AtomicFile
import eu.opencloud.android.next.core.network.EndpointPolicy
import org.json.JSONObject
import java.io.File
import java.io.FileNotFoundException
import java.security.MessageDigest

/** One backup-excluded atomic JSON file per canonical server; corruption cannot affect other accounts. */
class WifiServerRouteStore(
    context: Context,
) {
    private val directory = File(context.noBackupFilesDir, "wifi-server-routes")

    fun find(canonicalServerUrl: String): WifiServerRoute? =
        synchronized(storeLock) {
            val key = key(canonicalServerUrl)
            read(AtomicFile(fileFor(key)), key)
        }

    fun all(): List<WifiServerRoute> =
        synchronized(storeLock) {
            val files = directory.listFiles { file -> file.isFile && file.extension == "json" }.orEmpty()
            require(files.size <= MAX_ROUTES) { "Too many Wi-Fi server routes." }
            files.mapNotNull { read(AtomicFile(it), expectedKey = null) }
        }

    fun put(route: WifiServerRoute) =
        synchronized(storeLock) {
            val normalized = route.copy(canonicalServerUrl = key(route.canonicalServerUrl))
            WifiServerRoutePolicy.validate(normalized)
            require(directory.isDirectory || directory.mkdirs()) { "Wi-Fi route storage is unavailable." }
            val target = fileFor(normalized.canonicalServerUrl)
            if (!target.exists()) {
                require(directory.listFiles { file -> file.extension == "json" }.orEmpty().size < MAX_ROUTES)
            }
            write(AtomicFile(target), normalized)
        }

    fun remove(canonicalServerUrl: String) =
        synchronized(storeLock) {
            AtomicFile(fileFor(key(canonicalServerUrl))).delete()
        }

    private fun key(value: String): String {
        val endpoint = EndpointPolicy().endpoint(value, allowQuery = false)
        return if (endpoint.encodedPath == "/") endpoint.toString().trimEnd('/') else endpoint.toString()
    }

    private fun fileFor(key: String): File {
        val digest = MessageDigest.getInstance("SHA-256").digest(key.toByteArray(Charsets.UTF_8))
        return File(directory, digest.joinToString("") { "%02x".format(it.toInt() and 0xff) } + ".json")
    }

    private fun read(
        file: AtomicFile,
        expectedKey: String?,
    ): WifiServerRoute? {
        val input =
            try {
                file.openRead()
            } catch (_: FileNotFoundException) {
                return null
            }
        val bytes =
            input.use { stream ->
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(1024)
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    require(output.size() + count <= MAX_FILE_BYTES) { "Wi-Fi route configuration is too large." }
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
        val value = JSONObject(String(bytes, Charsets.UTF_8))
        val route =
            WifiServerRoute(
                value.getString("canonicalServerUrl"),
                value.getString("ssid"),
                value.getString("localServerUrl"),
                value.getBoolean("enabled"),
                WifiRouteMode.valueOf(value.optString("mode", WifiRouteMode.AUTOMATIC.name)),
            )
        WifiServerRoutePolicy.validate(route)
        require(route.canonicalServerUrl == key(route.canonicalServerUrl))
        require(expectedKey == null || route.canonicalServerUrl == expectedKey)
        return route
    }

    @Suppress("TooGenericExceptionCaught") // AtomicFile.failWrite must run for every failed write/commit.
    private fun write(file: AtomicFile, route: WifiServerRoute) {
        val bytes =
            JSONObject()
                .put("canonicalServerUrl", route.canonicalServerUrl)
                .put("ssid", route.ssid)
                .put("localServerUrl", route.localServerUrl)
                .put("enabled", route.enabled)
                .put("mode", route.mode.name)
                .toString()
                .toByteArray(Charsets.UTF_8)
        require(bytes.size <= MAX_FILE_BYTES)
        val stream = file.startWrite()
        try {
            stream.write(bytes)
            file.finishWrite(stream)
        } catch (failure: Exception) {
            file.failWrite(stream)
            throw failure
        }
    }

    private companion object {
        const val MAX_FILE_BYTES = 4096
        const val MAX_ROUTES = 128
        val storeLock = Any()
    }
}
