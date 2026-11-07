package eu.opencloud.android.next.core.security

import android.content.Context
import android.content.SharedPreferences
import android.system.Os
import android.system.OsConstants
import android.util.AtomicFile
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.TransportPolicyException
import okhttp3.CertificatePinner
import okhttp3.HttpUrl
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.security.MessageDigest
import java.util.Base64
import java.util.Locale
import javax.net.ssl.SSLPeerUnverifiedException

/**
 * Read-only pin policy with a checked, one-way import of the retired preferences format.
 * No pin approval/removal API is exposed. All instances serialize migration and cleanup.
 */
internal class LegacyCertificatePinStore internal constructor(
    private val directory: File,
    private val legacy: SharedPreferences,
) {
    constructor(context: Context) : this(
        File(context.applicationContext.noBackupFilesDir, "certificate-pins"),
        context.applicationContext.getSharedPreferences("tls_trust", Context.MODE_PRIVATE),
    )

    @Suppress("TooGenericExceptionCaught") // Storage/platform failures cross only the fixed trust-error boundary.
    fun pinsFor(host: String): Set<String> =
        synchronized(storeLock) {
            try {
                loadAndMigrate()[canonicalHost(host)].orEmpty().toSet()
            } catch (_: Exception) {
                throw TransportPolicyException(OpenCloudError.Trust)
            }
        }

    /** Adds an independent required check; replacing/merging the base pinner would weaken its policy. */
    fun applyTo(
        baseClient: OkHttpClient,
        host: String,
        pins: Set<String>,
    ): OkHttpClient {
        @Suppress("SpreadOperator")
        val required = CertificatePinner.Builder().add(host, *pins.toTypedArray()).build()
        return baseClient
            .newBuilder()
            .addInterceptor(
                Interceptor { chain ->
                    val upgrade = chain.request().header("Upgrade")
                    // OkHttp skips network interceptors for WebSocket upgrades. No legacy-pinned
                    // WebSocket transport is implemented, so refuse before handshake/request bytes.
                    if (upgrade.equals("websocket", ignoreCase = true) &&
                        (pins.isNotEmpty() || pinsFor(host).isNotEmpty())
                    ) {
                        throw TransportPolicyException(OpenCloudError.Trust)
                    }
                    chain.proceed(chain.request())
                },
            ).addNetworkInterceptor(
                Interceptor { chain ->
                    val accepted =
                        try {
                            check(pinsFor(host) == pins)
                            val request = chain.request()
                            if (pins.isNotEmpty() && request.url.isHttps && request.url.host == host) {
                                val handshake = checkNotNull(chain.connection()?.handshake())
                                required.check(host, handshake.peerCertificates)
                            }
                            true
                        } catch (_: SSLPeerUnverifiedException) {
                            false
                        } catch (_: IllegalStateException) {
                            false
                        } catch (_: TransportPolicyException) {
                            false
                        }
                    if (!accepted) {
                        ScopedTransportCache.invalidateAll()
                        throw TransportPolicyException(OpenCloudError.Trust)
                    }
                    chain.proceed(chain.request())
                },
            ).build()
    }

    private fun loadAndMigrate(): Map<String, Set<String>> {
        val entries = legacy.all.filterKeys { it.startsWith(PREFIX) }
        val imported = decodeLegacy(entries)
        val stored = read()
        val policy =
            if (stored == null) {
                // A directory left by a failed first write may be retried only with intact legacy data.
                check(entries.isNotEmpty() || !directory.exists())
                if (entries.isEmpty()) return emptyMap()
                write(imported)
                check(read() == imported)
                imported
            } else {
                // A crash after publication but before preference cleanup is safe to retry. Never merge
                // differing pin sets: union would turn two required policies into an either/or policy.
                check(imported.all { (host, pins) -> stored[host] == pins })
                stored
            }
        if (entries.isNotEmpty()) {
            syncDirectory(directory)
            syncDirectory(checkNotNull(directory.parentFile))
            check(read() == policy)
            val editor = legacy.edit()
            entries.keys.forEach(editor::remove)
            check(editor.commit())
        }
        return policy
    }

    private fun decodeLegacy(entries: Map<String, *>): Map<String, Set<String>> {
        check(entries.size <= MAX_HOSTS)
        return entries
            .mapKeys { (key, _) ->
                val host = key.removePrefix(PREFIX)
                // Old writers lowercased host keys. Ambiguous/noncanonical keys cannot silently disappear.
                check(host == canonicalHost(host))
                host
            }.mapValues { (_, value) ->
                check(value is Set<*>)
                check(value.size <= MAX_PINS)
                value
                    .map { pin ->
                        check(pin is String)
                        checkedPin(pin)
                    }.toSet()
            }
    }

    private fun read(): Map<String, Set<String>>? {
        val target = File(directory, STORE_NAME)
        val backup = File(target.path + ".bak")
        val source = if (backup.exists()) backup else target
        if (!source.exists()) {
            // An orphan pending file is recovery evidence, never evidence of an unpinned install.
            check(!File(target.path + ".new").exists())
            return null
        }
        // Read the recovery source without AtomicFile.openRead deleting/renaming any recovery files.
        val bytes =
            source.inputStream().use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(1024)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    check(output.size() + count <= MAX_BYTES)
                    output.write(buffer, 0, count)
                }
                output.toByteArray()
            }
        check(bytes.size in DIGEST_BYTES..MAX_BYTES)
        val payload = bytes.copyOf(bytes.size - DIGEST_BYTES)
        val digest = bytes.copyOfRange(payload.size, bytes.size)
        check(MessageDigest.isEqual(MessageDigest.getInstance("SHA-256").digest(payload), digest))
        return DataInputStream(ByteArrayInputStream(payload)).use { input ->
            check(input.readInt() == MAGIC && input.readInt() == VERSION)
            val count = input.readInt()
            check(count in 0..MAX_HOSTS)
            val result = linkedMapOf<String, Set<String>>()
            repeat(count) {
                val host = input.readUTF()
                check(host == canonicalHost(host) && host !in result)
                val pinCount = input.readInt()
                check(pinCount in 0..MAX_PINS)
                val pins = List(pinCount) { checkedPin(input.readUTF()) }.toSet()
                check(pins.size == pinCount)
                result[host] = pins
            }
            check(input.read() == -1)
            result
        }
    }

    @Suppress("TooGenericExceptionCaught") // AtomicFile rollback must cover every unsuccessful write.
    private fun write(policy: Map<String, Set<String>>) {
        val payload =
            ByteArrayOutputStream()
                .also { output ->
                    DataOutputStream(output).use { data ->
                        data.writeInt(MAGIC)
                        data.writeInt(VERSION)
                        data.writeInt(policy.size)
                        policy.toSortedMap().forEach { (host, pins) ->
                            data.writeUTF(host)
                            data.writeInt(pins.size)
                            pins.sorted().forEach(data::writeUTF)
                        }
                    }
                }.toByteArray()
        val bytes = payload + MessageDigest.getInstance("SHA-256").digest(payload)
        check(bytes.size <= MAX_BYTES)
        check(directory.isDirectory || directory.mkdirs())
        val atomic = AtomicFile(File(directory, STORE_NAME))
        val stream = atomic.startWrite()
        try {
            stream.write(bytes)
            stream.fd.sync()
            atomic.finishWrite(stream)
        } catch (failure: Exception) {
            atomic.failWrite(stream)
            throw failure
        }
    }

    private fun syncDirectory(path: File) {
        // Persist the directory entry before deleting the only legacy copy of the policy.
        val descriptor = Os.open(path.path, OsConstants.O_RDONLY, 0)
        try {
            check(OsConstants.S_ISDIR(Os.fstat(descriptor).st_mode))
            Os.fsync(descriptor)
        } finally {
            Os.close(descriptor)
        }
    }

    private fun canonicalHost(host: String): String {
        check(host.isNotEmpty() && host.length <= 253 && '*' !in host)
        return HttpUrl
            .Builder()
            .scheme("https")
            .host(host.lowercase(Locale.ROOT))
            .build()
            .host
    }

    private fun checkedPin(pin: String): String {
        check(pin.length <= 64)
        val algorithm = pin.substringBefore('/')
        val expectedBytes =
            when (algorithm) {
                "sha256" -> 32
                "sha1" -> 20
                else -> error("Invalid pin policy")
            }
        val encoded = pin.substringAfter('/', "")
        val decoded = Base64.getDecoder().decode(encoded)
        check(decoded.size == expectedBytes && Base64.getEncoder().encodeToString(decoded) == encoded)
        return pin
    }

    private companion object {
        const val PREFIX = "pins."
        const val STORE_NAME = "legacy-v1.bin"
        const val MAGIC = 0x5250494E
        const val VERSION = 1
        const val MAX_HOSTS = 128
        const val MAX_PINS = 32
        const val DIGEST_BYTES = 32
        const val MAX_BYTES = 64 * 1024
        val storeLock = Any()
    }
}
