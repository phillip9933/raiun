package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.VaultGroupOwner
import eu.opencloud.android.next.core.database.VaultGroupSeal
import eu.opencloud.android.next.core.network.DownloadExpectation
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavEntry
import eu.opencloud.android.next.core.security.VaultIdentity
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Framing contains only original opaque DAV descriptors; decryption/display labels never enter this codec. */
internal object VaultOfflineGroupPlanCodec {
    const val MAX_RECORD_BYTES = 1024 * 1024
    private val magic = "RVG1".toByteArray(Charsets.US_ASCII)

    fun context(value: VaultOfflineGroupContext): ByteArray {
        validateContext(value)
        return frame {
            writeInt(1)
            listOf(
                value.groupId,
                value.owner.accountId,
                value.owner.incarnation,
                value.owner.accountIdentityDigest,
                value.identity.accountId,
                value.identity.canonicalServer,
                value.identity.driveId,
                value.identity.remoteVaultId,
                value.location.kind.name,
                value.location.sourceRootId,
                value.location.rootWebDavUrl,
                value.location.vaultPath,
                value.selectedEncryptedRoot,
            ).forEach { text(it) }
            nullable(value.rootProofDigest)
            text(value.baseOfflineRootDigest)
        }
    }

    fun readContext(bytes: ByteArray): VaultOfflineGroupContext =
        decode(bytes) {
            require(readInt() == 1)
            val group = text()
            val owner = VaultGroupOwner(text(), text(), text())
            val identity = VaultIdentity(text(), text(), text(), text())
            val kind = VaultLocationKind.valueOf(text())
            val location =
                VaultLocation(
                    owner.accountId,
                    "",
                    kind,
                    identity.driveId,
                    identity.remoteVaultId,
                    text(),
                    identity.canonicalServer,
                    text(),
                    text(),
                    true,
                )
            VaultOfflineGroupContext(
                group,
                owner,
                identity,
                location,
                text(),
                nullable(),
                text(),
            ).also(::validateContext)
        }

    fun createMember(
        context: VaultOfflineGroupContext,
        sequence: Long,
        source: VaultDavEntry,
        payloadId: String?,
        payloadDigest: String?,
    ): VaultOfflineGroupMember {
        val member =
            VaultOfflineGroupMember(
                sequence,
                UUID.randomUUID().toString(),
                if (source.isFolder) VaultOfflineGroupMemberKind.DIRECTORY else VaultOfflineGroupMemberKind.FILE,
                source,
                payloadId,
                payloadDigest,
                "",
            )
        validateMember(context, member)
        return member.copy(descriptorDigest = memberDigest(context, member))
    }

    fun member(value: VaultOfflineGroupMember): ByteArray =
        frame {
            writeLong(value.sequence)
            text(value.id)
            writeByte(value.kind.ordinal)
            source(value.source)
            nullable(value.payloadId)
            nullable(value.payloadDescriptorDigest)
        }

    fun readMember(
        context: VaultOfflineGroupContext,
        bytes: ByteArray,
    ): VaultOfflineGroupMember =
        checked {
            val value =
                decode(bytes) {
                    VaultOfflineGroupMember(
                        readLong(),
                        text(),
                        VaultOfflineGroupMemberKind.entries[readUnsignedByte()],
                        source(),
                        nullable(),
                        nullable(),
                        "",
                    )
                }
            validateMember(context, value)
            value.copy(descriptorDigest = memberDigest(context, value))
        }

    private fun memberDigest(
        context: VaultOfflineGroupContext,
        value: VaultOfflineGroupMember,
    ): String =
        digest(
            frame {
                text(context.descriptorDigest)
                val encoded = member(value)
                writeInt(encoded.size)
                write(encoded)
            },
        )

    fun jobDigest(job: VaultDownloadJob): String =
        digest(
            frame {
                text(job.id)
                text(encodeLocation(job.location.copy(title = "", offlineOnly = false)))
                source(job.source)
                nullable(job.rootProofDigest)
            },
        )

    fun seal(
        context: VaultOfflineGroupContext,
        counts: LongArray,
        contentDigest: ByteArray,
        material: ByteArray,
    ): ByteArray {
        val header = header(counts)
        val key = key(context, material)
        return try {
            header + VaultOfflineIndexCodec.encrypt(key, aad(context, header), contentDigest)
        } finally {
            key.fill(0)
        }
    }

    fun sealInfo(
        context: VaultOfflineGroupContext,
        bytes: ByteArray,
    ): VaultGroupSeal =
        checked {
            require(bytes.size == 88 && bytes.copyOfRange(0, 4).contentEquals(magic))
            val counts =
                DataInputStream(bytes.inputStream()).use {
                    it.skipBytes(4)
                    longArrayOf(it.readLong(), it.readLong(), it.readLong())
                }
            require(counts[0] >= 1 && counts[1] in 0..counts[0] && counts[2] >= 0)
            VaultGroupSeal(context.groupId, digest(bytes), counts[0], counts[1], counts[2])
        }

    fun authenticateSeal(
        context: VaultOfflineGroupContext,
        bytes: ByteArray,
        material: ByteArray,
    ): ByteArray {
        sealInfo(context, bytes)
        val key = key(context, material)
        return try {
            VaultOfflineIndexCodec
                .decrypt(
                    key,
                    aad(context, bytes.copyOfRange(0, 28)),
                    bytes.copyOfRange(28, bytes.size),
                ).also { if (it.size != 32) integrity() }
        } finally {
            key.fill(0)
        }
    }

    fun update(
        hash: MessageDigest,
        sequence: Long,
        bytes: ByteArray,
    ) {
        hash.update(
            frame {
                writeLong(sequence)
                writeInt(bytes.size)
            },
        )
        hash.update(bytes)
    }

    fun digest(bytes: ByteArray): String =
        MessageDigest
            .getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it) }

    fun validateContext(value: VaultOfflineGroupContext) {
        uuid(value.groupId)
        incarnation(value.owner.incarnation)
        hash(value.owner.accountIdentityDigest)
        hash(value.baseOfflineRootDigest)
        value.rootProofDigest?.let(::hash)
        require(value.owner.accountId == value.identity.accountId && value.owner.accountId == value.location.accountId)
        require(value.owner.accountId.isNotBlank() && value.identity.driveId.isNotBlank())
        require(
            value.location.canonicalServer == value.identity.canonicalServer &&
                value.location.driveId == value.identity.driveId,
        )
        require(
            value.location.remoteVaultId == value.identity.remoteVaultId &&
                value.location.isVaultRoot &&
                !value.location.isDisabled,
        )
        require(value.location.title.isEmpty() && !value.location.offlineOnly)
        require(value.location.kind in setOf(VaultLocationKind.FOLDER_VAULT, VaultLocationKind.SPACE_VAULT))
        require(value.identity.remoteVaultId.isNotBlank() && value.location.sourceRootId.isNotBlank())
        path(value.location.vaultPath, allowEmpty = true)
        path(value.selectedEncryptedRoot, allowEmpty = true)
        require(inside(value.selectedEncryptedRoot, value.location.vaultPath))
        safeUrl(value.location.rootWebDavUrl)
        safeUrl(value.identity.canonicalServer)
    }

    @Suppress("CyclomaticComplexMethod") // Every root, source, URL and payload binding is independently required.
    fun validateMember(
        context: VaultOfflineGroupContext,
        value: VaultOfflineGroupMember,
    ) {
        require(value.sequence >= 0)
        uuid(value.id)
        val source = value.source
        require(source.id.isNotBlank() && source.isFolder == (value.kind == VaultOfflineGroupMemberKind.DIRECTORY))
        path(source.relativePath, allowEmpty = value.sequence == 0L)
        require(inside(source.relativePath, context.selectedEncryptedRoot))
        if (value.sequence == 0L) {
            require(source.isFolder && source.relativePath == context.selectedEncryptedRoot)
            if (source.relativePath == context.location.vaultPath) {
                require(source.id == context.identity.remoteVaultId)
            } else {
                require(source.rawName == source.relativePath.substringAfterLast('/') && !source.isVaultMarker)
            }
        } else {
            require(source.relativePath != context.selectedEncryptedRoot && !source.isVaultMarker)
            require(source.rawName == source.relativePath.substringAfterLast('/'))
        }
        require(source.size >= 0)
        source.strongETag?.let { require(DownloadExpectation(source.size, it).strongETag == it) }
        val href = safeUrl(source.href)
        val root = safeUrl(context.location.rootWebDavUrl)
        require(href.scheme == root.scheme && href.host == root.host && href.port == root.port)
        require(
            href.pathSegments.dropLastWhile(String::isEmpty) ==
                root.pathSegments.dropLastWhile(String::isEmpty) +
                source.relativePath.split('/').filter(String::isNotEmpty),
        )
        if (source.isFolder) {
            // DAV collections may carry aggregate sizes; retain that authenticated descriptor without a payload.
            require(value.payloadId == null && value.payloadDescriptorDigest == null)
        } else {
            require(source.size >= 32 && !source.isVaultMarker)
            uuid(requireNotNull(value.payloadId))
            hash(requireNotNull(value.payloadDescriptorDigest))
        }
    }

    fun uuid(value: String) {
        require(UUID.fromString(value).toString() == value)
    }

    fun incarnation(value: String) {
        require(value.matches(Regex("[a-f0-9]{32}")))
    }

    fun hash(value: String) {
        require(value.matches(Regex("[a-f0-9]{64}")))
    }

    fun inside(
        path: String,
        root: String,
    ): Boolean = path == root || root.isEmpty() || path.startsWith("$root/")

    fun integrity(): Nothing = throw OpenCloudException(OpenCloudError.DownloadIntegrity)

    private fun path(
        value: String,
        allowEmpty: Boolean,
    ) {
        if (value.isEmpty()) {
            require(allowEmpty)
            return
        }
        require(
            value.split('/').none {
                it.isEmpty() ||
                    it in setOf(".", "..") ||
                    it.any { c -> c == '\\' || c.isISOControl() }
            },
        )
    }

    private fun safeUrl(value: String) =
        value.toHttpUrl().also {
            require(it.username.isEmpty() && it.password.isEmpty() && it.query == null && it.fragment == null)
        }

    private fun header(counts: LongArray): ByteArray =
        frame {
            write(magic)
            counts.forEach(::writeLong)
        }

    private fun aad(
        context: VaultOfflineGroupContext,
        header: ByteArray,
    ): ByteArray =
        frame {
            text("raiun-offline-group-seal-v1")
            val bytes = VaultOfflineGroupPlanCodec.context(context)
            writeInt(bytes.size)
            write(bytes)
            write(header)
        }

    private fun key(
        context: VaultOfflineGroupContext,
        material: ByteArray,
    ): ByteArray {
        val master = deriveManifestKey(material, context.identity)
        return try {
            Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(master, "HmacSHA256"))
                doFinal(
                    frame {
                        text("raiun-offline-group-plan-v1")
                        text(context.groupId)
                        text(context.owner.incarnation)
                    },
                )
            }
        } finally {
            master.fill(0)
        }
    }

    private fun frame(write: DataOutputStream.() -> Unit): ByteArray =
        ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use(write)
            bytes.toByteArray().also { require(it.size <= MAX_RECORD_BYTES) }
        }

    @Suppress("TooGenericExceptionCaught") // Malformed private record formats fail as integrity errors.
    private fun <T> decode(bytes: ByteArray, read: DataInputStream.() -> T): T =
        try {
            require(bytes.size <= MAX_RECORD_BYTES)
            DataInputStream(bytes.inputStream()).use { input -> read(input).also { require(input.read() == -1) } }
        } catch (failure: OpenCloudException) {
            throw failure
        } catch (_: Exception) {
            integrity()
        }

    @Suppress("TooGenericExceptionCaught") // Typed cryptographic failures are retained; malformed fields fail closed.
    private fun <T> checked(
        read: () -> T,
    ): T =
        try {
            read()
        } catch (failure: OpenCloudException) {
            throw failure
        } catch (_: Exception) {
            integrity()
        }

    private fun DataOutputStream.text(value: String) {
        val buffer =
            Charsets.UTF_8
                .newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(CharBuffer.wrap(value))
        require(buffer.remaining() <= MAX_RECORD_BYTES)
        writeInt(buffer.remaining())
        val bytes = ByteArray(buffer.remaining())
        buffer.get(bytes)
        write(bytes)
    }

    private fun DataInputStream.text(): String {
        val size = readInt()
        require(size in 0..MAX_RECORD_BYTES)
        return VaultOfflineIndexCodec.text(ByteArray(size).also(::readFully))
    }

    private fun DataOutputStream.nullable(value: String?) {
        writeByte(
            if (value ==
                null
            ) {
                0
            } else {
                1
            },
        )
        value?.let { text(it) }
    }

    private fun DataInputStream.nullable(): String? =
        when (readUnsignedByte()) {
            0 -> null
            1 -> text()
            else -> integrity()
        }

    private fun DataOutputStream.source(value: VaultDavEntry) {
        listOf(value.id, value.relativePath, value.rawName).forEach { text(it) }
        writeByte(if (value.isFolder) 1 else 0)
        writeLong(value.size)
        nullable(value.strongETag)
        text(value.href)
        writeByte(if (value.isVaultMarker) 1 else 0)
    }

    private fun DataInputStream.source(): VaultDavEntry =
        VaultDavEntry(text(), text(), text(), flag(), readLong(), nullable(), text(), flag())

    private fun DataInputStream.flag(): Boolean =
        when (readUnsignedByte()) {
            0 -> false
            1 -> true
            else -> integrity()
        }
}
