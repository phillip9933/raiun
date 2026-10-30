package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavEntry
import eu.opencloud.android.next.core.network.VaultDavListing
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class VaultOfflineGroupSourceTest {
    private val location =
        VaultLocation(
            "account",
            "",
            VaultLocationKind.FOLDER_VAULT,
            "drive",
            "vault-id",
            "root-id",
            "https://example.test/",
            "https://example.test/dav/files/",
            "Secret.vault",
            true,
        )
    private val identity = VaultIdentity("account", location.canonicalServer, "drive", "vault-id")
    private val selected = entry("vault-id", "Secret.vault", true)

    @Test fun boundedPagesPreserveOriginalCiphertextNamesSizesAndVersions() =
        runBlocking {
            source { consume ->
                repeat(257) { consume(entry("file-$it", "Secret.vault/RAW-$it", false)) }
                listing()
            }.use { source ->
                source.openDirectory(selected).use { snapshot ->
                    assertEquals(257L, snapshot.totalCount)
                    var after = 0L
                    while (after < snapshot.totalCount) {
                        val page = snapshot.page(after)
                        page.forEach { captured ->
                            val raw = source.rawEntry(captured)
                            assertEquals(97L, raw.size)
                            assertEquals("\"version\"", raw.strongETag)
                            assertEquals(raw.relativePath.substringAfterLast('/'), raw.rawName)
                        }
                        after += page.size
                    }
                    assertEquals(257L, after)
                }
            }
        }

    @Test fun changedParentAtEndOfCompleteStreamDoesNotYieldASnapshot() {
        source { consume ->
            consume(entry("file", "Secret.vault/RAW", false))
            listing(selected.copy(id = "replacement-parent"))
        }.use { source ->
            val failure =
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { source.openDirectory(selected) }
                }
            assertEquals(OpenCloudError.PreconditionFailed, failure.error)
        }
    }

    @Test fun malformedOrOutsideEncryptedPathsAreRejectedBeforeHrefUse() {
        source { listing() }.use { source ->
            listOf(
                "Other.vault/RAW",
                "/Secret.vault/RAW",
                "Secret.vault//RAW",
                "Secret.vault/../RAW",
                "Secret.vault/RAW/",
                "Secret.vault/RAW\\escape",
            ).forEach { path ->
                assertThrows(OpenCloudException::class.java) {
                    source.rawEntry(BoundaryEntry("file", path, "RAW", false, 97, "\"version\""))
                }
            }
        }
    }

    @Test fun revokedPermitPreventsReadingAnAlreadyCapturedDirectory() {
        var allowed = true
        source(check = { if (!allowed) throw OpenCloudException(OpenCloudError.AccessDenied) }) { consume ->
            consume(entry("file", "Secret.vault/RAW", false))
            listing()
        }.use { source ->
            runBlocking {
                source.openDirectory(selected).use { snapshot ->
                    allowed = false
                    val failure = assertThrows(OpenCloudException::class.java) { runBlocking { snapshot.page() } }
                    assertEquals(OpenCloudError.AccessDenied, failure.error)
                }
            }
        }
    }

    @Test fun nestedVaultMarkerIsRejectedBeforeItsDescriptorLosesMarkerEvidence() {
        source { consume ->
            consume(entry("nested", "Secret.vault/RAW-NESTED", true).copy(isVaultMarker = true))
            listing()
        }.use { source ->
            val failure =
                assertThrows(OpenCloudException::class.java) { runBlocking { source.openDirectory(selected) } }
            assertEquals(OpenCloudError.PreconditionFailed, failure.error)
        }
    }

    @Test fun directoryBecomingAVaultAfterParentCaptureIsRejected() {
        val nested = entry("nested", "Secret.vault/RAW-NESTED", true)
        source { listing(nested.copy(isVaultMarker = true)).copy(requestedIsVaultMarker = true) }.use { source ->
            val failure = assertThrows(OpenCloudException::class.java) { runBlocking { source.openDirectory(nested) } }
            assertEquals(OpenCloudError.PreconditionFailed, failure.error)
        }
    }

    @Test fun closeWipesBorrowedPreparationMaterialAndRevokesFurtherUse() {
        val material = ByteArray(80) { 12 }
        val source = source(material = material) { listing() }
        source.close()
        assertArrayEquals(ByteArray(80), material)
        assertThrows(OpenCloudException::class.java) { source.checkActive() }
        source.close()
    }

    private fun source(
        material: ByteArray = ByteArray(80) { 12 },
        check: () -> Unit = {},
        stream: ((VaultDavEntry) -> Unit) -> VaultDavListing,
    ) = VaultOfflineGroupSource(
        RuntimeEnvironment.getApplication(),
        identity,
        location,
        selected,
        null,
        material,
        validateRoot = { check() },
        checkSession = check,
        decryptName = { "decoded-$it" },
        stream = { _, _, consume -> stream(consume) },
    )

    private fun entry(
        id: String,
        path: String,
        folder: Boolean,
    ) = VaultDavEntry(
        id,
        path,
        path.substringAfterLast('/'),
        folder,
        if (folder) 0 else 97,
        "\"version\"",
        resolveEntryHref(location.rootWebDavUrl, path),
    )

    private fun listing(root: VaultDavEntry = selected) = VaultDavListing(root, emptyList(), null, true)
}
