package eu.opencloud.android.next.core.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.crypto.RcloneVaultCipher
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class VaultOfflineStoreAndroidTest {
    @Test fun rcloneCiphertextPinsAndReopensWithPassword() =
        runBlocking {
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val root = File(context.cacheDir, "vault-offline-${UUID.randomUUID()}")
            val accountId = UUID.randomUUID().toString()
            val server = EndpointPolicy(true).endpoint("https://example.test/", allowQuery = false).toString()
            val account = AccountEntity(accountId, server, "user", "User", "BASIC", false)
            val location =
                VaultLocation(
                    accountId = accountId,
                    title = "Secret.vault",
                    kind = VaultLocationKind.FOLDER_VAULT,
                    driveId = "drive",
                    remoteVaultId = "vault-id",
                    sourceRootId = "root-id",
                    canonicalServer = server,
                    rootWebDavUrl = "https://example.test/dav/files/",
                    vaultPath = "Secret.vault",
                    isVaultRoot = true,
                )
            val identity = VaultIdentity(accountId, server, "drive", "vault-id")
            val password = "correct horse battery staple"
            val plain = "rclone encrypted offline payload".toByteArray()
            val cipher = RcloneVaultCipher.fromPassword(password.toCharArray())
            val encryptedName = cipher.encryptName("private.txt")
            val encrypted =
                ByteArrayOutputStream()
                    .also { output ->
                        cipher.encryptContent(plain.inputStream(), output, plain.size.toLong())
                    }.toByteArray()
            val keyMaterial = cipher.exportKeyMaterial()
            cipher.close()
            val store =
                VaultOfflineStore(
                    root,
                    { requestedId -> if (requestedId == accountId) account else null },
                    { { true } },
                    EndpointPolicy(true),
                    { RcloneVaultCipher.fromKeyMaterial(it).offlineEngine() },
                )
            try {
                val entry =
                    VaultFolder(
                        id = encryptedName,
                        name = encryptedName,
                        rawName = encryptedName,
                        path = encryptedName,
                        encryptedPath = "Secret.vault/$encryptedName",
                        isFolder = false,
                        size = encrypted.size.toLong(),
                        strongETag = "\"tag\"",
                    )
                store.pinFile(identity, location, entry, keyMaterial) { it.write(encrypted) }
                val session = store.openWithPassword(accountId, location, password.toCharArray())!!
                try {
                    val listed = session.list().single()
                    assertEquals("private.txt", listed.name)
                    val output = ByteArrayOutputStream()
                    session.download(listed, output)
                    assertArrayEquals(plain, output.toByteArray())
                } finally {
                    session.close()
                }
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { store.openWithPassword(accountId, location, "wrong password".toCharArray()) }
                }
            } finally {
                root.deleteRecursively()
                keyMaterial.fill(0)
                plain.fill(0)
                encrypted.fill(0)
            }
            Unit
        }
}
