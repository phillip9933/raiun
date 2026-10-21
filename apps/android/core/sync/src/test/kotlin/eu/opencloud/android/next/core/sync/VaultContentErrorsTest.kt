package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.crypto.VaultContentIntegrityException
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.IOException

class VaultContentErrorsTest {
    @Test fun `rejected ciphertext reports integrity instead of lost file permission`() {
        val failure =
            assertThrows(OpenCloudException::class.java) {
                authenticatedVaultContent { throw VaultContentIntegrityException() }
            }
        assertEquals(OpenCloudError.DownloadIntegrity, failure.error)
    }

    @Test fun `real source permission and network failures retain their meaning`() {
        val permission = SecurityException("synthetic provider denial")
        val network = IOException("synthetic read failure")
        assertSame(
            permission,
            assertThrows(SecurityException::class.java) { authenticatedVaultContent { throw permission } },
        )
        assertSame(network, assertThrows(IOException::class.java) { authenticatedVaultContent { throw network } })
    }
}
