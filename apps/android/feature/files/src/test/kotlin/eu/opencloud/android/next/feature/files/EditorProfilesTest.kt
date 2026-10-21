package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.network.OpenCloudException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class EditorProfilesTest {
    @Test fun `cleanup touches only canonical owned inactive profiles`() {
        val old = own()
        val storage = Storage(mutableSetOf("Default", "another-app", "opencloud-editor-foreign", old))
        val registry = EditorProfileRegistry(storage)
        val first = registry.acquire()
        storage.saved.add(first.name)
        val second = registry.acquire()
        assertEquals(listOf(old), storage.deleted)
        assertTrue(storage.saved.containsAll(listOf("Default", "another-app", "opencloud-editor-foreign", first.name)))
        assertNotEquals(first.name, second.name)
        assertFalse(storage.deleted.contains(first.name))
        first.close()
        first.close()
        assertEquals(1, storage.deleted.count { it == first.name })
        second.close()
    }

    @Test fun `loaded profile cleanup is deferred without ever reusing its identity`() {
        val old = own()
        val storage = Storage(mutableSetOf(old))
        storage.loaded.add(old)
        val registry = EditorProfileRegistry(storage)
        val lease = registry.acquire()
        assertNotEquals(old, lease.name)
        storage.saved.add(lease.name)
        storage.loaded.add(lease.name)
        lease.close()
        assertEquals("EditorProfileLease(redacted)", lease.toString())
        storage.loaded.clear()
        val next = EditorProfileRegistry(storage).acquire()
        assertFalse(old in storage.saved)
        assertFalse(lease.name in storage.saved)
        next.close()
    }

    @Test fun `retained profile limit fails closed rather than sharing a profile`() {
        val storage = Storage(MutableList(32) { own() }.toMutableSet())
        storage.loaded.addAll(storage.saved)
        assertThrows(OpenCloudException::class.java) { EditorProfileRegistry(storage).acquire() }
        assertEquals(32, storage.saved.size)
    }

    private fun own() = "opencloud-editor-${UUID.randomUUID()}"

    private class Storage(
        val saved: MutableSet<String>,
    ) : EditorProfileStorage {
        val loaded = mutableSetOf<String>()
        val deleted = mutableListOf<String>()

        override fun names(): Set<String> = saved.toSet()

        override fun delete(name: String) {
            check(name !in loaded)
            deleted.add(name)
            saved.remove(name)
        }
    }
}
