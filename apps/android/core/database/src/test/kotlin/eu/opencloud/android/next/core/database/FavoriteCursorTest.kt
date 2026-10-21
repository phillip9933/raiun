package eu.opencloud.android.next.core.database

import androidx.room.Room
import androidx.room.RoomDatabase
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class FavoriteCursorTest {
    @Test fun `cursor survives restart and rejects stale or removed account writers`() =
        runTest {
            val context = RuntimeEnvironment.getApplication()
            val name = "favorite-cursor.db"
            context.deleteDatabase(name)

            fun open() =
                Room
                    .databaseBuilder(context, FileBrowserDatabase::class.java, name)
                    .setJournalMode(RoomDatabase.JournalMode.TRUNCATE)
                    .build()
            var database = open()
            try {
                database.accountDao().upsert(
                    AccountEntity("a", "https://cloud.example", "user", "User", "BASIC", false),
                )
                database.accountDao().upsert(
                    AccountEntity("b", "https://cloud.example", "user", "User", "BASIC", false),
                )
                val first = requireNotNull(FileBrowserStore(database).advanceFavoriteCursor("a", "s", "one", null))
                database.close()
                database = open()
                val store = FileBrowserStore(database)
                assertEquals(first, store.favoriteCursor("a"))
                val next = store.advanceFavoriteCursor("a", "s", "two", first)
                assertNotNull(next)
                assertNull(store.advanceFavoriteCursor("a", "s", "stale", first))
                val other = store.advanceFavoriteCursor("b", "s", "other", null)
                store.removeAccount("a")
                assertNull(store.favoriteCursor("a"))
                assertNull(store.advanceFavoriteCursor("a", "s", "late", next))
                assertNull(store.advanceFavoriteCursor("a", "s", "late", null))
                assertEquals(other, store.favoriteCursor("b"))
            } finally {
                database.close()
                context.deleteDatabase(name)
            }
        }
}
