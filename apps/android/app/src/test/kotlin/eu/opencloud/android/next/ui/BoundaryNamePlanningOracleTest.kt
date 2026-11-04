package eu.opencloud.android.next.ui

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.sync.BoundaryEndpoint
import eu.opencloud.android.next.core.sync.BoundaryEntry
import eu.opencloud.android.next.core.sync.BoundaryNameIndex
import eu.opencloud.android.next.core.sync.VaultFolder
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.InputStream
import java.io.OutputStream

/** Oracle retains the previous Set algorithm in the test; production planning must use reservations. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class BoundaryNamePlanningOracleTest {
    @Test fun chosenWritesMatchOldExactSetSemanticsForFileFolderDotUnicodeAndSelectedDuplicates() =
        runBlocking<Unit> {
            val selected =
                listOf(
                    "fresh.txt" to false,
                    "report.txt" to false,
                    "report.txt" to false,
                    "archive.tar.gz" to false,
                    ".env" to false,
                    ".config.json" to false,
                    "folder.v1" to true,
                    "folder.v1" to true,
                    "name." to false,
                    "résumé.txt" to false,
                    "Résumé.txt" to false,
                    "İ.txt" to false,
                    "i.txt" to false,
                )
            val existing =
                setOf(
                    "report.txt",
                    "report (1).txt",
                    "archive.tar.gz",
                    ".env",
                    ".config.json",
                    "folder.v1",
                    "name.",
                    "résumé.txt",
                )
            val fixture = Fixture(selected, existing)
            val dispatcher = Dispatchers.Unconfined
            val controller = fixture.controller(dispatcher)
            try {
                awaitIdle(controller)
                controller.select(fixture.targetLocation)
                awaitIdle(controller)
                controller.transfer()
                awaitIdle(controller)
                val oracle = legacyPlan(selected, existing)
                assertEquals(
                    "report.txt",
                    controller.state.value.conflict
                        ?.name,
                )
                assertEquals(
                    oracle[1],
                    controller.state.value.conflict
                        ?.proposedName,
                )
                assertEquals(0, fixture.target.mutations)
                assertEquals(1, fixture.target.captures)
                assertEquals(1, fixture.target.closedIndexes)
                controller.keepBoth()
                awaitIdle(controller)
                assertTrue(controller.state.value.complete)
                assertEquals(oracle, fixture.target.createdNames)
                assertEquals(2, fixture.target.captures)
                assertEquals(2, fixture.target.closedIndexes)
            } finally {
                controller.close()
            }
        }

    @Test fun conflictCancelWritesNothingAndKeepBothRecapturesNewRemoteCollision() =
        runBlocking<Unit> {
            val fixture = Fixture(listOf("note.txt" to false), setOf("note.txt"))
            val controller = fixture.controller(Dispatchers.Unconfined)
            try {
                awaitIdle(controller)
                controller.select(fixture.targetLocation)
                awaitIdle(controller)
                controller.transfer()
                awaitIdle(controller)
                assertEquals(
                    "note (1).txt",
                    controller.state.value.conflict
                        ?.proposedName,
                )
                controller.cancelConflict()
                awaitIdle(controller)
                assertNull(controller.state.value.conflict)
                assertEquals(0, fixture.target.mutations)
                assertEquals(1, fixture.target.closedIndexes)
                fixture.target.seedName("note (1).txt")
                controller.keepBoth()
                awaitIdle(controller)
                assertEquals(listOf("note (2).txt"), fixture.target.createdNames)
                assertEquals(2, fixture.target.captures)
                assertEquals(2, fixture.target.closedIndexes)
            } finally {
                controller.close()
            }
        }

    @Test fun everySelectedSourceIsPreflightedBeforeFirstDestinationWriteAndIndexIsClosed() =
        runBlocking<Unit> {
            val fixture = Fixture(listOf("one.txt" to false, "two.txt" to false), emptySet())
            fixture.source.refusedId = "source-1"
            val controller = fixture.controller(Dispatchers.Unconfined)
            try {
                awaitIdle(controller)
                controller.select(fixture.targetLocation)
                awaitIdle(controller)
                controller.transfer()
                awaitIdle(controller)
                assertEquals(0, fixture.target.mutations)
                assertFalse(controller.state.value.complete)
                assertEquals(OpenCloudError.PreconditionFailed, controller.state.value.error)
                assertEquals(listOf("source-0", "source-1"), fixture.source.checked)
                assertEquals(1, fixture.target.closedIndexes)
            } finally {
                controller.close()
            }
        }

    private suspend fun awaitIdle(controller: BoundaryDestinationController) {
        withTimeout(10_000) { controller.state.first { !it.loading && !it.transferring } }
    }

    /** Exact former algorithm: case-sensitive membership and extension split only after the first character. */
    private fun legacyPlan(
        selected: List<Pair<String, Boolean>>,
        initial: Set<String>,
    ): List<String> {
        val names = initial.toMutableSet()
        return selected.map { (original, directory) ->
            var candidate = original
            if (candidate in names) {
                val dot = if (directory) -1 else original.lastIndexOf('.').takeIf { it > 0 } ?: -1
                val stem = if (dot < 0) original else original.substring(0, dot)
                val suffix = if (dot < 0) "" else original.substring(dot)
                var number = 1
                do {
                    candidate = "$stem (${number++})$suffix"
                } while (candidate in names)
            }
            names += candidate
            candidate
        }
    }

    private class Fixture(
        selected: List<Pair<String, Boolean>>,
        existing: Set<String>,
    ) {
        private val context = ApplicationProvider.getApplicationContext<Context>()
        val source = Endpoint("source")
        val target = Endpoint("target")
        val sourceLocation = location("source")
        val targetLocation = location("target")
        private val resources =
            selected.mapIndexed { index, (name, directory) ->
                val content = "source-$index".toByteArray()
                val entry =
                    BoundaryEntry(
                        "source-$index",
                        "selected-$index/$name",
                        name,
                        directory,
                        if (directory) 0 else content.size.toLong(),
                        "\"v1\"",
                        null,
                    )
                source.entries[entry.path] = entry
                if (!directory) source.contents[entry.path] = content
                ResourceEntity(
                    "account",
                    "source",
                    entry.id,
                    "selected-$index",
                    "/${entry.path}",
                    name,
                    if (directory) ResourceKind.FOLDER else ResourceKind.FILE,
                    null,
                    entry.size,
                    entry.version,
                    0,
                    0,
                )
            }

        init {
            existing.forEach(target::seedName)
        }

        fun controller(dispatcher: kotlinx.coroutines.CoroutineDispatcher) =
            BoundaryDestinationController(
                context,
                BoundaryTransferRequest("account", false, ordinary = resources),
                object : BoundaryDestinationRepository {
                    override suspend fun locations(accountId: String) = listOf(sourceLocation, targetLocation)

                    override suspend fun ordinaryEndpoint(
                        accountId: String,
                        location: VaultLocation,
                    ): BoundaryEndpoint = if (location.driveId == "source") source else target

                    override suspend fun folders(
                        accountId: String,
                        location: VaultLocation,
                        path: String,
                    ) = emptyList<VaultFolder>()

                    override suspend fun unlock(
                        accountId: String,
                        location: VaultLocation,
                        password: CharArray,
                    ): BoundaryUnlockedDestination = error("No encrypted destination in this planning fixture")
                },
                dispatcher = dispatcher,
                ioDispatcher = dispatcher,
            )

        private fun location(id: String) =
            VaultLocation(
                "account",
                id,
                VaultLocationKind.SPACE,
                id,
                id,
                id,
                "https://example.test/",
                "https://example.test/dav/$id/",
                "",
                false,
            )
    }

    private class Endpoint(
        override val identity: String,
    ) : BoundaryEndpoint {
        override val encrypted = false
        val entries = linkedMapOf<String, BoundaryEntry>()
        val contents = linkedMapOf<String, ByteArray>()
        val createdNames = mutableListOf<String>()
        val checked = mutableListOf<String>()
        var refusedId: String? = null
        var captures = 0
        var closedIndexes = 0
        var mutations = 0

        fun seedName(name: String) {
            entries[name] = BoundaryEntry("existing-$name", name, name, false, 0, "\"v1\"")
        }

        override suspend fun list(path: String) = entries.values.filter { it.path.substringBeforeLast('/', "") == path }

        override suspend fun openNameIndex(
            context: Context,
            path: String,
        ): BoundaryNameIndex {
            captures++
            val index = super<BoundaryEndpoint>.openNameIndex(context, path)
            return object : BoundaryNameIndex by index {
                override fun close() {
                    closedIndexes++
                    index.close()
                }
            }
        }

        override suspend fun requireUnchanged(entry: BoundaryEntry) {
            checked += entry.id
            if (entry.id == refusedId || entries[entry.path] != entry) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
        }

        override suspend fun read(
            entry: BoundaryEntry,
            sink: OutputStream,
        ) {
            requireUnchanged(entry)
            sink.write(contents.getValue(entry.path))
        }

        override suspend fun write(
            parent: String,
            name: String,
            source: InputStream,
            size: Long,
            mimeType: String?,
        ): BoundaryEntry {
            val content = source.readBytes()
            assertEquals(size, content.size.toLong())
            val entry = create(parent, name, false, size)
            contents[entry.path] = content
            return entry
        }

        override suspend fun createDirectory(
            parent: String,
            name: String,
        ): BoundaryEntry = create(parent, name, true, 0)

        private fun create(
            parent: String,
            name: String,
            directory: Boolean,
            size: Long,
        ): BoundaryEntry {
            check(closedIndexes == captures) // Planning store must close before preflight/copy side effects.
            val path = listOf(parent, name).filter(String::isNotEmpty).joinToString("/")
            check(path !in entries)
            mutations++
            createdNames += name
            return BoundaryEntry("target-$mutations", path, name, directory, size, "\"v1\"", null)
                .also { entries[path] = it }
        }

        override suspend fun delete(entry: BoundaryEntry) = error("Copy-only fixture must never delete")
    }
}
