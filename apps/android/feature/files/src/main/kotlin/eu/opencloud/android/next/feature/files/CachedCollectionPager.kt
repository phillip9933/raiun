package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.RESOURCE_DIRECTORY_PAGE_SIZE
import eu.opencloud.android.next.core.database.ResourceCollectionOptions
import eu.opencloud.android.next.core.database.ResourceCollectionPage
import eu.opencloud.android.next.core.database.ResourceCollectionRoot
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

internal data class CachedCollectionRequest(
    val account: String,
    val options: ResourceCollectionOptions,
    val revision: Long = 0,
    val accountRevision: Long = 0,
)

internal data class CachedCollectionState(
    val request: CachedCollectionRequest? = null,
    val result: ResourceCollectionPage? = null,
    val bytes: Long = 0,
    val error: Throwable? = null,
)

/**
 * One replaceable window. Synchronous account/options transitions run on Main;
 * asynchronous admission and byte-memo publication use the same dispatcher.
 */
@OptIn(ExperimentalCoroutinesApi::class)
internal class CachedCollectionPager(
    scope: CoroutineScope,
    private val invalidations: (String) -> Flow<Int>,
    private val load: suspend (CachedCollectionRequest) -> ResourceCollectionPage,
    private val bytes: suspend (CachedCollectionRequest) -> Long = { 0 },
    private val publicationDispatcher: CoroutineDispatcher = Dispatchers.Main.immediate,
) {
    private var revision = 0L
    private val request = MutableStateFlow<CachedCollectionRequest?>(null)
    private val mutableState = MutableStateFlow(CachedCollectionState())
    val state = mutableState.asStateFlow()
    private var verifiedBytes: Pair<ByteCacheKey, Long>? = null

    private data class Invalidation(
        val account: String,
        val revision: Long,
    )

    private data class ByteCacheKey(
        val account: String,
        val accountRevision: Long,
        val roots: List<ResourceCollectionRoot>,
        val databaseRevision: Long,
    )

    init {
        scope.launch(Dispatchers.IO) {
            var databaseRevision = 0L
            val databaseEvents =
                request.map { it?.account }.distinctUntilChanged().flatMapLatest { account ->
                    if (account ==
                        null
                    ) {
                        flowOf(null)
                    } else {
                        invalidations(account).map { Invalidation(account, ++databaseRevision) }
                    }
                }
            request
                .combine(databaseEvents) { current, invalidation ->
                    if (current != null &&
                        invalidation != null &&
                        invalidation.account == current.account
                    ) {
                        current to invalidation
                    } else {
                        null
                    }
                }.collectLatest { trigger ->
                    if (trigger != null) refresh(trigger.first, trigger.second.revision)
                }
        }
    }

    fun isCurrent(candidate: CachedCollectionRequest): Boolean = request.value == candidate

    fun account(account: String): CachedCollectionRequest {
        val current = request.value
        if (current?.account == account) return current
        val next =
            CachedCollectionRequest(
                account,
                request.value?.options?.copy(offset = 0, roots = emptyList()) ?: ResourceCollectionOptions(),
                ++revision,
                revision,
            )
        mutableState.value = CachedCollectionState(request = next)
        request.value = next
        return next
    }

    fun options(options: ResourceCollectionOptions) {
        val current = request.value ?: return
        val next =
            current.copy(
                options = options.copy(offset = 0, roots = current.options.roots),
                revision = ++revision,
            )
        if (current.options.copy(offset = 0) == next.options) return
        mutableState.value = CachedCollectionState(request = next)
        request.value = next
    }

    fun roots(roots: List<ResourceCollectionRoot>) {
        val current = request.value ?: return
        if (current.options.roots == roots) return
        val next = current.copy(options = current.options.copy(offset = 0, roots = roots), revision = ++revision)
        mutableState.value = CachedCollectionState(request = next)
        request.value = next
    }

    fun page(previous: Boolean) {
        val current = request.value
        val page = state.value.result?.page
        if (current == null || page == null) return
        val canMove = if (previous) page.hasPrevious else page.hasNext
        if (!canMove) return
        request.value =
            current.copy(
                revision = ++revision,
                options =
                    current.options.copy(
                        offset =
                            page.offset + if (previous) -RESOURCE_DIRECTORY_PAGE_SIZE else RESOURCE_DIRECTORY_PAGE_SIZE,
                    ),
            )
    }

    @Suppress("TooGenericExceptionCaught") // Retain verified window on failure and rethrow coroutine cancellation.
    private suspend fun refresh(current: CachedCollectionRequest, databaseRevision: Long) {
        try {
            val result = load(current)
            currentCoroutineContext().ensureActive()
            val key = ByteCacheKey(current.account, current.accountRevision, current.options.roots, databaseRevision)
            val cachedBytes =
                withContext(publicationDispatcher) {
                    verifiedBytes?.takeIf { it.first == key }?.second
                }
            val size = cachedBytes ?: bytes(current)
            currentCoroutineContext().ensureActive()
            withContext(publicationDispatcher) {
                currentCoroutineContext().ensureActive()
                if (request.value == current) {
                    verifiedBytes = key to size
                    mutableState.value = CachedCollectionState(current, result, size)
                }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            withContext(publicationDispatcher) {
                if (request.value == current) mutableState.update { it.copy(request = current, error = failure) }
            }
        }
    }
}
