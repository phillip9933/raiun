package eu.opencloud.android.next.core.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.gestures.rememberTransformableState
import androidx.compose.foundation.gestures.transformable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.datastore.PreviewKind
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.withContext
import java.io.File

@Composable
@Suppress("LongParameterList") // File identity, loading and independent viewer actions.
fun FilePreviewRoute(
    name: String,
    kind: PreviewKind,
    onClose: () -> Unit,
    onOpenWith: () -> Unit,
    load: suspend (File) -> Unit,
    onEdit: (() -> Unit)? = null,
) {
    val context = LocalContext.current
    val loader by rememberUpdatedState(load)
    var state by remember { mutableStateOf(FilePreviewState()) }
    var snapshot by remember { mutableStateOf<File?>(null) }
    var page by remember { mutableIntStateOf(0) }
    var retry by remember { mutableIntStateOf(0) }
    BackHandler(onBack = onClose)
    LaunchedEffect(retry) {
        var file: File? = null
        try {
            val target = File.createTempFile("preview-", ".bin", context.cacheDir)
            file = target
            snapshot = null
            state = FilePreviewState()
            withContext(Dispatchers.IO) { loader(target) }
            page = 0
            snapshot = target
            awaitCancellation()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            state = FilePreviewState(loading = false, failed = true)
        } finally {
            file?.delete()
        }
    }
    LaunchedEffect(snapshot, page) {
        val file = snapshot ?: return@LaunchedEffect
        state = state.copy(loading = true)
        state =
            try {
                withContext(Dispatchers.IO) { readPreview(file, kind, page) }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                FilePreviewState(loading = false, failed = true)
            }
    }
    FilePreviewScreen(name, state, onClose, onOpenWith, { page = it }, { retry++ }, onEdit = onEdit)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongParameterList") // Viewer state and independent user actions.
fun FilePreviewScreen(
    name: String,
    state: FilePreviewState,
    onClose: () -> Unit,
    onOpenWith: (() -> Unit)?,
    onPage: (Int) -> Unit,
    onRetry: (() -> Unit)?,
    modifier: Modifier = Modifier,
    onEdit: (() -> Unit)? = null,
) {
    Scaffold(modifier = modifier, topBar = {
        TopAppBar(title = { Text(name, maxLines = 1) }, navigationIcon = {
            IconButton(
                onClick = onClose,
            ) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.preview_back)) }
        })
    }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            Row {
                onOpenWith?.let { openWith ->
                    TextButton(onClick = openWith) { Text(stringResource(R.string.preview_open_with)) }
                }
                onEdit?.let { edit ->
                    TextButton(
                        onClick = edit,
                        enabled = !state.loading && !state.failed,
                    ) { Text(stringResource(R.string.preview_edit)) }
                }
            }
            Box(Modifier.weight(1f).fillMaxSize().clipToBounds(), contentAlignment = Alignment.Center) {
                if (state.loading) {
                    CircularProgressIndicator()
                } else if (state.failed) {
                    Column(Modifier.padding(OpenCloudDimensions.SpacingMd)) {
                        Text(stringResource(R.string.preview_failed))
                        onRetry?.let { retry ->
                            TextButton(onClick = retry) { Text(stringResource(R.string.preview_retry)) }
                        }
                    }
                } else {
                    state.text?.let { text ->
                        SelectionContainer {
                            Text(
                                text,
                                Modifier
                                    .fillMaxSize()
                                    .verticalScroll(
                                        rememberScrollState(),
                                    ).padding(OpenCloudDimensions.SpacingMd),
                            )
                        }
                    }
                    state.bitmap?.let { bitmap ->
                        var scale by remember(bitmap) { mutableFloatStateOf(1f) }
                        var offset by remember(bitmap) { mutableStateOf(Offset.Zero) }
                        val transform =
                            rememberTransformableState { zoom, pan, _ ->
                                scale = (scale * zoom).coerceIn(1f, 5f)
                                offset = if (scale == 1f) Offset.Zero else offset + pan
                            }
                        Image(
                            bitmap.asImageBitmap(),
                            name,
                            Modifier
                                .fillMaxSize()
                                .graphicsLayer {
                                    scaleX = scale
                                    scaleY = scale
                                    translationX = offset.x
                                    translationY = offset.y
                                }.transformable(transform),
                        )
                    }
                }
            }
            if (state.pages > 0) {
                Row(horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
                    TextButton(onClick = { onPage(state.page - 1) }, enabled = !state.loading && state.page > 0) {
                        Text(stringResource(R.string.preview_previous))
                    }
                    Text(stringResource(R.string.preview_page, state.page + 1, state.pages))
                    TextButton(
                        onClick = { onPage(state.page + 1) },
                        enabled =
                            !state.loading && state.page + 1 < state.pages,
                    ) {
                        Text(stringResource(R.string.preview_next))
                    }
                }
            }
        }
    }
}
