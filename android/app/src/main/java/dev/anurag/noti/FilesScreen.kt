package dev.anurag.noti

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

class FileActions(
    val refresh: () -> Unit,
    val copy: (RemoteFile) -> Unit,
    val share: (RemoteFile) -> Unit,
    val download: (RemoteFile) -> Unit,
    val open: (RemoteFile) -> Unit,
    val delete: (RemoteFile) -> Unit,
    val clearAll: () -> Unit,
    val cancelJob: (Long) -> Unit,
    val dismissJob: (Long) -> Unit,
)

private enum class Sort { Newest, Largest }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FilesScreen(
    paired: Boolean,
    files: List<RemoteFile>?,
    stat: ServerStat?,
    jobs: List<UploadJob>,
    error: String?,
    refreshing: Boolean,
    a: FileActions,
) {
    var sort by remember { mutableStateOf(Sort.Newest) }
    var selected by remember { mutableStateOf<RemoteFile?>(null) }
    var confirmDelete by remember { mutableStateOf<RemoteFile?>(null) }
    var confirmClear by remember { mutableStateOf(false) }
    var menu by remember { mutableStateOf(false) }

    PullToRefreshBox(isRefreshing = refreshing, onRefresh = a.refresh, modifier = Modifier.fillMaxSize()) {
        LazyColumn(
            contentPadding = PaddingValues(start = 20.dp, end = 20.dp, bottom = 96.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
            modifier = Modifier.fillMaxSize(),
        ) {
            item {
                ScreenTitle("Files", "Upload from your phone, share a link anywhere") {
                    if (paired) Box {
                        IconButton(onClick = { menu = true }) { Icon(Icons.Default.MoreVert, "More") }
                        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                            DropdownMenuItem(text = { Text("Refresh") }, onClick = { menu = false; a.refresh() })
                            DropdownMenuItem(
                                text = { Text("Delete all files…", color = MaterialTheme.colorScheme.error) },
                                onClick = { menu = false; confirmClear = true },
                            )
                        }
                    }
                }
            }
            if (!paired) {
                item { EmptyState("Pair first", "Pair this phone with your laptop on the Home tab to use the file store.") }
                return@LazyColumn
            }
            stat?.let { item { StorageCard(it) } }
            if (error != null) item { ErrorCard(error, a.refresh) }
            items(jobs, key = { "job${it.id}" }) { JobCard(it, a) }

            if (files != null && files.isNotEmpty()) {
                item {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 4.dp)) {
                        Sort.entries.forEach {
                            FilterChip(selected = sort == it, onClick = { sort = it }, label = { Text(it.name) })
                        }
                    }
                }
                val sorted = when (sort) {
                    Sort.Newest -> files.sortedByDescending { it.uploaded }
                    Sort.Largest -> files.sortedByDescending { it.size }
                }
                items(sorted, key = { it.id }) { FileRow(it) { selected = it } }
            } else if (files != null && error == null && jobs.isEmpty()) {
                item { EmptyState("No files yet", "Tap Upload, or use Share → Noti from any app. A link is copied automatically.") }
            }
        }
    }

    selected?.let { f ->
        ModalBottomSheet(onDismissRequest = { selected = null }, sheetState = rememberModalBottomSheetState()) {
            Column(Modifier.padding(horizontal = 24.dp).padding(bottom = 32.dp)) {
                Text(f.name, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, maxLines = 2, overflow = TextOverflow.Ellipsis)
                Text(
                    "${humanSize(f.size)}  ·  uploaded ${ago(f.uploaded)}  ·  ${expiresIn(f.expires)}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 4.dp, bottom = 4.dp),
                )
                Text(f.url, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.primary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Gap(8)
                SheetAction(Glyphs.Copy, "Copy link") { a.copy(f); selected = null }
                SheetAction(Icons.Default.Share, "Share link") { a.share(f); selected = null }
                SheetAction(Glyphs.Download, "Download to phone") { a.download(f); selected = null }
                SheetAction(Glyphs.OpenInNew, "Open in browser") { a.open(f); selected = null }
                SheetAction(Icons.Default.Delete, "Delete", danger = true) { confirmDelete = f; selected = null }
            }
        }
    }

    confirmDelete?.let { f ->
        AlertDialog(
            onDismissRequest = { confirmDelete = null },
            title = { Text("Delete file?") },
            text = { Text("${f.name} (${humanSize(f.size)}) will be removed and its link stops working.") },
            confirmButton = { TextButton(onClick = { a.delete(f); confirmDelete = null }) { Text("Delete", color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = { confirmDelete = null }) { Text("Cancel") } },
        )
    }
    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text("Delete all files?") },
            text = { Text("Every uploaded file is removed from the server and all links stop working. This can't be undone.") },
            confirmButton = { TextButton(onClick = { a.clearAll(); confirmClear = false }) { Text("Delete all", color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = { confirmClear = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun SheetAction(icon: ImageVector, label: String, danger: Boolean = false, onClick: () -> Unit) {
    val c = if (danger) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Icon(icon, null, tint = c, modifier = Modifier.size(22.dp))
        Text(label, style = MaterialTheme.typography.bodyLarge, color = c)
    }
}

@Composable
private fun StorageCard(s: ServerStat) {
    val frac = if (s.quota > 0) (s.used.toFloat() / s.quota).coerceIn(0f, 1f) else 0f
    Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer), shape = MaterialTheme.shapes.extraLarge) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.Bottom) {
                Text(humanSize(s.used), style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.onPrimaryContainer)
                Text(
                    "  of ${humanSize(s.quota)}",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.7f),
                    modifier = Modifier.padding(bottom = 3.dp),
                )
            }
            LinearProgressIndicator(
                progress = { frac },
                modifier = Modifier.fillMaxWidth().height(8.dp),
                color = MaterialTheme.colorScheme.primary,
                trackColor = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.15f),
                strokeCap = androidx.compose.ui.graphics.StrokeCap.Round,
                gapSize = 0.dp,
                drawStopIndicator = {},
            )
            Text(
                "${s.count} file${if (s.count == 1L) "" else "s"}  ·  ${humanSize(s.free)} free on server",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.8f),
            )
        }
    }
}

private fun kind(name: String): Pair<String, Int> {
    val ext = name.substringAfterLast('.', "").lowercase()
    val group = when (ext) {
        "png", "jpg", "jpeg", "gif", "webp", "heic", "svg" -> 1
        "mp4", "mkv", "webm", "mov", "mp3", "wav", "ogg", "flac", "m4a" -> 2
        "zip", "tar", "gz", "7z", "rar", "xz", "apk" -> 3
        "pdf", "txt", "md", "doc", "docx", "odt" -> 4
        else -> 0
    }
    return (if (ext.isEmpty()) "FILE" else ext.take(4).uppercase()) to group
}

@Composable
private fun FileRow(f: RemoteFile, onClick: () -> Unit) {
    val (label, group) = kind(f.name)
    val cs = MaterialTheme.colorScheme
    val (bg, fg) = when (group) {
        1 -> cs.tertiaryContainer to cs.onTertiaryContainer
        2 -> cs.primaryContainer to cs.onPrimaryContainer
        3 -> cs.errorContainer to cs.onErrorContainer
        4 -> cs.secondaryContainer to cs.onSecondaryContainer
        else -> cs.surfaceContainerHighest to cs.onSurfaceVariant
    }
    Card(
        modifier = Modifier.fillMaxWidth(),
        onClick = onClick,
        colors = CardDefaults.cardColors(containerColor = cs.surfaceContainer),
        shape = MaterialTheme.shapes.large,
    ) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            IconBadge(bg) { Text(label, color = fg, fontSize = 11.sp, fontWeight = FontWeight.Bold, maxLines = 1) }
            Column(Modifier.weight(1f)) {
                Text(f.name, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    "${humanSize(f.size)}  ·  ${ago(f.uploaded)}  ·  ${expiresIn(f.expires)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = cs.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

@Composable
private fun JobCard(j: UploadJob, a: FileActions) {
    val cs = MaterialTheme.colorScheme
    val sem = LocalSemantic.current
    Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = cs.surfaceContainerHigh), shape = MaterialTheme.shapes.large) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(j.name, Modifier.weight(1f), style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                when (j.phase) {
                    Phase.Preparing, Phase.Uploading -> IconButton(onClick = { a.cancelJob(j.id) }, Modifier.size(32.dp)) { Icon(Icons.Default.Close, "Cancel") }
                    Phase.Done -> Icon(Icons.Default.Check, null, tint = sem.ok)
                    Phase.Failed -> Icon(Icons.Default.Warning, null, tint = cs.error)
                }
                if (j.phase == Phase.Done || j.phase == Phase.Failed) {
                    IconButton(onClick = { a.dismissJob(j.id) }, Modifier.size(32.dp)) { Icon(Icons.Default.Close, "Dismiss") }
                }
            }
            when (j.phase) {
                Phase.Preparing -> {
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                    Text("Preparing…", style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant)
                }
                Phase.Uploading -> {
                    val f = if (j.size > 0) (j.sent.toFloat() / j.size).coerceIn(0f, 1f) else 0f
                    LinearProgressIndicator(progress = { f }, modifier = Modifier.fillMaxWidth())
                    Text("${humanSize(j.sent)} of ${humanSize(j.size)}  ·  ${(f * 100).toInt()}%", style = MaterialTheme.typography.bodySmall, color = cs.onSurfaceVariant)
                }
                Phase.Done -> Text("Uploaded. Link copied to clipboard.", style = MaterialTheme.typography.bodySmall, color = sem.ok)
                Phase.Failed -> Text(j.error ?: "Upload failed", style = MaterialTheme.typography.bodySmall, color = cs.error)
            }
        }
    }
}

@Composable
private fun ErrorCard(msg: String, onRetry: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer), shape = MaterialTheme.shapes.large) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Warning, null, tint = MaterialTheme.colorScheme.onErrorContainer)
            Text(msg, Modifier.weight(1f).padding(horizontal = 12.dp), color = MaterialTheme.colorScheme.onErrorContainer, style = MaterialTheme.typography.bodyMedium)
            TextButton(onClick = onRetry) { Text("Retry") }
        }
    }
}

@Composable
private fun EmptyState(title: String, body: String) {
    Column(Modifier.fillMaxWidth().padding(vertical = 56.dp, horizontal = 12.dp), horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(10.dp)) {
        IconBadge(MaterialTheme.colorScheme.secondaryContainer) { Icon(Glyphs.Folder, null, tint = MaterialTheme.colorScheme.onSecondaryContainer) }
        Text(title, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
        Text(body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = androidx.compose.ui.text.style.TextAlign.Center)
    }
}
