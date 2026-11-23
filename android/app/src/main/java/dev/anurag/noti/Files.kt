package dev.anurag.noti

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.File
import java.io.InputStream
import java.security.MessageDigest

data class RemoteFile(val id: String, val name: String, val size: Long, val uploaded: Long, val expires: Long, val url: String)
data class ServerStat(val total: Long, val free: Long, val used: Long, val quota: Long, val count: Long)

enum class Phase { Preparing, Uploading, Done, Failed }

data class UploadJob(
    val id: Long,
    val name: String,
    val size: Long,
    val phase: Phase,
    val sent: Long = 0,
    val error: String? = null,
    val url: String? = null,
)

private class Cancelled : RuntimeException()

/** State and operations for the server-side file store, shared by the UI and the upload service. */
object Files {
    const val MAX_BYTES = 256L * 1024 * 1024

    val files = MutableStateFlow<List<RemoteFile>?>(null)
    val stat = MutableStateFlow<ServerStat?>(null)
    val jobs = MutableStateFlow<List<UploadJob>>(emptyList())
    val error = MutableStateFlow<String?>(null)
    val refreshing = MutableStateFlow(false)
    /** One-shot messages for the UI (snackbar). */
    val messages = MutableStateFlow<String?>(null)

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val uploadLock = Mutex()
    private val cancelled = java.util.Collections.synchronizedSet(HashSet<Long>())
    private var nextJob = 1L
    private var active = 0

    fun refresh(ctx: Context) {
        val app = ctx.applicationContext
        scope.launch {
            val p = Store.loadPairing(app) ?: return@launch
            refreshing.value = true
            try {
                val list = Api.get(p, "/v1/files").getJSONArray("files")
                files.value = List(list.length()) {
                    list.getJSONObject(it).let { o ->
                        RemoteFile(o.getString("id"), o.getString("name"), o.getLong("size"), o.getLong("uploaded"), o.getLong("expires"), o.getString("url"))
                    }
                }
                val s = Api.get(p, "/v1/files/stat")
                stat.value = ServerStat(s.getLong("total"), s.getLong("free"), s.getLong("used"), s.getLong("quota"), s.getLong("count"))
                error.value = null
            } catch (e: Exception) {
                error.value = describe(e)
            } finally {
                refreshing.value = false
            }
        }
    }

    fun delete(ctx: Context, id: String) = launchOp(ctx, "Deleted") { p -> Api.delete(p, "/v1/files/$id") }

    fun clearAll(ctx: Context) = launchOp(ctx, "All files deleted") { p -> Api.post(p, "/v1/files/clear") }

    private fun launchOp(ctx: Context, done: String, op: (Pairing) -> Unit) {
        val app = ctx.applicationContext
        scope.launch {
            val p = Store.loadPairing(app) ?: return@launch
            try {
                op(p)
                messages.value = done
            } catch (e: Exception) {
                messages.value = describe(e)
            }
            refresh(app)
        }
    }

    fun clearState() {
        files.value = null
        stat.value = null
        error.value = null
    }

    fun dismiss(jobId: Long) = jobs.update { l -> l.filterNot { it.id == jobId } }

    fun cancel(jobId: Long) {
        cancelled.add(jobId)
    }

    fun upload(ctx: Context, uri: Uri) {
        val app = ctx.applicationContext
        val (name, declared) = describeUri(app, uri)
        val job = synchronized(this) { UploadJob(nextJob++, name, declared, Phase.Preparing) }
        jobs.update { it + job }
        UploadService.begin(app)
        synchronized(this) { active++ }
        scope.launch {
            uploadLock.withLock { run(app, uri, job) }
            val idle = synchronized(this@Files) { --active == 0 }
            if (idle) UploadService.end(app)
        }
    }

    private fun patch(id: Long, f: (UploadJob) -> UploadJob) = jobs.update { l -> l.map { if (it.id == id) f(it) else it } }

    private fun run(app: Context, uri: Uri, job: UploadJob) {
        var temp: File? = null
        try {
            val p = Store.loadPairing(app) ?: throw IllegalStateException("Not paired")
            var size = job.size
            var sha: String
            if (size <= 0) {
                // Some providers don't report a size; spool to cache so we know the length up front.
                temp = File.createTempFile("upload", ".tmp", app.cacheDir)
                val md = MessageDigest.getInstance("SHA-256")
                app.contentResolver.openInputStream(uri)!!.use { ins ->
                    temp.outputStream().use { out -> copyHashing(ins, out, md, job.id) { } }
                }
                size = temp.length()
                sha = Crypto.hex(md.digest())
            } else {
                val md = MessageDigest.getInstance("SHA-256")
                app.contentResolver.openInputStream(uri)!!.use { copyHashing(it, null, md, job.id) { } }
                sha = Crypto.hex(md.digest())
            }
            if (size == 0L) throw IllegalStateException("File is empty")
            if (size > MAX_BYTES) throw IllegalStateException("Too large (max 256 MB)")
            patch(job.id) { it.copy(size = size, phase = Phase.Uploading) }

            var lastReport = 0L
            val input = temp?.inputStream() ?: app.contentResolver.openInputStream(uri)!!
            val res = input.use {
                Api.put(p, job.name, sha, size, it) { sent ->
                    if (job.id in cancelled) throw Cancelled()
                    val now = System.currentTimeMillis()
                    if (now - lastReport > 150) {
                        lastReport = now
                        patch(job.id) { j -> j.copy(sent = sent) }
                        UploadService.progress(app, job.name, sent, size)
                    }
                }
            }
            val url = res.getString("url")
            patch(job.id) { it.copy(phase = Phase.Done, sent = size, url = url) }
            copyToClipboard(app, url)
            messages.value = "Link copied"
            UploadService.done(app, job.name)
            refresh(app)
        } catch (e: Cancelled) {
            dismiss(job.id)
        } catch (e: Exception) {
            patch(job.id) { it.copy(phase = Phase.Failed, error = describe(e)) }
        } finally {
            cancelled.remove(job.id)
            temp?.delete()
        }
    }

    private fun copyHashing(ins: InputStream, out: java.io.OutputStream?, md: MessageDigest, jobId: Long, tick: () -> Unit) {
        val buf = ByteArray(64 * 1024)
        while (true) {
            val n = ins.read(buf)
            if (n < 0) break
            if (jobId in cancelled) throw Cancelled()
            md.update(buf, 0, n)
            out?.write(buf, 0, n)
            tick()
        }
    }

    fun copyToClipboard(ctx: Context, text: String) {
        ctx.getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("link", text))
    }

    /** Same sanitising rules as the server, so the signed request path equals what is sent. */
    fun sanitize(name: String): String {
        val base = name.substringAfterLast('/').substringAfterLast('\\')
        val s = base.map { if (it.isLetterOrDigit() && it.code < 128 || it in "._-") it else '_' }.joinToString("")
            .trimStart('.').take(100)
        return s.ifEmpty { "file" }
    }

    private fun describeUri(ctx: Context, uri: Uri): Pair<String, Long> {
        var name = uri.lastPathSegment ?: "file"
        var size = -1L
        ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                c.getString(0)?.let { name = it }
                if (!c.isNull(1)) size = c.getLong(1)
            }
        }
        return sanitize(name) to size
    }

    private fun describe(e: Exception) = when (e) {
        is ApiException -> e.message ?: "Server error"
        is java.net.UnknownHostException, is java.net.ConnectException, is java.net.SocketTimeoutException -> "Can't reach the relay"
        else -> e.message ?: e.javaClass.simpleName
    }
}
