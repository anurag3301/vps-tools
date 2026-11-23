package dev.anurag.noti

import android.Manifest
import android.app.DownloadManager
import android.content.ComponentName
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.PowerManager
import android.provider.Settings
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import org.json.JSONObject

class MainActivity : ComponentActivity() {
    private var tab by mutableIntStateOf(0)
    private var tick by mutableIntStateOf(0)
    private var dynamic by mutableStateOf(false)
    private var pasteOpen by mutableStateOf(false)
    private val snack = SnackbarHostState()

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        enableEdgeToEdge()
        dynamic = Store.dynamicColor(this)
        setContent { NotiTheme(dynamic) { App() } }
        handle(intent)
    }

    override fun onNewIntent(i: Intent) {
        super.onNewIntent(i)
        handle(i)
    }

    override fun onResume() {
        super.onResume()
        tick++
        Files.refresh(this)
    }

    @Composable
    private fun App() {
        val pairing = remember(tick) { Store.loadPairing(this) }
        val home = remember(tick) {
            HomeState(
                pairing = pairing,
                listening = isListening(),
                batteryOk = getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(packageName),
                queued = Store.pending(this).size,
                status = Store.status(this),
            )
        }
        val files by Files.files.collectAsStateWithLifecycle()
        val stat by Files.stat.collectAsStateWithLifecycle()
        val jobs by Files.jobs.collectAsStateWithLifecycle()
        val error by Files.error.collectAsStateWithLifecycle()
        val refreshing by Files.refreshing.collectAsStateWithLifecycle()
        val message by Files.messages.collectAsState()
        LaunchedEffect(message) {
            message?.let {
                Files.messages.value = null
                snack.showSnackbar(it)
            }
        }

        val notifPerm = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
        val picker = rememberLauncherForActivityResult(ActivityResultContracts.GetMultipleContents()) { uris ->
            if (uris.isNotEmpty() && Build.VERSION.SDK_INT >= 33 &&
                checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
            ) notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
            uris.forEach { Files.upload(this, it) }
        }

        val actions = remember {
            FileActions(
                refresh = { Files.refresh(this) },
                copy = { Files.copyToClipboard(this, it.url); Files.messages.value = "Link copied" },
                share = {
                    startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, it.url), null))
                },
                download = { download(it) },
                open = { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(it.url))) },
                delete = { Files.delete(this, it.id) },
                clearAll = { Files.clearAll(this) },
                cancelJob = Files::cancel,
                dismissJob = Files::dismiss,
            )
        }

        Scaffold(
            snackbarHost = { SnackbarHost(snack) },
            bottomBar = {
                NavigationBar {
                    NavigationBarItem(tab == 0, { tab = 0 }, { Icon(Icons.Default.Home, null) }, label = { Text("Home") })
                    NavigationBarItem(tab == 1, { tab = 1 }, { Icon(Glyphs.Folder, null) }, label = { Text("Files") })
                    NavigationBarItem(tab == 2, { tab = 2 }, { Icon(Icons.Default.Settings, null) }, label = { Text("Settings") })
                }
            },
            floatingActionButton = {
                if (tab == 1 && pairing != null) {
                    ExtendedFloatingActionButton(
                        onClick = { picker.launch("*/*") },
                        icon = { Icon(Glyphs.Upload, null) },
                        text = { Text("Upload") },
                    )
                }
            },
        ) { inner ->
            Box(Modifier.padding(inner)) {
                when (tab) {
                    0 -> HomeScreen(
                        home,
                        onScan = ::scan,
                        onPaste = { pasteOpen = true },
                        onGrantAccess = { startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)) },
                        onBattery = {
                            startActivity(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName")))
                        },
                        onTest = ::sendTest,
                    )
                    1 -> FilesScreen(pairing != null, files, stat, jobs, error, refreshing, actions)
                    else -> SettingsScreen(
                        pairing,
                        dynamic,
                        onDynamic = { dynamic = it; Store.setDynamicColor(this@MainActivity, it) },
                        onUnpair = {
                            Store.clear(this@MainActivity)
                            Files.clearState()
                            tick++
                        },
                        onRepair = { tab = 0; scan() },
                    )
                }
            }
        }
        if (pasteOpen) PasteDialog()
    }

    @Composable
    private fun PasteDialog() {
        var text by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { pasteOpen = false },
            title = { Text("Pairing link") },
            text = { OutlinedTextField(text, { text = it }, placeholder = { Text("noti://pair?u=…&k=…") }, singleLine = true) },
            confirmButton = { TextButton(onClick = { pasteOpen = false; applyPairing(text.trim()) }) { Text("Pair") } },
            dismissButton = { TextButton(onClick = { pasteOpen = false }) { Text("Cancel") } },
        )
    }

    private fun handle(i: Intent?) {
        i ?: return
        when (i.action) {
            Intent.ACTION_VIEW -> i.data?.toString()?.let { applyPairing(it) }
            Intent.ACTION_SEND -> shared(listOfNotNull(streamExtra(i)))
            Intent.ACTION_SEND_MULTIPLE -> shared(streamListExtra(i))
        }
    }

    @Suppress("DEPRECATION")
    private fun streamExtra(i: Intent): Uri? =
        if (Build.VERSION.SDK_INT >= 33) i.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java) else i.getParcelableExtra(Intent.EXTRA_STREAM)

    @Suppress("DEPRECATION")
    private fun streamListExtra(i: Intent): List<Uri> =
        (if (Build.VERSION.SDK_INT >= 33) i.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java) else i.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM))
            .orEmpty()

    /** Files shared to Noti from other apps. */
    private fun shared(uris: List<Uri>) {
        if (uris.isEmpty()) return
        if (Store.loadPairing(this) == null) return toast("Pair this phone first")
        tab = 1
        uris.forEach { Files.upload(this, it) }
    }

    private fun download(f: RemoteFile) {
        val req = DownloadManager.Request(Uri.parse(f.url))
            .setTitle(f.name)
            .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED)
            .setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, f.name)
        getSystemService(DownloadManager::class.java).enqueue(req)
        Files.messages.value = "Downloading ${f.name}…"
    }

    private fun isListening() = Settings.Secure.getString(contentResolver, "enabled_notification_listeners")
        ?.contains(ComponentName(this, NotiListener::class.java).flattenToString()) == true

    private fun scan() {
        GmsBarcodeScanning.getClient(this).startScan()
            .addOnSuccessListener { applyPairing(it.rawValue.orEmpty()) }
            .addOnFailureListener { toast("Scan failed: ${it.message}") }
    }

    private fun sendTest() {
        Sender.enqueue(
            this,
            JSONObject().put("id", "test-${System.currentTimeMillis()}").put("pkg", packageName)
                .put("app", "Noti").put("title", "Test").put("text", "Hello from your phone")
                .put("ts", System.currentTimeMillis())
        )
        Files.messages.value = "Test notification queued"
    }

    private fun applyPairing(uri: String) {
        val u = Uri.parse(uri)
        if (u.scheme != "noti" || u.host != "pair") return toast("Not a pairing link")
        val relay = u.getQueryParameter("u") ?: return toast("Missing relay")
        val key = try { Crypto.unb64(u.getQueryParameter("k").orEmpty()) } catch (e: Exception) { null }
        val schemeOk = relay.startsWith("https://") || (BuildConfig.ALLOW_HTTP && relay.startsWith("http://"))
        if (!schemeOk) return toast("Relay must be https")
        if (key == null || key.size != 32) return toast("Bad key")
        Store.savePairing(this, relay, key)
        Files.clearState()
        toast("Paired")
        tick++
        Files.refresh(this)
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_SHORT).show()
}
