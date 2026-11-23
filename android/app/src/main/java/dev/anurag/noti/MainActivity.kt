package dev.anurag.noti

import android.app.Activity
import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import org.json.JSONObject

class MainActivity : Activity() {
    private lateinit var status: TextView

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }
        status = TextView(this).apply { textSize = 16f }
        root.addView(status)
        fun button(label: String, onClick: () -> Unit) = root.addView(
            Button(this).apply { text = label; setOnClickListener { onClick() } }
        )
        button("Scan pairing QR") { scan() }
        button("Paste pairing link") { paste() }
        button("1. Grant notification access") {
            startActivity(Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
        }
        button("2. Disable battery optimization") {
            val pm = getSystemService(PowerManager::class.java)
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                startActivity(
                    Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName"))
                )
            }
        }
        button("Send test notification") {
            Sender.enqueue(
                this,
                JSONObject().put("id", "test-${System.currentTimeMillis()}").put("pkg", packageName)
                    .put("app", "Noti").put("title", "Test").put("text", "Hello from your phone")
                    .put("ts", System.currentTimeMillis())
            )
            toast("queued")
        }
        button("Unpair") {
            Store.clear(this)
            refresh()
        }
        setContentView(root)
        handle(intent)
    }

    override fun onNewIntent(i: Intent) {
        super.onNewIntent(i)
        handle(i)
    }

    override fun onResume() {
        super.onResume()
        refresh()
    }

    private fun handle(i: Intent?) {
        i?.data?.toString()?.let { applyPairing(it) }
    }

    private fun scan() {
        GmsBarcodeScanning.getClient(this).startScan()
            .addOnSuccessListener { applyPairing(it.rawValue.orEmpty()) }
            .addOnFailureListener { toast("scan failed: ${it.message}") }
    }

    private fun paste() {
        val et = EditText(this).apply { inputType = InputType.TYPE_CLASS_TEXT; hint = "noti://pair?u=…&k=…" }
        android.app.AlertDialog.Builder(this).setTitle("Pairing link").setView(et)
            .setPositiveButton("OK") { _, _ -> applyPairing(et.text.toString().trim()) }.show()
    }

    private fun applyPairing(uri: String) {
        val u = Uri.parse(uri)
        if (u.scheme != "noti" || u.host != "pair") return toast("not a pairing link")
        val relay = u.getQueryParameter("u") ?: return toast("missing relay")
        val key = try { Crypto.unb64(u.getQueryParameter("k").orEmpty()) } catch (e: Exception) { null }
        if (!relay.startsWith("https://")) return toast("relay must be https")
        if (key == null || key.size != 32) return toast("bad key")
        Store.savePairing(this, relay, key)
        toast("paired")
        refresh()
    }

    private fun refresh() {
        val p = Store.loadPairing(this)
        val listening = Settings.Secure.getString(contentResolver, "enabled_notification_listeners")
            ?.contains(ComponentName(this, NotiListener::class.java).flattenToString()) == true
        status.text = buildString {
            append(if (p != null) "Paired with ${p.relay}\nchannel ${p.keys.channelHex.take(8)}…" else "Not paired")
            append("\nNotification access: ${if (listening) "granted" else "NOT granted"}")
            append("\nQueued: ${Store.pending(this@MainActivity).size}")
            append("\nStatus: ${Store.status(this@MainActivity)}")
        }
        status.visibility = View.VISIBLE
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_SHORT).show()
}
