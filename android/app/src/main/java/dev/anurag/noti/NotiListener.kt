package dev.anurag.noti

import android.app.Notification
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.graphics.Bitmap
import android.graphics.Canvas
import org.json.JSONObject

class NotiListener : NotificationListenerService() {
    private val recent = LinkedHashMap<String, Long>()

    /**
     * 48x48 PNG of the app icon. The laptop caches icons, so each is sent once, then again only
     * when the app was updated or after 7 days (persisted across restarts).
     */
    private fun iconFor(pkg: String, now: Long): String? {
        return try {
            val updated = packageManager.getPackageInfo(pkg, 0).lastUpdateTime
            val last = Store.iconSent(this, pkg)
            if (last != null && last.second == updated && now - last.first < 7 * 24 * 3600_000L) return null
            val d = packageManager.getApplicationIcon(pkg)
            val bmp = Bitmap.createBitmap(48, 48, Bitmap.Config.ARGB_8888)
            d.setBounds(0, 0, 48, 48)
            d.draw(Canvas(bmp))
            val out = java.io.ByteArrayOutputStream()
            bmp.compress(Bitmap.CompressFormat.PNG, 100, out)
            Store.setIconSent(this, pkg, now, updated)
            if (out.size() > 8 * 1024) null else Crypto.b64(out.toByteArray())
        } catch (e: Exception) {
            null
        }
    }

    override fun onListenerConnected() {
        Sender.ensureNetworkCallback(this)
        Sender.flush(this)
    }

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val n = sbn.notification
        if (sbn.packageName == packageName) return
        if (n.flags and Notification.FLAG_ONGOING_EVENT != 0) return
        if (n.flags and Notification.FLAG_GROUP_SUMMARY != 0) return
        if (n.flags and Notification.FLAG_LOCAL_ONLY != 0) return
        if (sbn.packageName in Store.blocked(this)) return

        val ex = n.extras
        val title = ex.getCharSequence(Notification.EXTRA_TITLE)?.toString().orEmpty()
        val text = (ex.getCharSequence(Notification.EXTRA_BIG_TEXT) ?: ex.getCharSequence(Notification.EXTRA_TEXT))
            ?.toString().orEmpty()
        if (title.isEmpty() && text.isEmpty()) return

        // Apps re-post the same notification for progress/updates; drop exact repeats within 5s.
        val sig = "${sbn.key}|$title|$text"
        val now = System.currentTimeMillis()
        if (recent[sig]?.let { now - it < 5_000 } == true) return
        recent[sig] = now
        if (recent.size > 100) recent.remove(recent.keys.first())

        val app = try {
            packageManager.getApplicationLabel(packageManager.getApplicationInfo(sbn.packageName, 0)).toString()
        } catch (e: Exception) {
            sbn.packageName
        }
        val json = JSONObject()
                .put("id", sbn.key)
                .put("pkg", sbn.packageName)
                .put("app", app)
                .put("title", title.take(200))
                .put("text", text.take(2000))
                .put("ts", sbn.postTime)
        iconFor(sbn.packageName, now)?.let { json.put("icon", it) }
        Sender.enqueue(this, json)
    }
}
