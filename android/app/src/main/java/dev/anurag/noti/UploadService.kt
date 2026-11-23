package dev.anurag.noti

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat

/**
 * Keeps the process alive and shows progress while files upload. Our own notifications are never
 * forwarded to the laptop (NotiListener skips this package).
 */
class UploadService : Service() {
    override fun onBind(i: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ensureChannels(this)
        val n = build(this, "Uploading…", -1)
        startForeground(ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        return START_NOT_STICKY
    }

    companion object {
        private const val ID = 42
        private const val DONE_ID = 43
        private const val CH_PROGRESS = "uploads"
        private const val CH_DONE = "uploads_done"

        fun ensureChannels(ctx: Context) {
            val nm = ctx.getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(NotificationChannel(CH_PROGRESS, "Upload progress", NotificationManager.IMPORTANCE_LOW))
            nm.createNotificationChannel(NotificationChannel(CH_DONE, "Upload finished", NotificationManager.IMPORTANCE_DEFAULT))
        }

        private fun build(ctx: Context, text: String, pct: Int): Notification {
            val open = PendingIntent.getActivity(ctx, 0, Intent(ctx, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
            return NotificationCompat.Builder(ctx, CH_PROGRESS)
                .setSmallIcon(android.R.drawable.stat_sys_upload)
                .setContentTitle("Uploading")
                .setContentText(text)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .setContentIntent(open)
                .apply { if (pct >= 0) setProgress(100, pct, false) else setProgress(0, 0, true) }
                .build()
        }

        fun begin(ctx: Context) {
            ContextCompat.startForegroundService(ctx, Intent(ctx, UploadService::class.java))
        }

        fun end(ctx: Context) {
            ctx.stopService(Intent(ctx, UploadService::class.java))
        }

        fun progress(ctx: Context, name: String, sent: Long, total: Long) {
            val pct = if (total > 0) (sent * 100 / total).toInt() else -1
            runCatching { ctx.getSystemService(NotificationManager::class.java).notify(ID, build(ctx, name, pct)) }
        }

        fun done(ctx: Context, name: String) {
            val open = PendingIntent.getActivity(ctx, 0, Intent(ctx, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
            val n = NotificationCompat.Builder(ctx, CH_DONE)
                .setSmallIcon(android.R.drawable.stat_sys_upload_done)
                .setContentTitle("Upload finished")
                .setContentText("$name — link copied")
                .setAutoCancel(true)
                .setContentIntent(open)
                .build()
            runCatching { ctx.getSystemService(NotificationManager::class.java).notify(DONE_ID, n) }
        }
    }
}
