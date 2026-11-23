package dev.anurag.noti

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

fun humanSize(b: Long): String {
    var v = b.toDouble()
    for (u in listOf("B", "KB", "MB", "GB", "TB")) {
        if (v < 1000 || u == "TB") return if (u == "B") "$b B" else if (v >= 100) "%.0f %s".format(v, u) else "%.1f %s".format(v, u)
        v /= 1000
    }
    return "$b B"
}

fun ago(unixSecs: Long, nowMs: Long = System.currentTimeMillis()): String {
    val s = nowMs / 1000 - unixSecs
    return when {
        s < 60 -> "just now"
        s < 3600 -> "${s / 60} min ago"
        s < 86400 -> "${s / 3600} h ago"
        s < 86400 * 30 -> "${s / 86400} d ago"
        else -> java.text.DateFormat.getDateInstance(java.text.DateFormat.MEDIUM).format(java.util.Date(unixSecs * 1000))
    }
}

fun expiresIn(unixSecs: Long, nowMs: Long = System.currentTimeMillis()): String {
    val d = (unixSecs - nowMs / 1000) / 86400
    return if (d <= 0) "expires today" else "expires in $d d"
}

@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text.uppercase(),
        modifier = modifier.padding(start = 4.dp, top = 8.dp),
        style = MaterialTheme.typography.labelMedium.copy(letterSpacing = 1.2.sp),
        color = MaterialTheme.colorScheme.primary,
        fontWeight = FontWeight.SemiBold,
    )
}

@Composable
fun ScreenTitle(title: String, subtitle: String? = null, actions: @Composable () -> Unit = {}) {
    Row(Modifier.fillMaxWidth().padding(top = 8.dp, bottom = 4.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.headlineLarge, fontWeight = FontWeight.Bold)
            if (subtitle != null) Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        actions()
    }
}

@Composable
fun IconBadge(color: Color, content: @Composable () -> Unit) {
    Box(Modifier.size(44.dp).clip(RoundedCornerShape(14.dp)).background(color), contentAlignment = Alignment.Center) { content() }
}

@Composable
fun StatusDot(color: Color) {
    Box(Modifier.size(10.dp).clip(CircleShape).background(color))
}

@Composable
fun Gap(h: Int) = Spacer(Modifier.height(h.dp))

@Composable
fun RowSpace(content: @Composable () -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) { content() }
}
