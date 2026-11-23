package dev.anurag.noti

import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Send
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

data class HomeState(val pairing: Pairing?, val listening: Boolean, val batteryOk: Boolean, val queued: Int, val status: String)

@Composable
fun HomeScreen(
    s: HomeState,
    onScan: () -> Unit,
    onPaste: () -> Unit,
    onGrantAccess: () -> Unit,
    onBattery: () -> Unit,
    onTest: () -> Unit,
) {
    val sem = LocalSemantic.current
    Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        ScreenTitle("Noti", "Phone notifications on your laptop, end-to-end encrypted")

        if (s.pairing == null) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
                shape = MaterialTheme.shapes.extraLarge,
            ) {
                Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    IconBadge(MaterialTheme.colorScheme.primary) { Icon(Icons.Default.Lock, null, tint = MaterialTheme.colorScheme.onPrimary) }
                    Text("Pair with your laptop", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.onPrimaryContainer)
                    Text(
                        "Run  noti-daemon pair  on the laptop, then scan the QR code it shows. The key never leaves your two devices.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = onScan) { Text("Scan QR") }
                        OutlinedButton(onClick = onPaste) { Text("Paste link") }
                    }
                }
            }
        } else {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
                shape = MaterialTheme.shapes.extraLarge,
            ) {
                Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        StatusDot(if (s.listening) sem.ok else sem.warn)
                        Text(
                            if (s.listening) "Forwarding notifications" else "Notification access needed",
                            style = MaterialTheme.typography.labelLarge,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                    }
                    Text(
                        Uri.parse(s.pairing.relay).host ?: s.pairing.relay,
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onPrimaryContainer,
                    )
                    Text(
                        "Channel ${s.pairing.keys.channelHex.take(8)}…  ·  ${s.status}",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.8f),
                    )
                    if (s.queued > 0) {
                        AssistChip(onClick = {}, label = { Text("${s.queued} waiting to send") })
                    }
                }
            }
        }

        SectionLabel("Setup")
        SetupRow(
            icon = { Icon(Icons.Default.Notifications, null, tint = MaterialTheme.colorScheme.onSecondaryContainer) },
            title = "Notification access",
            subtitle = if (s.listening) "Noti can read incoming notifications" else "Required to forward notifications",
            done = s.listening,
            action = "Grant",
            onAction = onGrantAccess,
        )
        SetupRow(
            icon = { Icon(Icons.Default.Info, null, tint = MaterialTheme.colorScheme.onSecondaryContainer) },
            title = "Run in background",
            subtitle = if (s.batteryOk) "Battery usage is unrestricted" else "Stops Samsung from putting Noti to sleep",
            done = s.batteryOk,
            action = "Allow",
            onAction = onBattery,
        )

        if (s.pairing != null) {
            SectionLabel("Try it")
            FilledTonalButton(onClick = onTest, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.Send, null, Modifier.size(18.dp))
                Text("  Send a test notification")
            }
        }
        androidx.compose.foundation.layout.Spacer(Modifier.padding(bottom = 16.dp))
    }
}

@Composable
private fun SetupRow(icon: @Composable () -> Unit, title: String, subtitle: String, done: Boolean, action: String, onAction: () -> Unit) {
    val sem = LocalSemantic.current
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
        shape = MaterialTheme.shapes.large,
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
            IconBadge(MaterialTheme.colorScheme.secondaryContainer, icon)
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (done) Icon(Icons.Default.Check, "done", tint = sem.ok) else TextButton(onClick = onAction) { Text(action) }
        }
    }
}
