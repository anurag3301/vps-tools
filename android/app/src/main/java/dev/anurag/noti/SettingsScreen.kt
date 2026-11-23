package dev.anurag.noti

import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@Composable
fun SettingsScreen(
    pairing: Pairing?,
    dynamic: Boolean,
    onDynamic: (Boolean) -> Unit,
    onUnpair: () -> Unit,
    onRepair: () -> Unit,
) {
    var confirm by remember { mutableStateOf(false) }
    Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal = 20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        ScreenTitle("Settings")

        SectionLabel("Pairing")
        Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer), shape = MaterialTheme.shapes.large) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                if (pairing == null) {
                    Text("Not paired", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text("Pair from the Home tab.", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    Text("Relay", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Text(Uri.parse(pairing.relay).authority ?: pairing.relay, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text("Channel", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 8.dp))
                    Text(pairing.keys.channelHex.take(16) + "…", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Row(Modifier.padding(top = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = onRepair) { Text("Pair again") }
                        OutlinedButton(onClick = { confirm = true }) { Text("Unpair", color = MaterialTheme.colorScheme.error) }
                    }
                }
            }
        }

        SectionLabel("Appearance")
        Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer), shape = MaterialTheme.shapes.large) {
            Row(Modifier.padding(horizontal = 20.dp, vertical = 14.dp), verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Match system colours", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                    Text("Use Material You colours from your wallpaper", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Switch(checked = dynamic, onCheckedChange = onDynamic)
            }
        }

        SectionLabel("About")
        Card(modifier = Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainer), shape = MaterialTheme.shapes.large) {
            Column(Modifier.padding(20.dp).fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Noti ${BuildConfig.VERSION_NAME}", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Text(
                    "Notifications are encrypted on this phone with a key only your laptop has; the relay can't read them. " +
                        "Uploaded files are not encrypted: anyone with the link can download them until they expire.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        androidx.compose.foundation.layout.Spacer(Modifier.padding(bottom = 16.dp))
    }

    if (confirm) {
        AlertDialog(
            onDismissRequest = { confirm = false },
            title = { Text("Unpair this phone?") },
            text = { Text("Notifications and file access stop until you pair again.") },
            confirmButton = { TextButton(onClick = { confirm = false; onUnpair() }) { Text("Unpair", color = MaterialTheme.colorScheme.error) } },
            dismissButton = { TextButton(onClick = { confirm = false }) { Text("Cancel") } },
        )
    }
}
