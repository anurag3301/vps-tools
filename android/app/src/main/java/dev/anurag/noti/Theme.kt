package dev.anurag.noti

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.unit.dp

private val Light = lightColorScheme(
    primary = Color(0xFF4B50E6), onPrimary = Color.White,
    primaryContainer = Color(0xFFE1E0FF), onPrimaryContainer = Color(0xFF0A0A6E),
    secondary = Color(0xFF5C5D72), onSecondary = Color.White,
    secondaryContainer = Color(0xFFE1E0F9), onSecondaryContainer = Color(0xFF191A2C),
    tertiary = Color(0xFF8A3F9B), tertiaryContainer = Color(0xFFFAD8FF), onTertiaryContainer = Color(0xFF330045),
    background = Color(0xFFFBF8FF), onBackground = Color(0xFF1B1B21),
    surface = Color(0xFFFBF8FF), onSurface = Color(0xFF1B1B21),
    surfaceVariant = Color(0xFFE4E1EC), onSurfaceVariant = Color(0xFF46464F),
    surfaceContainerLowest = Color.White, surfaceContainerLow = Color(0xFFF5F2FA),
    surfaceContainer = Color(0xFFEFEDF4), surfaceContainerHigh = Color(0xFFE9E7EF), surfaceContainerHighest = Color(0xFFE4E1E9),
    outline = Color(0xFF777680), outlineVariant = Color(0xFFC7C5D0),
    error = Color(0xFFBA1A1A), errorContainer = Color(0xFFFFDAD6), onErrorContainer = Color(0xFF410002),
)

private val Dark = darkColorScheme(
    primary = Color(0xFFBEC2FF), onPrimary = Color(0xFF111480),
    primaryContainer = Color(0xFF3236CE), onPrimaryContainer = Color(0xFFE1E0FF),
    secondary = Color(0xFFC4C4DC), onSecondary = Color(0xFF2D2E42),
    secondaryContainer = Color(0xFF444559), onSecondaryContainer = Color(0xFFE1E0F9),
    tertiary = Color(0xFFEEB0FF), tertiaryContainer = Color(0xFF6E2A81), onTertiaryContainer = Color(0xFFFAD8FF),
    background = Color(0xFF121318), onBackground = Color(0xFFE4E1E9),
    surface = Color(0xFF121318), onSurface = Color(0xFFE4E1E9),
    surfaceVariant = Color(0xFF46464F), onSurfaceVariant = Color(0xFFC7C5D0),
    surfaceContainerLowest = Color(0xFF0D0E13), surfaceContainerLow = Color(0xFF1B1B21),
    surfaceContainer = Color(0xFF1F1F25), surfaceContainerHigh = Color(0xFF292A2F), surfaceContainerHighest = Color(0xFF34343A),
    outline = Color(0xFF918F9A), outlineVariant = Color(0xFF46464F),
    error = Color(0xFFFFB4AB), errorContainer = Color(0xFF93000A), onErrorContainer = Color(0xFFFFDAD6),
)

@Immutable
class Semantic(val ok: Color, val warn: Color)

val LocalSemantic = staticCompositionLocalOf { Semantic(Color(0xFF2E7D32), Color(0xFFB26A00)) }

@Composable
fun NotiTheme(dynamic: Boolean, content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val ctx = LocalContext.current
    val scheme = when {
        dynamic && Build.VERSION.SDK_INT >= 31 -> if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        dark -> Dark
        else -> Light
    }
    val sem = if (dark) Semantic(Color(0xFF7ADB8A), Color(0xFFFFB95C)) else Semantic(Color(0xFF2E7D32), Color(0xFFB26A00))
    androidx.compose.runtime.CompositionLocalProvider(LocalSemantic provides sem) {
        MaterialTheme(
            colorScheme = scheme,
            shapes = Shapes(
                small = RoundedCornerShape(12.dp), medium = RoundedCornerShape(20.dp),
                large = RoundedCornerShape(28.dp), extraLarge = RoundedCornerShape(32.dp),
            ),
            content = content,
        )
    }
}
