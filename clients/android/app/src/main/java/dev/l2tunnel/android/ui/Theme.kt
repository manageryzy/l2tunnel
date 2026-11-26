package dev.l2tunnel.android.ui

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private val FallbackDarkColors = darkColorScheme(
    primary = Color(0xFF7CC4FA),
    onPrimary = Color(0xFF00344F),
    primaryContainer = Color(0xFF004B70),
    onPrimaryContainer = Color(0xFFC9E6FF),
    secondary = Color(0xFF7EDAB6),
    onSecondary = Color(0xFF003828),
    secondaryContainer = Color(0xFF00513C),
    onSecondaryContainer = Color(0xFF9BF6D1),
    background = Color(0xFF0F1419),
    surface = Color(0xFF0F1419),
    surfaceVariant = Color(0xFF1A222B),
    error = Color(0xFFFFB4AB),
)

private val FallbackLightColors = lightColorScheme(
    primary = Color(0xFF006494),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFC9E6FF),
    onPrimaryContainer = Color(0xFF001E30),
    secondary = Color(0xFF006B50),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFF9BF6D1),
    onSecondaryContainer = Color(0xFF002016),
    background = Color(0xFFF6F9FC),
    surface = Color(0xFFF6F9FC),
    surfaceVariant = Color(0xFFE7EFF6),
)

@Composable
fun L2TunnelTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val context = LocalContext.current
    val colorScheme = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && darkTheme -> dynamicDarkColorScheme(context)
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && !darkTheme -> dynamicLightColorScheme(context)
        darkTheme -> FallbackDarkColors
        else -> FallbackLightColors
    }
    MaterialTheme(
        colorScheme = colorScheme,
        content = content,
    )
}

object Formatters {
    fun bytes(bytes: Long): String = when {
        bytes >= 1_000_000_000L -> String.format("%.2f GB", bytes / 1e9)
        bytes >= 1_000_000L -> String.format("%.2f MB", bytes / 1e6)
        bytes >= 1_000L -> String.format("%.1f KB", bytes / 1e3)
        else -> "$bytes B"
    }

    fun rateBits(bitsPerSecond: Double): String = when {
        bitsPerSecond >= 1e9 -> String.format("%.2f Gbit/s", bitsPerSecond / 1e9)
        bitsPerSecond >= 1e6 -> String.format("%.1f Mbit/s", bitsPerSecond / 1e6)
        bitsPerSecond >= 1e3 -> String.format("%.1f kbit/s", bitsPerSecond / 1e3)
        else -> "${bitsPerSecond.toLong()} bit/s"
    }

    fun rateBytesPerSec(bytesPerSec: Float): String = rateBits(bytesPerSec.toDouble() * 8.0)

    fun rttMicros(us: Long?): String =
        us?.let { String.format("%.2f ms", it / 1000.0) } ?: "—"
}
