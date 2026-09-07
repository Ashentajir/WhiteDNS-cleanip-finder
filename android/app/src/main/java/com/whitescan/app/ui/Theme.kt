package com.whitescan.app.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Matches the TUI colour palette:
//   cAccent   = #00d1ff  (sky blue / cyan — primary)
//   cGreen    = #00c875  (mint green — success)
//   cOrange   = #ffa040  (orange — warning)
//   cRed      = #ff5252  (coral red — error)
//   cPurple   = #b39ddb  (lavender — secondary)
//   cBase     = #1a1a1e  (near-black surface)

val CyanAccent    = Color(0xFF00D1FF)
val MintGreen     = Color(0xFF00C875)
val Amber         = Color(0xFFFFB400)
val CoralRed      = Color(0xFFFF5252)
val Lavender      = Color(0xFFB39DDB)
val DarkBase      = Color(0xFF12121A)
val DarkSurface   = Color(0xFF1E1E2A)
val DarkSurface2  = Color(0xFF252535)
val OnDark        = Color(0xFFE8E8F0)
val OnDarkMuted   = Color(0xFF8888AA)
val ResultGreen   = Color(0xFF4CAF50)

private val WhiteDNSDarkScheme = darkColorScheme(
    primary             = CyanAccent,
    onPrimary           = Color(0xFF001820),
    primaryContainer    = Color(0xFF00374A),
    onPrimaryContainer  = Color(0xFFB3ECFF),
    secondary           = Lavender,
    onSecondary         = Color(0xFF1A0050),
    secondaryContainer  = Color(0xFF2D1F60),
    onSecondaryContainer= Color(0xFFE0D5FF),
    error               = CoralRed,
    onError             = Color(0xFF3B0011),
    errorContainer      = Color(0xFF93000A),
    onErrorContainer    = Color(0xFFFFDAD6),
    background          = DarkBase,
    onBackground        = OnDark,
    surface             = DarkSurface,
    onSurface           = OnDark,
    surfaceVariant      = DarkSurface2,
    onSurfaceVariant    = OnDarkMuted,
    outline             = Color(0xFF3A3A55),
    outlineVariant      = Color(0xFF2A2A40),
)

@Composable
fun WhiteDNSTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = WhiteDNSDarkScheme,
        content = content,
    )
}
