package com.whitescan.app.ui

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// ─────────────────────────────────────────────────────────────────────────────
//  WhiteDNS design language — "field instrument"
//
//  The app measures a network and reports what it found, so it is styled like a
//  measurement instrument rather than a menu of features: a stepped neutral
//  ramp for structure, ONE signal colour for anything live or actionable, and
//  status colours that only ever appear when that status is true.
//
//  The rules that keep it from drifting back into a generic dark theme:
//
//   1. Colour is meaning, never decoration. If two items differ only in hue,
//      the hue is wrong — use the ramp.
//   2. The ground is graphite, not black. Pure #000 reads as a void; a cool
//      stepped ramp reads as a machined surface and gives depth without
//      shadows.
//   3. Structure is drawn with hairlines, not floating rounded cards.
//   4. Monospace means machine data — addresses, counts, ports, results.
//      Prose is set in the UI sans. Never mix the two roles.
//   5. No gradients. A gradient here is decoration standing in for hierarchy.
// ─────────────────────────────────────────────────────────────────────────────

// Neutral ramp — cool graphite, five deliberate steps.
val Ink        = Color(0xFF090D10)   // app ground
val Panel      = Color(0xFF10171E)   // panel face
val Inset      = Color(0xFF172129)   // recessed: inputs, tracks, code blocks
val Rule       = Color(0xFF223039)   // hairline divisions
val RuleLit    = Color(0xFF33454F)   // emphasised edge / focus

// Text ramp — never pure white; a cool off-white sits correctly on graphite.
val TextPrimary = Color(0xFFDBE5EB)
val TextDim     = Color(0xFF7A8D9A)
val TextFaint   = Color(0xFF4C5E6A)

// Signal — the brand cyan, reserved for what is live, selected or actionable.
val Signal     = Color(0xFF00D1FF)
val SignalMute = Color(0xFF0B6E85)   // signal at rest: fills, inactive traces

// Status — each appears only when its condition holds.
val Pass       = Color(0xFF35C48B)   // confirmed / found
val Caution    = Color(0xFFE8A33D)   // needs attention, slow, costly
val Fault      = Color(0xFFE4585E)   // failed / invalid

// Back-compatible aliases. Older screens refer to the palette by these names;
// pointing them at the new roles calms the whole app at once instead of
// leaving pockets of the old five-accent scheme behind.
val CyanAccent   = Signal
val MintGreen    = Pass
val Amber        = Caution
val CoralRed     = Fault
val Lavender     = TextDim      // was a decorative accent; demoted to neutral
val DarkBase     = Ink
val DarkSurface  = Panel
val DarkSurface2 = Inset
val OnDark       = TextPrimary
val OnDarkMuted  = TextDim
val ResultGreen  = Pass

private val WhiteDNSDarkScheme = darkColorScheme(
    primary              = Signal,
    onPrimary            = Color(0xFF00222B),
    primaryContainer     = Color(0xFF06323D),
    onPrimaryContainer   = Color(0xFFB6ECF8),
    secondary            = TextDim,
    onSecondary          = Ink,
    secondaryContainer   = Inset,
    onSecondaryContainer = TextPrimary,
    tertiary             = Pass,
    onTertiary           = Color(0xFF00251A),
    error                = Fault,
    onError              = Color(0xFF2B0407),
    errorContainer       = Color(0xFF3A1417),
    onErrorContainer     = Color(0xFFFFD9DA),
    background           = Ink,
    onBackground         = TextPrimary,
    surface              = Panel,
    onSurface            = TextPrimary,
    surfaceVariant       = Inset,
    onSurfaceVariant     = TextDim,
    outline              = RuleLit,
    outlineVariant       = Rule,
    scrim                = Color(0xCC05080A),
)

/**
 * Data readout style. Every number, address, port and parsed result uses this,
 * so machine output is visually separable from prose at a glance.
 */
val MonoData = TextStyle(
    fontFamily = FontFamily.Monospace,
    fontSize = 12.sp,
    lineHeight = 16.sp,
    letterSpacing = 0.sp,
)

/** Small tracked capitals used for section eyebrows and instrument labels. */
val MonoLabel = TextStyle(
    fontFamily = FontFamily.Monospace,
    fontSize = 10.sp,
    fontWeight = FontWeight.Bold,
    letterSpacing = 1.6.sp,
)

// A tighter scale than the Material default, which is sized for content apps
// and leaves this one looking loose and shouty.
private val WhiteDNSTypography = Typography(
    titleLarge  = TextStyle(fontSize = 19.sp, lineHeight = 25.sp, fontWeight = FontWeight.SemiBold, letterSpacing = (-0.2).sp),
    titleMedium = TextStyle(fontSize = 15.sp, lineHeight = 20.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 0.sp),
    titleSmall  = TextStyle(fontSize = 13.sp, lineHeight = 18.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 0.1.sp),
    bodyLarge   = TextStyle(fontSize = 14.sp, lineHeight = 20.sp),
    bodyMedium  = TextStyle(fontSize = 13.sp, lineHeight = 18.sp),
    bodySmall   = TextStyle(fontSize = 12.sp, lineHeight = 17.sp),
    labelLarge  = TextStyle(fontSize = 13.sp, lineHeight = 17.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.2.sp),
    labelMedium = TextStyle(fontSize = 11.sp, lineHeight = 15.sp, fontWeight = FontWeight.Medium, letterSpacing = 0.3.sp),
    labelSmall  = TextStyle(fontSize = 10.sp, lineHeight = 14.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.4.sp),
)

// Instruments are square-ish. The Material default rounding is what makes a
// stock Compose app recognisable on sight.
private val WhiteDNSShapes = Shapes(
    extraSmall = RoundedCornerShape(3.dp),
    small      = RoundedCornerShape(5.dp),
    medium     = RoundedCornerShape(7.dp),
    large      = RoundedCornerShape(10.dp),
    extraLarge = RoundedCornerShape(12.dp),
)

@Composable
fun WhiteDNSTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = WhiteDNSDarkScheme,
        typography = WhiteDNSTypography,
        shapes = WhiteDNSShapes,
        content = content,
    )
}
