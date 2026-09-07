package com.whitescan.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.whitescan.app.BuildConfig
import com.whitescan.app.ScanKind

/**
 * One entry in the index. The number is not decoration: the list is a fixed,
 * ordered inventory of the instrument's functions, and the number is how a user
 * refers to one — the same way the desktop TUI addresses them.
 */
private data class Tool(
    val icon: ImageVector,
    val title: String,
    val detail: String,
    val onOpen: () -> Unit,
)

@Composable
fun HomeScreen(onSelect: (ScanKind) -> Unit, onEdgeFinder: () -> Unit, onConfigMaker: () -> Unit) {
    val uriHandler = LocalUriHandler.current

    val findClean = listOf(
        Tool(Icons.Default.Search, "IP / CIDR Scan",
            "Direct probe of IP ranges on chosen ports") { onSelect(ScanKind.IP) },
        Tool(Icons.Default.CloudQueue, "Edge IP Finder",
            "Cloudflare, Vercel, Fly.io, Render, Netlify, Railway, Koyeb, Glitch", onEdgeFinder),
        Tool(Icons.Default.Lock, "SNI Scanner",
            "TLS hostname probe and domain-fronting detection") { onSelect(ScanKind.SNI) },
        Tool(Icons.Default.Speed, "Speed & Loss Rank",
            "Rank clean IPs by throughput and packet loss") { onSelect(ScanKind.SPEED) },
    )
    val findRelays = listOf(
        Tool(Icons.Default.Http, "HTTP Proxy Scan",
            "Three-wave open-proxy discovery") { onSelect(ScanKind.HTTP) },
        Tool(Icons.Default.Lan, "SOCKS5 Scan",
            "SOCKS5 proxy verification") { onSelect(ScanKind.SOCKS5) },
        Tool(Icons.Default.Public, "DNS Resolver / Tunnel",
            "Open recursion, EDNS0 and tunnel-readiness") { onSelect(ScanKind.DNS) },
    )
    val build = listOf(
        Tool(Icons.Default.Download, "ASN Export",
            "Search IranASNs, expand CIDRs to an IP list") { onSelect(ScanKind.ASN_EXPORT) },
        Tool(Icons.Default.Build, "Config Maker",
            "Repoint vless, vmess, trojan, ss, hysteria, WireGuard and Amnezia configs", onConfigMaker),
    )

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Ink),
        contentAlignment = Alignment.TopCenter,
    ) {
        Column(
            modifier = Modifier
                .widthIn(max = 600.dp)
                .fillMaxWidth()
                .verticalScroll(rememberScrollState()),
        ) {
            Masthead()

            var n = 1
            GroupRule("Find clean IPs")
            findClean.forEach { ToolRow(n++, it) }

            GroupRule("Find relays and resolvers")
            findRelays.forEach { ToolRow(n++, it) }

            GroupRule("Build and export")
            build.forEach { ToolRow(n++, it) }

            Spacer(Modifier.height(28.dp))
            Row(
                modifier = Modifier
                    .align(Alignment.CenterHorizontally)
                    .clickable { uriHandler.openUri("https://t.me/whitedns") }
                    .padding(horizontal = 14.dp, vertical = 10.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(7.dp),
            ) {
                Icon(
                    Icons.AutoMirrored.Filled.Send,
                    contentDescription = null,
                    tint = TextFaint,
                    modifier = Modifier.size(14.dp),
                )
                Text("t.me/whitedns", style = MonoData, color = TextDim)
            }
            Spacer(Modifier.height(20.dp))
        }
    }
}

/**
 * The masthead reads as an instrument nameplate rather than a banner: the
 * wordmark set in widely tracked monospace, the build stamped beside it, and a
 * single cyan rule as the only colour on the screen at rest. The rule is the
 * signature — restraint is what distinguishes this from every other dark
 * scanner UI, which all open with a gradient.
 */
@Composable
private fun Masthead() {
    Column {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(start = 18.dp, end = 18.dp, top = 26.dp, bottom = 14.dp),
            verticalAlignment = Alignment.Bottom,
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    "WHITEDNS",
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 25.sp,
                    letterSpacing = 7.sp,
                    color = TextPrimary,
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    "CLEAN IP FINDER",
                    style = MonoLabel,
                    color = TextFaint,
                )
            }
            Column(horizontalAlignment = Alignment.End) {
                Text("v" + BuildConfig.VERSION_NAME, style = MonoData, color = Signal)
                Spacer(Modifier.height(3.dp))
                Text("TAJIRAX", style = MonoLabel, color = TextFaint)
            }
        }
        // Two-tone rule: a short lit segment against the full hairline, the way
        // a scale is marked on an instrument face.
        Row(Modifier.fillMaxWidth().height(2.dp)) {
            Box(Modifier.width(64.dp).fillMaxHeight().background(Signal))
            Box(Modifier.weight(1f).fillMaxHeight().background(Rule))
        }
    }
}

/** Section eyebrow. Names which stage of the workflow the rows below serve. */
@Composable
private fun GroupRule(label: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 18.dp, end = 18.dp, top = 26.dp, bottom = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(label.uppercase(), style = MonoLabel, color = TextDim)
        Box(
            Modifier
                .weight(1f)
                .height(1.dp)
                .background(Rule)
        )
    }
}

/**
 * A row, not a card. Hairline-separated rows read as one continuous instrument
 * index; nine floating cards each with its own coloured chip read as a toy.
 * Colour enters only on press, so the signal colour still means "live".
 */
@Composable
private fun ToolRow(index: Int, tool: Tool) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val accent = if (pressed) Signal else TextFaint

    Column {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable(interactionSource = interaction, indication = null) { tool.onOpen() }
                .background(if (pressed) Panel else Color.Transparent)
                .padding(horizontal = 18.dp, vertical = 13.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Text(
                index.toString().padStart(2, '0'),
                style = MonoData,
                fontWeight = FontWeight.Bold,
                color = accent,
            )
            Icon(
                tool.icon,
                contentDescription = null,
                tint = if (pressed) Signal else TextDim,
                modifier = Modifier.size(19.dp),
            )
            Column(Modifier.weight(1f)) {
                Text(
                    tool.title,
                    style = MaterialTheme.typography.titleSmall,
                    color = if (pressed) Signal else TextPrimary,
                )
                Spacer(Modifier.height(2.dp))
                Text(
                    tool.detail,
                    style = MaterialTheme.typography.bodySmall,
                    color = TextDim,
                )
            }
        }
        Box(
            Modifier
                .fillMaxWidth()
                .padding(start = 18.dp)
                .height(1.dp)
                .background(Rule)
        )
    }
}
