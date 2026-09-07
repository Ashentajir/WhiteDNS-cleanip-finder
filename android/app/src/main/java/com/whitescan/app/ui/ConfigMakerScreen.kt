package com.whitescan.app.ui

import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.whitescan.engine.mobile.Mobile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

private enum class CmMode { REWRITE, EXTRACT }

// Every format the engine's parser accepts, named the way the user's client
// names them. Shown as the empty state so the input explains itself.
private const val SUPPORTED_FORMATS =
    "vless · vmess · trojan · ss · hysteria2 · WireGuard · AmneziaWG · Amnezia vpn://"

/** What the engine parsed out of a paste. Counts come from the engine itself,
 *  so what is shown here is exactly what a run would produce. */
private data class ParsedInput(
    val configs: Int = 0,
    val targets: Int = 0,
    val breakdown: String = "",
)

@Composable
fun ConfigMakerScreen(dataDir: String) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    var mode by remember { mutableStateOf(CmMode.REWRITE) }
    var configs by remember { mutableStateOf("") }
    var targets by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var result by remember { mutableStateOf<CmResult?>(null) }
    var error by remember { mutableStateOf<String?>(null) }
    var parsed by remember { mutableStateOf(ParsedInput()) }

    // Re-parse shortly after typing stops. LaunchedEffect cancels its previous
    // run whenever the text changes, so the delay debounces large pastes
    // without a scan of the whole buffer on every keystroke.
    LaunchedEffect(configs, targets) {
        delay(180)
        parsed = withContext(Dispatchers.Default) {
            runCatching {
                ParsedInput(
                    configs = Mobile.configMakerCountConfigs(configs).toInt(),
                    targets = Mobile.configMakerCountTargets(targets).toInt(),
                    breakdown = Mobile.configMakerSummarizeConfigs(configs),
                )
            }.getOrDefault(ParsedInput())
        }
    }

    val needsTargets = mode == CmMode.REWRITE
    val ready = parsed.configs > 0 && (!needsTargets || parsed.targets > 0)
    // RewriteConfigs cycles the shorter list, so the run produces one config per
    // whichever list is longer.
    val outputCount = if (needsTargets) maxOf(parsed.configs, parsed.targets) else parsed.configs

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        ModeSwitch(
            mode = mode,
            onSelect = {
                if (it != mode) {
                    mode = it
                    result = null
                    error = null
                }
            },
        )

        Text(
            if (needsTargets)
                "Point working configs at clean IPs the scanner found. Every config and every target is used."
            else
                "Pull the IP:port endpoints back out of configs or any pasted text.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        Step(
            index = "01",
            title = if (needsTargets) "Your working configs" else "Configs or text to read",
            satisfied = parsed.configs > 0,
        ) {
            PasteField(
                value = configs,
                onChange = { configs = it; result = null; error = null },
                placeholder = "vless://…\n\n[Interface]\nPrivateKey = …",
                onPaste = { configs = appendClip(ctx, configs) },
                onClear = { configs = ""; result = null; error = null },
            )
            Readout(
                active = parsed.configs > 0,
                text = when {
                    configs.isBlank() -> SUPPORTED_FORMATS
                    parsed.configs == 0 -> "Nothing recognised yet"
                    else -> parsed.breakdown
                },
                accent = if (parsed.configs > 0) Pass else TextDim,
            )
        }

        if (needsTargets) {
            Step(
                index = "02",
                title = "Clean IP:port targets",
                satisfied = parsed.targets > 0,
            ) {
                PasteField(
                    value = targets,
                    onChange = { targets = it; result = null; error = null },
                    placeholder = "1.2.3.4:443\n5.6.7.8:8443",
                    onPaste = { targets = appendClip(ctx, targets) },
                    onClear = { targets = ""; result = null; error = null },
                    minHeight = 96.dp,
                )
                Readout(
                    active = parsed.targets > 0,
                    text = when {
                        targets.isBlank() -> "One IP:port per line. A bare IP defaults to :443."
                        parsed.targets == 0 -> "No valid IP:port targets yet"
                        else -> "${parsed.targets} target${if (parsed.targets == 1) "" else "s"}"
                    },
                    accent = if (parsed.targets > 0) Pass else TextDim,
                )
            }
        }

        error?.let {
            Surface(
                color = Color(0xFF2A1214),
                shape = MaterialTheme.shapes.extraSmall,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    it,
                    modifier = Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodySmall,
                    color = Fault,
                )
            }
        }

        Button(
            onClick = {
                if (busy) return@Button
                error = null
                result = null
                scope.launch {
                    busy = true
                    val run = withContext(Dispatchers.IO) {
                        runCatching {
                            val path = if (needsTargets)
                                Mobile.configMakerRewrite(dataDir, configs, targets)
                            else
                                Mobile.configMakerExtractIPs(dataDir, configs)
                            readResult(path)
                        }
                    }
                    busy = false
                    run.onSuccess { result = it }
                        .onFailure { error = it.message ?: "Could not write the output file." }
                }
            },
            enabled = !busy && ready,
            shape = MaterialTheme.shapes.small,
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
        ) {
            if (busy) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.onPrimary,
                )
            } else {
                Text(buttonLabel(mode, ready, parsed, outputCount), fontWeight = FontWeight.SemiBold)
            }
        }

        result?.let { ResultPanel(ctx, it) }
    }
}

/** Says exactly what pressing the button will do, or what is still missing. */
private fun buttonLabel(mode: CmMode, ready: Boolean, parsed: ParsedInput, outputCount: Int): String {
    if (mode == CmMode.EXTRACT) {
        return if (ready) "Extract IP:ports" else "Paste configs to read"
    }
    return when {
        parsed.configs == 0 -> "Paste your configs"
        parsed.targets == 0 -> "Add clean IP:port targets"
        else -> "Rewrite $outputCount config${if (outputCount == 1) "" else "s"}"
    }
}

// ── Pieces ──────────────────────────────────────────────────────────────────

/** Two exclusive modes, drawn as one control so it reads as a single choice
 *  rather than two independent toggles. */
@Composable
private fun ModeSwitch(mode: CmMode, onSelect: (CmMode) -> Unit) {
    val shape = RoundedCornerShape(6.dp)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Inset, shape)
            .padding(3.dp),
        horizontalArrangement = Arrangement.spacedBy(3.dp),
    ) {
        ModeSegment("Rewrite configs", mode == CmMode.REWRITE, Modifier.weight(1f)) {
            onSelect(CmMode.REWRITE)
        }
        ModeSegment("Extract IP:ports", mode == CmMode.EXTRACT, Modifier.weight(1f)) {
            onSelect(CmMode.EXTRACT)
        }
    }
}

@Composable
private fun ModeSegment(
    label: String,
    selected: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    val shape = RoundedCornerShape(4.dp)
    Box(
        modifier = modifier
            .background(if (selected) Panel else Color.Transparent, shape)
            .clickable(onClick = onClick)
            .padding(vertical = 10.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            label,
            style = MaterialTheme.typography.labelLarge,
            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
            color = if (selected) Signal else TextDim,
        )
    }
}

/** A numbered stage of the pipeline. The number carries the state: muted while
 *  the step is empty, mint once the engine has parsed something usable. */
@Composable
private fun Step(
    index: String,
    title: String,
    satisfied: Boolean,
    content: @Composable ColumnScope.() -> Unit,
) {
    val accent = if (satisfied) Pass else TextFaint
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text(index, style = MonoData, fontWeight = FontWeight.Bold, color = accent)
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                color = TextPrimary,
            )
            Box(Modifier.weight(1f).height(1.dp).background(Rule))
        }
        content()
    }
}

@Composable
private fun PasteField(
    value: String,
    onChange: (String) -> Unit,
    placeholder: String,
    onPaste: () -> Unit,
    onClear: () -> Unit,
    minHeight: Dp = 132.dp,
) {
    Row(
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.Top,
    ) {
        OutlinedTextField(
            value = value,
            onValueChange = onChange,
            modifier = Modifier
                .weight(1f)
                .heightIn(min = minHeight, max = 240.dp),
            placeholder = {
                Text(
                    placeholder,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                )
            },
            textStyle = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp),
        )
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            FilledTonalIconButton(onClick = onPaste, modifier = Modifier.size(46.dp)) {
                Icon(Icons.Default.ContentPaste, contentDescription = "Paste from clipboard")
            }
            if (value.isNotEmpty()) {
                IconButton(onClick = onClear, modifier = Modifier.size(46.dp)) {
                    Icon(
                        Icons.Default.Clear,
                        contentDescription = "Clear this field",
                        tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

/** The parse readout: what the engine found, reported the way the scanner
 *  reports a hit. This is the screen's one loud element — it is what turns a
 *  blind paste into something you can trust before running it. */
@Composable
private fun Readout(active: Boolean, text: String, accent: Color) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(Panel, MaterialTheme.shapes.extraSmall)
            .padding(horizontal = 10.dp, vertical = 7.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Box(Modifier.size(4.dp).background(if (active) accent else TextFaint))
        Text(text, style = MonoData, fontSize = 11.sp, color = accent)
    }
}

@Composable
private fun ResultPanel(ctx: Context, result: CmResult) {
    HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    "Saved ${result.lines} line${if (result.lines == 1) "" else "s"}",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold,
                    color = Pass,
                )
                Text(
                    result.file.name,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (result.confFiles.isNotEmpty()) {
                    Text(
                        "${result.confFiles.size} importable .conf in ${result.file.nameWithoutExtension}/",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        color = Signal,
                    )
                }
            }
            FilledTonalButton(
                onClick = { shareResult(ctx, result) },
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.height(42.dp),
            ) {
                Icon(Icons.Default.Share, contentDescription = null, modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(6.dp))
                Text("Share")
            }
        }

        if (result.truncated) {
            Text(
                "Showing the last ${result.preview.size} lines.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Surface(
            color = Inset,
            shape = MaterialTheme.shapes.extraSmall,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(Modifier.padding(10.dp)) {
                result.preview.forEach { line ->
                    Text(
                        line,
                        style = MonoData,
                        fontSize = 11.sp,
                        // INI section headers are structure, not data — tinting
                        // them keeps a multi-line WireGuard block readable.
                        color = if (line.trimStart().startsWith("[")) Signal else Pass,
                        modifier = Modifier.padding(vertical = 1.dp),
                    )
                }
            }
        }
    }
}

// ── Result loading & sharing ────────────────────────────────────────────────

private const val PREVIEW_LINES = 120

private data class CmResult(
    val file: File,
    val lines: Int,
    val preview: List<String>,
    val truncated: Boolean,
    val confFiles: List<File>,
)

/** Reads the engine's output for display. The line count is taken by streaming
 *  the file rather than from the preview, so a long output reports its real
 *  size instead of the preview cap. */
private fun readResult(path: String): CmResult {
    val file = File(path)
    val total = runCatching { file.useLines { it.count() } }.getOrDefault(0)
    val preview = runCatching { file.readLines().takeLast(PREVIEW_LINES) }.getOrDefault(emptyList())
    // ConfigMakerRewrite puts each WireGuard/AmneziaWG config in a folder
    // beside the text file, sharing its name.
    val confDir = File(file.parentFile, file.nameWithoutExtension)
    val confFiles = confDir.listFiles { f -> f.isFile && f.name.endsWith(".conf") }
        ?.sortedBy { it.name }
        ?: emptyList()
    return CmResult(file, total, preview, total > preview.size, confFiles)
}

private fun appendClip(ctx: Context, existing: String): String {
    val clip = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    val text = clip?.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(ctx)?.toString()
    return when {
        text.isNullOrBlank() -> existing
        existing.isBlank() -> text
        else -> existing.trimEnd() + "\n" + text
    }
}

private fun uriFor(ctx: Context, file: File): Uri? = try {
    FileProvider.getUriForFile(ctx, ctx.packageName + ".provider", file)
} catch (_: Exception) {
    null
}

/** Shares the text output, plus every generated .conf so a WireGuard config can
 *  go straight to the VPN client instead of being copied out by hand. */
private fun shareResult(ctx: Context, result: CmResult) {
    if (!result.file.exists()) {
        Toast.makeText(ctx, "The output file is no longer on disk.", Toast.LENGTH_SHORT).show()
        return
    }
    val uris = ArrayList<Uri>()
    uriFor(ctx, result.file)?.let { uris.add(it) }
    result.confFiles.forEach { conf -> uriFor(ctx, conf)?.let { uris.add(it) } }
    if (uris.isEmpty()) {
        Toast.makeText(ctx, "Cannot share from this folder.", Toast.LENGTH_SHORT).show()
        return
    }

    val intent = if (uris.size == 1) {
        Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_STREAM, uris[0])
        }
    } else {
        Intent(Intent.ACTION_SEND_MULTIPLE).apply {
            type = "text/plain"
            putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris)
        }
    }
    intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    ctx.startActivity(Intent.createChooser(intent, "Share config maker output"))
}
