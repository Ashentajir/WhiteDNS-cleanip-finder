package com.whitescan.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.whitescan.app.ScanUiState

@Composable
fun ScanningScreen(
    state: ScanUiState,
    onPauseResume: () -> Unit,
    onStop: () -> Unit,
    onViewResults: () -> Unit,
) {
    val logListState = rememberLazyListState()

    // Auto-scroll log to newest entry. Keyed on the newest line, not the list
    // size: the buffer is capped at 50 lines, so once it fills, size stops
    // changing and a size-keyed effect would never fire again — freezing the
    // log exactly during the long scans where it matters most.
    LaunchedEffect(state.logs.lastOrNull()) {
        if (state.logs.isNotEmpty()) {
            logListState.animateScrollToItem(state.logs.lastIndex)
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {

        // ── Progress ───────────────────────────────────────────────────────
        // One signal colour on a recessed track. The old five-stop rainbow was
        // decoration: the hue carried no information, it just changed along the
        // bar, which is exactly what made the screen look generic.
        val pct = if (state.total > 0) state.processed.toFloat() / state.total else 0f
        Column(verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.Bottom,
            ) {
                Text(
                    "${(pct * 100).toInt()}",
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 30.sp,
                    color = TextPrimary,
                )
                Text(
                    "%",
                    style = MonoData,
                    color = TextDim,
                    modifier = Modifier.padding(start = 2.dp, bottom = 5.dp),
                )
                Spacer(Modifier.weight(1f))
                Column(horizontalAlignment = Alignment.End) {
                    Text("SCANNED", style = MonoLabel, color = TextFaint)
                    Spacer(Modifier.height(2.dp))
                    Text("${state.processed} / ${state.total}", style = MonoData, color = TextPrimary)
                }
            }
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(4.dp)
                    .background(Inset),
            ) {
                if (pct > 0f) {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth(pct.coerceIn(0f, 1f))
                            .fillMaxHeight()
                            .background(Signal),
                    )
                }
            }
        }

        // ── Readouts ───────────────────────────────────────────────────────
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(1.dp),
        ) {
            Readout("FOUND", state.found.toString(), if (state.found > 0) Pass else TextPrimary, Modifier.weight(1f))
            Readout("UNIQUE IPS", state.uniqueIPs.toString(), TextPrimary, Modifier.weight(1f))
            Readout(
                "ETA",
                if (state.etaSec > 0) "${state.etaSec / 60}m ${state.etaSec % 60}s" else "--",
                TextPrimary,
                Modifier.weight(1f),
            )
        }

        // ── Current target ─────────────────────────────────────────────────
        if (state.currentIP.isNotEmpty()) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("PROBING", style = MonoLabel, color = TextFaint)
                Text(
                    state.currentIP,
                    style = MonoData,
                    color = Signal,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }

        // ── Live hits (last 6) ─────────────────────────────────────────────
        if (state.liveResults.isNotEmpty()) {
            SectionRule("Recent hits", state.found.toString())
            state.liveResults.takeLast(6).forEach { line ->
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Box(Modifier.size(4.dp).background(Pass))
                    Text(
                        line,
                        style = MonoData,
                        color = Pass,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }

        // ── Log tail ───────────────────────────────────────────────────────
        SectionRule("Log", "")
        LazyColumn(
            state = logListState,
            modifier = Modifier
                .weight(1f)
                .fillMaxWidth()
                .background(Inset, MaterialTheme.shapes.extraSmall)
                .padding(horizontal = 9.dp, vertical = 7.dp),
        ) {
            items(state.logs) { line ->
                Text(
                    line,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                    lineHeight = 14.sp,
                    color = TextDim,
                    softWrap = false,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }

        // ── Controls (48 dp touch targets) ────────────────────────────────
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            OutlinedButton(
                onClick = onPauseResume,
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.weight(1f).height(48.dp),
            ) {
                Icon(
                    if (state.paused) Icons.Default.PlayArrow else Icons.Default.Pause,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.width(6.dp))
                Text(if (state.paused) "Resume" else "Pause")
            }
            Button(
                onClick = onStop,
                shape = MaterialTheme.shapes.small,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error,
                ),
                modifier = Modifier.weight(1f).height(48.dp),
            ) {
                Icon(
                    Icons.Default.Stop,
                    contentDescription = null,
                    modifier = Modifier.size(20.dp),
                )
                Spacer(Modifier.width(6.dp))
                Text("Stop")
            }
        }

        if (state.done) {
            Button(
                onClick = onViewResults,
                shape = MaterialTheme.shapes.small,
                modifier = Modifier.fillMaxWidth().height(52.dp),
            ) {
                Text("View Results (${state.found})")
            }
        }
    }
}

/** One labelled value on the instrument face. */
@Composable
private fun Readout(label: String, value: String, valueColor: Color, modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .background(Panel)
            .padding(horizontal = 10.dp, vertical = 8.dp),
    ) {
        Text(label, style = MonoLabel, color = TextFaint)
        Spacer(Modifier.height(3.dp))
        Text(value, style = MonoData, fontWeight = FontWeight.Bold, color = valueColor)
    }
}

/** Section head: a tracked label, a hairline, and an optional count. */
@Composable
private fun SectionRule(label: String, count: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text(label.uppercase(), style = MonoLabel, color = TextDim)
        Box(Modifier.weight(1f).height(1.dp).background(Rule))
        if (count.isNotEmpty()) Text(count, style = MonoData, color = TextDim)
    }
}
