package com.whitescan.app.ui

import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.CloudQueue
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.whitescan.app.ScanKind

data class FormState(
    val targets: String = "",
    val ports: String = "",
    val concurrency: String = "50",   // phone-safe default
    val lowBandwidth: Boolean = false,
    val transferModel: String = "old",
    val sniDomains: String = "",
    val sniStrict: Boolean = false,
    // Edge platform the scan is scoped to (see EdgePickerScreen). The engine
    // probes that platform's hostnames, so an accepted IP is one that serves it.
    val edgeProvider: String = "",
    val edgeProbeDomains: String = "",
    // Fast scans stop probing an endpoint once its verdict is settled: same
    // accepted IPs, less work each. The engine ignores it in Lite / low-bandwidth
    // mode, where the extra attempts are what make a hit findable at all.
    val fastMode: Boolean = false,
    val verboseLog: Boolean = false,
    val liteMode: Boolean = false,
    val dnsProtocol: String = "both",     // dnsscan.Options.Protocol: udp | tcp | both | all
    val dnsReference: String = "google",  // truth-table reference resolver
    val dnsScanDepth: String = "full",    // fast skips hijack validation; full runs every check
    val dnsTestNearby: Boolean = false,   // expand + rescan the /24 around tunnel-ready hits
    // Speed test — runs after an IP scan on the IPs it found, ranking them by
    // download/upload speed and ping (Android only; IP scan only).
    val speedTestEnabled: Boolean = false,
    // DNSTT end-to-end tunnel test — runs after a DNS scan on its tunnel-ready shortlist.
    val e2eEnabled: Boolean = false,
    val e2eDomain: String = "",
    val e2ePubKey: String = "",
    val e2eTransport: String = "udp",     // udp | tcp (both working) | dot | doh (gated)
)

// Port sets people actually reach for, named by what they cover. Anything else
// goes in Custom, which keeps the ports field out of the way until it is wanted.
private data class PortPreset(val label: String, val ports: String)
private val PORT_PRESETS = listOf(
    PortPreset("HTTPS", "443"),
    PortPreset("Web", "80,443"),
    PortPreset("Cloudflare TLS", "443,2053,2083,2087,2096,8443"),
    PortPreset("Proxy ports", "80,8080,3128,1080"),
)

// Android-safe worker modes. High fanout on a phone saturates the radio and
// disconnects the device, so the modes are tuned down. "Ultra-light" and
// "Gentle" also probe fewer domains per IP (handled in the Go bridge).
private data class ConcurrencyPreset(val label: String, val value: String, val lowBw: Boolean = false)
private val CONCURRENCY_PRESETS = listOf(
    ConcurrencyPreset("Ultra-light (10)", "10", lowBw = true),
    ConcurrencyPreset("Gentle (25)",      "25", lowBw = true),
    ConcurrencyPreset("Safe (50)",        "50"),
    ConcurrencyPreset("Fast (100)",       "100"),
)

// DNS transport presets — couples a label with the engine protocol + port set,
// matching the desktop TUI's dnsPortPresets so behavior stays identical.
private data class DnsTransportPreset(val label: String, val protocol: String, val ports: String)
private val DNS_TRANSPORT_PRESETS = listOf(
    DnsTransportPreset("Port 53 - standard DNS (UDP + TCP)", "both", "53"),
    DnsTransportPreset("UDP/53 only - fastest transport", "udp", "53"),
    DnsTransportPreset("TCP/53 only - UDP-blocked networks", "tcp", "53"),
    DnsTransportPreset("DoT - DNS-over-TLS (853)", "all", "853"),
    DnsTransportPreset("DoH - DNS-over-HTTPS (443)", "all", "443"),
    DnsTransportPreset("All valid DNS ports (53 + 853 + 443)", "all", "53,853,443"),
)

private data class DnsDepthPreset(val label: String, val value: String)
private val DNS_DEPTH_PRESETS = listOf(
    DnsDepthPreset("Fast - 1.2s probes, one UDP attempt", "fast"),
    DnsDepthPreset("Thorough - retries + NXDOMAIN hijack checks", "full"),
)

// DNS reference resolver presets — the trusted resolver used to build the
// truth table candidate answers are checked against for poisoning.
private data class DnsReferencePreset(val label: String, val value: String)
private val DNS_REFERENCE_PRESETS = listOf(
    DnsReferencePreset("Google Public DNS - 8.8.8.8 (default)", "google"),
    DnsReferencePreset("Cloudflare - 1.1.1.1", "cloudflare"),
    DnsReferencePreset("Quad9 - 9.9.9.9", "quad9"),
)

// DNSTT end-to-end transport presets. UDP/53 and TCP/53 are wired up (TCP reaches
// servers where UDP/53 is poisoned); dnstt's DoT/DoH aren't vendored yet, so
// those chips are shown but disabled so the option set is clear without misleading.
private data class E2ETransportPreset(val label: String, val value: String, val enabled: Boolean)
private val E2E_TRANSPORT_PRESETS = listOf(
    E2ETransportPreset("UDP", "udp", enabled = true),
    E2ETransportPreset("TCP", "tcp", enabled = true),
    E2ETransportPreset("DoT", "dot", enabled = false),
    E2ETransportPreset("DoH", "doh", enabled = false),
)

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun ScanConfigForm(
    kind: ScanKind,
    form: FormState,
    onFormChange: (FormState) -> Unit,
    onStart: () -> Unit,
    onPickASN: () -> Unit,
    onPickEdge: () -> Unit,
) {
    val ctx = LocalContext.current
    var showWorkerMenu by remember { mutableStateOf(false) }
    var showAdvanced by remember { mutableStateOf(false) }
    var showCustomWorkers by remember {
        mutableStateOf(CONCURRENCY_PRESETS.none { it.value == form.concurrency })
    }
    // Ports that match no preset are the user's own, so the field stays open.
    var customPorts by remember {
        mutableStateOf(form.ports.isNotBlank() && PORT_PRESETS.none { it.ports == form.ports })
    }

    Column(Modifier.fillMaxSize()) {
        LazyColumn(
            modifier = Modifier.weight(1f),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 12.dp, bottom = 20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {

            // ── Targets ──────────────────────────────────────────────────────
            item {
                FormSection("TARGETS", summary = targetSummary(form.targets)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            "IPs, CIDRs or ASN ranges — one per line",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.weight(1f),
                        )
                        TextButton(onClick = {
                            paste(ctx) { text ->
                                val sep = if (form.targets.isBlank()) text
                                          else "${form.targets.trimEnd()}\n$text"
                                onFormChange(form.copy(targets = sep))
                            }
                        }) {
                            Icon(Icons.Default.ContentPaste, contentDescription = null,
                                modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Paste")
                        }
                    }
                    Spacer(Modifier.height(6.dp))
                    OutlinedTextField(
                        value = form.targets,
                        onValueChange = { onFormChange(form.copy(targets = it)) },
                        modifier = Modifier.fillMaxWidth().height(112.dp),
                        placeholder = { Text("1.2.3.0/24\n5.6.7.8") },
                    )
                    Spacer(Modifier.height(10.dp))
                    FilledTonalButton(
                        onClick = onPickASN,
                        shape = MaterialTheme.shapes.small,
                        modifier = Modifier.fillMaxWidth().height(50.dp),
                    ) {
                        Icon(Icons.Default.Dns, contentDescription = null, modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Select from ASN list")
                    }
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(
                        onClick = onPickEdge,
                        shape = MaterialTheme.shapes.small,
                        modifier = Modifier.fillMaxWidth().height(50.dp),
                    ) {
                        Icon(Icons.Default.CloudQueue, contentDescription = null,
                            modifier = Modifier.size(20.dp))
                        Spacer(Modifier.width(8.dp))
                        Text("Pick an edge network")
                    }
                    if (form.edgeProvider.isNotBlank()) {
                        Spacer(Modifier.height(10.dp))
                        EdgeScopeStrip(
                            provider = form.edgeProvider,
                            probeDomains = form.edgeProbeDomains,
                            onClear = {
                                onFormChange(form.copy(edgeProvider = "", edgeProbeDomains = ""))
                            },
                        )
                    }
                }
            }

            // ── Ports (everything but DNS, which couples port to transport) ───
            if (kind != ScanKind.DNS) {
                item {
                    FormSection("PORTS", summary = portSummary(form.ports)) {
                        FlowRow(
                            horizontalArrangement = Arrangement.spacedBy(6.dp),
                            verticalArrangement = Arrangement.spacedBy(6.dp),
                        ) {
                            PORT_PRESETS.forEach { preset ->
                                FilterChip(
                                    selected = !customPorts && form.ports == preset.ports,
                                    onClick = {
                                        customPorts = false
                                        onFormChange(form.copy(ports = preset.ports))
                                    },
                                    label = { Text(preset.label) },
                                    modifier = Modifier.height(36.dp),
                                )
                            }
                            FilterChip(
                                selected = customPorts,
                                onClick = { customPorts = true },
                                label = { Text("Custom") },
                                modifier = Modifier.height(36.dp),
                            )
                        }
                        if (customPorts) {
                            Spacer(Modifier.height(10.dp))
                            OutlinedTextField(
                                value = form.ports,
                                onValueChange = { onFormChange(form.copy(ports = it)) },
                                modifier = Modifier.fillMaxWidth(),
                                label = { Text("Ports and ranges") },
                                placeholder = { Text("443,2053,8000-8100") },
                                singleLine = true,
                            )
                        } else {
                            Spacer(Modifier.height(8.dp))
                            DataLine(
                                if (form.ports.isBlank()) "Engine defaults"
                                else form.ports.split(",").joinToString("  ") { it.trim() }
                            )
                        }
                    }
                }
            }

            // ── DNS transport / depth / reference — matches the desktop screens ─
            if (kind == ScanKind.DNS) {
                item {
                    FormSection("DNS TRANSPORT") {
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            DNS_TRANSPORT_PRESETS.forEach { preset ->
                                FilterChip(
                                    selected = form.dnsProtocol == preset.protocol && form.ports == preset.ports,
                                    onClick = {
                                        onFormChange(form.copy(dnsProtocol = preset.protocol, ports = preset.ports))
                                    },
                                    label = { Text(preset.label) },
                                    modifier = Modifier.fillMaxWidth().height(40.dp),
                                )
                            }
                        }
                    }
                }
                item {
                    FormSection("SCAN DEPTH") {
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            DNS_DEPTH_PRESETS.forEach { preset ->
                                FilterChip(
                                    selected = form.dnsScanDepth == preset.value,
                                    onClick = { onFormChange(form.copy(dnsScanDepth = preset.value)) },
                                    label = { Text(preset.label) },
                                    modifier = Modifier.fillMaxWidth().height(40.dp),
                                )
                            }
                        }
                        Spacer(Modifier.height(8.dp))
                        Text(
                            if (form.dnsScanDepth == "fast")
                                "Uses a short probe deadline and skips UDP compatibility retries and NXDOMAIN hijack probes"
                            else
                                "Runs compatibility retries and repeated NXDOMAIN hijack validation",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
                item {
                    FormSection("REFERENCE RESOLVER") {
                        Text(
                            "The trusted resolver every answer is checked against for poisoning",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(8.dp))
                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                            DNS_REFERENCE_PRESETS.forEach { preset ->
                                FilterChip(
                                    selected = form.dnsReference == preset.value,
                                    onClick = { onFormChange(form.copy(dnsReference = preset.value)) },
                                    label = { Text(preset.label) },
                                    modifier = Modifier.fillMaxWidth().height(40.dp),
                                )
                            }
                        }
                        Spacer(Modifier.height(12.dp))
                        SwitchRow(
                            checked = form.dnsTestNearby,
                            enabled = !form.liteMode,
                            title = "Test nearby IPs",
                            detail = if (form.liteMode)
                                "Off in Lite mode — each hit would expand into a 256-address /24 rescan"
                            else
                                "Also expand and rescan the /24 around every tunnel-ready resolver found",
                            onCheckedChange = { onFormChange(form.copy(dnsTestNearby = it)) },
                        )
                    }
                }
            }

            // ── Transfer model (HTTP / SOCKS5 only) ──────────────────────────
            if (kind == ScanKind.HTTP || kind == ScanKind.SOCKS5) {
                item {
                    FormSection("TRANSFER MODEL") {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            listOf("old" to "Stable", "brrr" to "Fast (goBrrrr)").forEach { (model, label) ->
                                FilterChip(
                                    selected = form.transferModel == model,
                                    onClick = { onFormChange(form.copy(transferModel = model)) },
                                    label = { Text(label) },
                                    modifier = Modifier.height(40.dp),
                                )
                            }
                        }
                    }
                }
            }

            // ── SNI domains + match mode (SNI scan only) ─────────────────────
            if (kind == ScanKind.SNI) {
                item {
                    FormSection("SNI DOMAINS", summary = if (form.sniStrict) "strict" else "lenient") {
                        Text(
                            "Leave blank to probe the built-in list",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        Spacer(Modifier.height(6.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.Top) {
                            OutlinedTextField(
                                value = form.sniDomains,
                                onValueChange = { onFormChange(form.copy(sniDomains = it)) },
                                modifier = Modifier.weight(1f).height(90.dp),
                                placeholder = { Text("workers.dev\npages.dev") },
                            )
                            FilledTonalIconButton(
                                onClick = { paste(ctx) { text ->
                                    val sep = if (form.sniDomains.isBlank()) text
                                              else "${form.sniDomains.trimEnd()}\n$text"
                                    onFormChange(form.copy(sniDomains = sep))
                                } },
                                modifier = Modifier.size(48.dp).align(Alignment.CenterVertically),
                            ) { Icon(Icons.Default.ContentPaste, contentDescription = "Paste domains") }
                        }
                        Spacer(Modifier.height(12.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            FilterChip(
                                selected = form.sniStrict,
                                onClick = { onFormChange(form.copy(sniStrict = true)) },
                                label = { Text("Strict") },
                                modifier = Modifier.height(40.dp),
                            )
                            FilterChip(
                                selected = !form.sniStrict,
                                onClick = { onFormChange(form.copy(sniStrict = false)) },
                                label = { Text("Lenient") },
                                modifier = Modifier.height(40.dp),
                            )
                        }
                        Spacer(Modifier.height(6.dp))
                        Text(
                            if (form.sniStrict)
                                "Strict: keeps a pair only when the edge answers that hostname with a certificate for it — the pairs you can actually spoof with"
                            else
                                "Lenient: any TLS handshake counts, including edges serving some other name",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }

            // ── Scan rate ────────────────────────────────────────────────────────
            item {
                FormSection("SCAN RATE", accent = SectionCost, summary = rateSummary(form)) {
                    val currentLabel = if (showCustomWorkers) "Custom (${form.concurrency} workers)"
                    else CONCURRENCY_PRESETS.find {
                        it.value == form.concurrency && it.lowBw == form.lowBandwidth
                    }?.label ?: "Custom (${form.concurrency} workers)"
                    Box(Modifier.fillMaxWidth()) {
                        OutlinedButton(
                            onClick = { showWorkerMenu = true },
                            modifier = Modifier.fillMaxWidth().height(50.dp),
                        ) {
                            Text(currentLabel, modifier = Modifier.weight(1f))
                            Icon(Icons.Default.ArrowDropDown, contentDescription = null)
                        }
                        DropdownMenu(expanded = showWorkerMenu, onDismissRequest = { showWorkerMenu = false }) {
                            CONCURRENCY_PRESETS.forEach { preset ->
                                DropdownMenuItem(
                                    text = { Text(preset.label) },
                                    onClick = {
                                        showCustomWorkers = false
                                        onFormChange(form.copy(concurrency = preset.value, lowBandwidth = preset.lowBw))
                                        showWorkerMenu = false
                                    },
                                )
                            }
                            DropdownMenuItem(
                                text = { Text("Custom…") },
                                onClick = { showCustomWorkers = true; showWorkerMenu = false },
                            )
                        }
                    }
                    if (showCustomWorkers) {
                        Spacer(Modifier.height(8.dp))
                        OutlinedTextField(
                            value = form.concurrency,
                            onValueChange = { onFormChange(form.copy(concurrency = it)) },
                            modifier = Modifier.fillMaxWidth(),
                            label = { Text("Worker count") },
                            singleLine = true,
                            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        )
                    }
                    Spacer(Modifier.height(12.dp))
                    SwitchRow(
                        checked = form.lowBandwidth,
                        title = "Low bandwidth mode",
                        detail = "Extends timeouts for slow or high-latency links",
                        onCheckedChange = { onFormChange(form.copy(lowBandwidth = it)) },
                    )
                    if (kind == ScanKind.IP) {
                        Spacer(Modifier.height(14.dp))
                        Text("Effort per IP", style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                        Spacer(Modifier.height(6.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            FilterChip(
                                selected = !form.fastMode,
                                onClick = { onFormChange(form.copy(fastMode = false)) },
                                label = { Text("Balanced") },
                                modifier = Modifier.height(40.dp),
                            )
                            FilterChip(
                                selected = form.fastMode,
                                enabled = !form.lowBandwidth && !form.liteMode,
                                onClick = { onFormChange(form.copy(fastMode = true)) },
                                label = { Text("Fast") },
                                modifier = Modifier.height(40.dp),
                            )
                        }
                        Spacer(Modifier.height(6.dp))
                        Text(
                            when {
                                form.lowBandwidth || form.liteMode ->
                                    "Fast is off on slow links and in Lite mode — the retries it drops are what find a hit there"
                                form.fastMode ->
                                    "Stops each IP as soon as its verdict is settled. Same IPs found, fewer probes each"
                                else ->
                                    "Tests every probe domain against every IP and retries flaky ones"
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }

            // ── After the scan ───────────────────────────────────────────────
            if (kind == ScanKind.IP || kind == ScanKind.DNS) {
                item {
                    FormSection("AFTER THE SCAN", accent = SectionAfter) {
                        if (kind == ScanKind.IP) {
                            SwitchRow(
                                checked = form.speedTestEnabled,
                                title = "Speed test the IPs found",
                                detail = "Benchmarks every clean IP and ranks them by download, upload and ping (uses extra data)",
                                onCheckedChange = { onFormChange(form.copy(speedTestEnabled = it)) },
                            )
                        }
                        if (kind == ScanKind.DNS) {
                            SwitchRow(
                                checked = form.e2eEnabled,
                                title = "End-to-end tunnel test",
                                detail = "Brings up a real DNSTT tunnel through every tunnel-ready resolver and keeps the ones that carry traffic",
                                onCheckedChange = { onFormChange(form.copy(e2eEnabled = it)) },
                            )
                            if (form.e2eEnabled) {
                                Spacer(Modifier.height(12.dp))
                                OutlinedTextField(
                                    value = form.e2eDomain,
                                    onValueChange = { onFormChange(form.copy(e2eDomain = it)) },
                                    modifier = Modifier.fillMaxWidth(),
                                    label = { Text("DNSTT domain") },
                                    placeholder = { Text("t.example.com") },
                                    singleLine = true,
                                )
                                Spacer(Modifier.height(8.dp))
                                OutlinedTextField(
                                    value = form.e2ePubKey,
                                    onValueChange = { onFormChange(form.copy(e2ePubKey = it)) },
                                    modifier = Modifier.fillMaxWidth(),
                                    label = { Text("DNSTT public key (hex)") },
                                    placeholder = { Text("64 hex chars") },
                                    singleLine = true,
                                )
                                Spacer(Modifier.height(12.dp))
                                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    E2E_TRANSPORT_PRESETS.forEach { preset ->
                                        FilterChip(
                                            selected = form.e2eTransport == preset.value,
                                            enabled = preset.enabled,
                                            onClick = { onFormChange(form.copy(e2eTransport = preset.value)) },
                                            label = { Text(preset.label) },
                                            modifier = Modifier.height(36.dp),
                                        )
                                    }
                                }
                                Spacer(Modifier.height(6.dp))
                                Text(
                                    "UDP and TCP are available — TCP helps where UDP/53 is poisoned. DoT and DoH are coming soon.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
            }

            // ── Advanced — set once, rarely touched again ────────────────────
            item {
                FormSection("ADVANCED", accent = SectionCost, summary = advancedSummary(form)) {
                    TextButton(
                        onClick = { showAdvanced = !showAdvanced },
                        modifier = Modifier.fillMaxWidth().height(44.dp),
                    ) {
                        Text(
                            if (showAdvanced) "Hide device and logging options"
                            else "Device and logging options",
                            modifier = Modifier.weight(1f),
                        )
                        Icon(
                            if (showAdvanced) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                            contentDescription = null,
                        )
                    }
                    if (showAdvanced) {
                        Spacer(Modifier.height(8.dp))
                        SwitchRow(
                            checked = form.liteMode,
                            title = "Lite mode",
                            detail = "Smaller batches and low concurrency so old or low-RAM phones don't crash (slower, same coverage)",
                            onCheckedChange = { onFormChange(form.copy(liteMode = it)) },
                        )
                        Spacer(Modifier.height(14.dp))
                        SwitchRow(
                            checked = form.verboseLog,
                            title = "Verbose probe logging",
                            detail = "Logs every probe. Slows the scan down — turn it on to debug",
                            onCheckedChange = { onFormChange(form.copy(verboseLog = it)) },
                        )
                    }
                }
            }
        }

        // ── Start — pinned, so it never hides below a long form ──────────────
        Surface(
            color = MaterialTheme.colorScheme.surface,
            tonalElevation = 3.dp,
            shadowElevation = 8.dp,
        ) {
            Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp)) {
                if (form.targets.isBlank()) {
                    Text(
                        "Add a target above to start — paste IPs, pick ASNs, or choose an edge network.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(Modifier.height(8.dp))
                }
                Button(
                    onClick = onStart,
                    modifier = Modifier.fillMaxWidth().height(54.dp),
                    enabled = form.targets.isNotBlank(),
                ) {
                    Text("Start scan", style = MaterialTheme.typography.titleSmall)
                    if (form.targets.isNotBlank()) {
                        Text(
                            "  ${targetSummary(form.targets)} · ${portSummary(form.ports)}",
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                        )
                    }
                }
            }
        }
    }
}

// A section's rail says what kind of setting it holds: signal for what gets
// scanned, caution for the knobs that spend battery, radio and exposure. What
// runs afterwards is not a state, so it takes the neutral ramp rather than a
// third colour invented to tell sections apart — that is what turns a palette
// into decoration. The rail is the same device the edge picker uses, so the
// two screens read as one instrument.
private val SectionScan = Signal
private val SectionCost = Caution
private val SectionAfter = TextFaint

// One group of settings. The header carries the section's current value on the
// right, so scrolling the form reads back the whole configuration without
// opening anything.
@Composable
private fun FormSection(
    label: String,
    accent: Color = SectionScan,
    summary: String? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    Surface(
        color = Panel,
        shape = MaterialTheme.shapes.small,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.height(IntrinsicSize.Min)) {
            Box(
                Modifier
                    .width(3.dp)
                    .fillMaxHeight()
                    .background(accent.copy(alpha = 0.8f)),
            )
            Column(Modifier.padding(start = 14.dp, end = 14.dp, top = 13.dp, bottom = 14.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        label,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 2.sp,
                        color = accent,
                        modifier = Modifier.weight(1f, fill = false),
                    )
                    if (!summary.isNullOrBlank()) {
                        Spacer(Modifier.width(10.dp))
                        Text(
                            summary,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            letterSpacing = 0.3.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.weight(1f),
                            textAlign = TextAlign.End,
                            maxLines = 1,
                        )
                    }
                }
                Spacer(Modifier.height(10.dp))
                content()
            }
        }
    }
}

// A toggle and the sentence that explains what it changes.
@Composable
private fun SwitchRow(
    checked: Boolean,
    title: String,
    detail: String,
    enabled: Boolean = true,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                title,
                style = MaterialTheme.typography.bodyMedium,
                color = if (enabled) MaterialTheme.colorScheme.onSurface
                        else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                detail,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(checked = checked, enabled = enabled, onCheckedChange = onCheckedChange)
    }
}

// Engine values echoed back to the user. Anything the engine will actually read
// is set in the data face on a recessed ground, so a value is never mistaken for
// the sentence explaining it.
@Composable
private fun DataLine(text: String) {
    Surface(
        color = MaterialTheme.colorScheme.background,
        shape = MaterialTheme.shapes.extraSmall,
    ) {
        Text(
            text,
            fontFamily = FontFamily.Monospace,
            fontSize = 12.sp,
            letterSpacing = 0.4.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 5.dp),
        )
    }
}

// ── header summaries ─────────────────────────────────────────────────────
// Each reads back what the section is currently set to, in one line.

private fun targetSummary(targets: String): String {
    val n = targets.split('\n', ',', ' ').count { it.isNotBlank() }
    return when (n) {
        0 -> "none"
        1 -> "1 range"
        else -> "$n ranges"
    }
}

private fun portSummary(ports: String): String {
    if (ports.isBlank()) return "defaults"
    val n = ports.split(',').count { it.isNotBlank() }
    return if (n == 1) ports.trim() else "$n ports"
}

private fun rateSummary(form: FormState): String {
    val effort = when {
        form.lowBandwidth || form.liteMode -> "balanced"
        form.fastMode -> "fast"
        else -> "balanced"
    }
    return "${form.concurrency} workers · $effort"
}

private fun advancedSummary(form: FormState): String {
    val on = buildList {
        if (form.liteMode) add("lite")
        if (form.verboseLog) add("verbose")
    }
    return if (on.isEmpty()) "off" else on.joinToString(" · ")
}

// Shown once a platform is chosen: names what the scan is scoped to and the
// hostnames every candidate IP is probed with.
@Composable
private fun EdgeScopeStrip(provider: String, probeDomains: String, onClear: () -> Unit) {
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.small,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(
            modifier = Modifier.padding(start = 14.dp, end = 6.dp, top = 10.dp, bottom = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    "EDGE SCOPE",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 10.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 2.sp,
                    color = CyanAccent,
                )
                Spacer(Modifier.height(3.dp))
                Text(
                    provider,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.SemiBold,
                )
                if (probeDomains.isNotBlank()) {
                    Text(
                        "Every target is probed with $probeDomains",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            TextButton(onClick = onClear) { Text("Clear") }
        }
    }
}

private fun paste(ctx: Context, apply: (String) -> Unit) {
    val clip = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
    val text = clip?.primaryClip?.getItemAt(0)?.coerceToText(ctx)?.toString()
    if (!text.isNullOrBlank()) apply(text)
}
