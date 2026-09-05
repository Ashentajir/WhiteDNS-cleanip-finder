WhiteDNS v1.4.2 — crash fixes, sharper edge-network scans, and a scan form that reads back what it is set to.

## Fixed

**Two crashes that could end a running scan.** The scanner's log and progress callbacks were plain fields: the UI attaches them when a scan starts and clears them when it ends, while workers and the health monitor are still calling them. That is a data race (reproduced under Go's race detector), and the surrounding "check, then call" reads could also see the clear land in between and call nothing at all. Separately, the desktop closed its message channel as soon as a scan returned — but stopping the health monitor does not wait for its goroutine, so a late log line could arrive afterwards and take the whole TUI down with it. Both paths are now guarded, with tests that fail if either returns.

**Lite-mode SNI scans probed only the first port.** The single-port shortcut the standard path had already dropped was still live in the Lite path, so phones in Lite mode scanned one port however many were selected. Fixed, along with the progress total and the chunk sizing, which divided its budget by the domain count alone and would have made a multi-port chunk that many times heavier than Lite mode is meant to allow.

## Edge network scans

**Hits are judged on the same evidence a plain IP scan collects.** A scoped scan previously replaced the standard probe domains with the platform's own, so a hit meant "this IP answers for vercel.app" and nothing more. It now probes both sets — the standard domains say the IP carries real traffic to the services people are trying to reach, the platform's own say it is that platform's edge — and requires one of the platform's to pass. Neither question answers the other, so both are asked and only the second decides. The fast path waits for the deciding domain before it stops.

**Targets are ordered the way they are useful.** The /24 around every address a platform actually answers with now comes first, its published ranges after. Those /24s are where the edge is live right now, and a scan stopped early — the normal case on a phone — should have spent its time there rather than walking the front of a /13. A /24 already inside a published range is dropped, and IPv6 targets are left out entirely on a device with no IPv6 route, where they could only time out.

*Expect Cloudflare addresses in these results, and keep them.* Render, Railway and Koyeb all front through Cloudflare, so a scan scoped to one of them returns Cloudflare addresses that hold a valid certificate for that platform's names. Those are working ways in, not stray matches: an edge refuses the TLS handshake outright for a name it does not front, which is what makes the platform requirement mean something. A required name now has to be backed by that certificate, or by the answer naming it — a CDN signature header alone is no longer enough, which matters most on port 80, where there is no certificate to check.

## Android

The scan form read as one long strip of identical grey cards. Sections now carry a coloured rail saying what kind of setting they hold — cyan for what gets scanned, amber for the knobs that spend battery, radio and exposure, lavender for what runs afterwards — the same device and colour meanings the edge picker uses, so the two screens read as one instrument. Each section header reads back its current value, so scrolling the form recites the whole configuration without opening anything, and engine values sit on a recessed ground in the data face so a value is never mistaken for the sentence explaining it. The edge picker now states what a choice costs in scan time.

Desktop binaries, Android APKs/AAB, and SHA-256 checksums are attached below.
