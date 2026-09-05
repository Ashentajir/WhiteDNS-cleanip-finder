WhiteDNS v1.4.1 — edge-network targeting, a fast scan mode, and a round of scanning correctness fixes.

## New

**Edge network picker.** Pick the platform you want working IPs for instead of hand-feeding ranges: Cloudflare (CDN/Workers), Cloudflare Pages, Render, Fly.io, Railway, Vercel, Netlify, Koyeb and Glitch. Selecting one resolves that platform's own hostnames, widens each resolved IPv4 to its /24 (plus Cloudflare's published ranges), and hands the result to the normal review → ports → scan flow. The selection also scopes the scan's probe hostnames to that platform — `workers.dev`, `vercel.app`, `onrender.com` and so on — so an accepted IP is one that really serves it. Available on the desktop scan-mode screen and as a dedicated Android picker screen.

**Fast / Balanced IP scan.** The accept rule only needs one or two domain confirmations, but every endpoint used to probe all nine domains with retries; the extra probes could not change the verdict. Fast mode stops an endpoint as soon as its verdict is settled, skips retries and timeout padding, and culls unresponsive IPs after three strikes instead of ten — same accepted IPs, far fewer probes each. Balanced (every domain tested, flaky ones retried) remains the default and is what slow or lossy links should use. Fast mode is disabled automatically in Lite and low-bandwidth mode, where the dropped retries are what make a hit findable at all.

## Fixed

**HTTP probes never sent the probe domain.** The IP scanner set the `Host` header through `Header.Set`, which `net/http` ignores in favour of the URL host — so every HTTP probe asked the IP for its own default site and no domain token could ever match. Probes now set `req.Host`.

**Single IPs and IP ranges were scanned as `0.0.0.0`.** `net.ParseIP` returns a 16-byte address even for `1.2.3.4`, and the range walker read the first four bytes directly, yielding zero for any parsed IPv4 and an unrelated IPv4 for a real IPv6 address. Conversions now go through `To4()` and non-IPv4 ranges are skipped instead of being walked as garbage. This affected direct proxy discovery, masscan/nmap target building, and CIDR streaming alike.

**Caller-supplied probe domains are honoured.** Cloudflare's `workers.dev`/`pages.dev` were force-injected into every probe list, so a scan scoped to one platform could accept an IP that only answers for Cloudflare. An explicit list is now used verbatim; callers that pass nothing still get the built-in defaults.

**SNI scan results are usable for spoofing again.** Certificates are not verified during a probe, so nearly every live TLS server completes a handshake for an SNI it has never heard of — strict mode was passing almost any reachable IP. Strict now requires the edge to answer with a certificate that actually covers the requested hostname. The desktop passed-file records the `IP:PORT` *and* the hostname it accepted (the pair is the result); mobile scans every selected port instead of only the first; and an endpoint that refuses TCP is no longer redialled once per hostname.

**Speed & loss ranking measured the wrong thing.** Only the Cloudflare endpoint was pinned to the candidate IP — cachefly, hetzner, postman-echo and httpbin resolved normally, so any candidate that failed the pinned fetch was scored on your own uplink: identical numbers, flat ranking, and up to 100 MB of real traffic per IP. All unpinned fallbacks are gone, a non-Cloudflare edge is measured by asking it for its own root, and transfers are time-boxed rather than "move 10 MB or time out", so slow links produce a real number. "Reachable but nothing transfers" is now reported instead of a silent 0 Mbps.

**HTTP and proxy scanning reliability.**
- Preserve HTTP request contexts until response bodies are read.
- Parse fragmented and chunked proxy responses correctly, with bounded reads.
- Fix SOCKS5 verification and IPv4, IPv6, and domain-form connection replies.
- Preserve explicit proxy `IP:port` targets, including bracketed IPv6 endpoints.
- Reject empty and error responses when assigning proxy service tags.
- Respect the HTTP proxy concurrency limit you chose — the wave pipeline previously ignored it and ran a fixed 4000-wide fanout — and report completed verification progress.
- Bound direct discovery so a wide range cannot exhaust memory as `ip:port` strings.

## Faster

IPv4 expansion no longer allocates a `net.IP` and formats it per address; addresses are written into a stack buffer, and batches are pre-sized. Loading and expanding large target lists is markedly quicker on desktop and on phones.

## Build

Tagged releases now build and publish themselves: desktop binaries, Android APKs and the AAB, plus SHA-256 checksums, are produced by CI and attached to the release automatically.

Desktop binaries, Android APKs/AAB, and SHA-256 checksums are attached below.
