WhiteDNS v1.4.4 — a platform scope that means what it says, and the app domains that matter actually working.

## Scoping a scan to a platform

**Pick a platform, bring your own targets.** Choosing Vercel now sets a scope rather than replacing what you are scanning. An ASN range, a pasted list or a file are all scanned against that platform, and the platform's own edge addresses become one target source among those rather than the only one. On the desktop the scan-mode screen names the active scope and the hostnames it will probe; on Android the scope survives swapping the targets, and the form says so.

**A scoped scan probes that platform's hostnames, and only those.** It had been merging the standard IP-scan set in, so an ASN range you picked was still being asked about `workers.dev` and `pages.dev` — and addresses could pass on those, answering a question about Cloudflare rather than the platform you chose.

*Verified live:* `76.76.21.0/25` scoped to Vercel probes `vercel.app, vercel.com, react.dev, nextjs.org` and accepts 25 addresses. The same range scoped to Cloudflare or Netlify accepts none.

## The app domains now work

`netlify.app`, `pages.dev`, `fly.dev`, `vercel.app`, `workers.dev` — the wildcard suffixes your apps actually live on — could never confirm anything. There is no site at the apex of a wildcard suffix, so an edge serving every app on the platform answers a probe with 404, 530 or nothing at all, and the probe gave up before looking at the certificate already on the table.

A scoped scan now settles the platform question the moment the TLS handshake completes. An edge refuses the handshake outright for a suffix it does not front, so holding a certificate for the name is the evidence, and no page needs to come back.

This applies to scoped scans only. A plain IP scan keeps its own accept rules, so it does not become "any TLS host with a valid certificate passes".

*Verified live:* an address holding a certificate for `onrender.com` that returns no page is rejected by an unscoped scan and accepted when scoped to Render.

## Target quality

**A stale seed hostname no longer drags a stranger's network into a scan.** One name in Cloudflare's seed list now resolves to a parked host on an unrelated network, and target-building widened it to a /24 that was then scanned as if it were Cloudflare. A platform that publishes its ranges tells us where its edge is, so answers from outside them are dropped; platforms that publish nothing are still mapped entirely from DNS.

Every platform's scope hostnames were checked against that platform's own edge for a certificate covering each name.

Desktop binaries, Android APKs/AAB, and SHA-256 checksums are attached below.
