WhiteDNS v1.4.3 — a correction to how scoped scans judge a platform, and one identity domain restored.

A small release on top of v1.4.2. Coming from v1.4.1, everything in the v1.4.2 notes applies as well.

## Fixed

**A required platform domain now needs evidence about that name.** A scan scoped to an edge platform accepts an address only when one of the platform's own hostnames passes. That check previously counted a bare CDN signature header as a pass, which is not enough to conclude the platform is reachable through that address — the claim a scoped scan makes. It now takes a certificate covering the name, or the answer naming it.

Over TLS this rarely changes a verdict: an edge refuses the handshake outright for a name it does not front, so a completed handshake with a matching certificate was already real evidence. It matters on **port 80**, where there is no certificate to check and the signature header had been the whole basis.

**`railway.app` is back among Railway's identity domains.** v1.4.2 dropped it on the reasoning that a name resolving into Cloudflare identifies Cloudflare rather than Railway. That was backwards. Railway fronts through Cloudflare, so a Cloudflare address holding a valid certificate for `railway.app` is a working way in — exactly what the scan is looking for. Dropping it made Railway scans worse.

**The v1.4.2 notes carried the same mistake** and have been corrected in place.

## What to expect from a scoped scan

Render, Railway and Koyeb all front through Cloudflare, so scoping a scan to one of them returns Cloudflare addresses holding a valid certificate for that platform's names. Keep them — they are working ways in, not stray matches. Verified against a live Cloudflare edge, which serves `render.com`, `onrender.com`, `railway.app`, `koyeb.app` and `react.dev`, and refuses the handshake for `vercel.com`, `vercel.app`, `fly.dev` and `nextjs.org`. That refusal is what gives the platform requirement its teeth.

Desktop binaries, Android APKs/AAB, and SHA-256 checksums are attached below.
