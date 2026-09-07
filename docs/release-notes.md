WhiteDNS v1.4.5 — WireGuard and AmneziaWG configs can finally be repointed at a clean IP.

## WireGuard and AmneziaWG

The config maker understood vless, vmess, trojan, ss and hysteria — all of which are single-line URIs. A WireGuard config is not: it is a multi-line INI document, and the parser had no way to represent one. Pasting a tunnel produced one broken "config" per line.

**A WireGuard or AmneziaWG config is now read as one config.** The whole `[Interface]` / `[Peer]` block is taken together, repointed at your clean IP by rewriting its `Endpoint` line, and written back with every other byte intact — including AmneziaWG's obfuscation parameters (`Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`–`H4`). Dropping one of those silently breaks the handshake, so they are preserved exactly rather than re-serialised.

A block ends where the INI ends, so proxy URIs pasted directly underneath a tunnel are not swallowed into it. A config with no `Endpoint` line gets one added inside its `[Peer]` section; a config with no `[Peer]` section is returned untouched rather than guessed at.

**Amnezia's own `vpn://` share links work too.** The link is unpacked from its compressed envelope and rewritten structurally rather than against a fixed schema, so a config from any Amnezia version keeps every field it arrived with. The container's embedded copy of the tunnel is repointed as well — without that, the client keeps dialling the old address behind an updated host. A link that cannot be decoded passes through untouched instead of being replaced with something corrupt.

The `wireguard://`, `wg://` and `awg://` URI forms some clients emit are handled, and the reverse direction — pulling `IP:port` endpoints back out of configs — reads all of these too.

**Each tunnel is also written as its own `.conf`.** WireGuard and AmneziaWG clients import one tunnel per file and cannot read the combined text output, so rewritten tunnels are also written individually, in a folder beside it, named so the WireGuard Android client will accept them as tunnel names.

*Note:* WireGuard is UDP and the IP scanner probes TCP. This works for the case it is meant for — pointing a tunnel at clean edge addresses that serve UDP — but a clean IP found by a TCP scan is not automatically a working WireGuard endpoint.

## Config maker

The desktop config maker names what it accepts on the source screen, and the review step now tallies what your paste actually parsed into, per protocol — so a WireGuard block being read as one config, rather than split into lines, is visible before anything is written.

Two display fixes came out of that: a multi-line config no longer shifts every row beneath it in the review list, and config names are truncated by character rather than by byte, which had been mangling Persian labels.

Desktop binaries, Android APKs/AAB, and SHA-256 checksums are attached below.
