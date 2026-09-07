WhiteDNS v1.4.5 — WireGuard and AmneziaWG configs can finally be repointed at a clean IP, and the Android app has been rebuilt as an instrument rather than a menu.

## WireGuard and AmneziaWG

The config maker understood vless, vmess, trojan, ss and hysteria — all of which are single-line URIs. A WireGuard config is not: it is a multi-line INI document, and the parser had no way to represent one. Pasting a tunnel produced one broken "config" per line.

**A WireGuard or AmneziaWG config is now read as one config.** The whole `[Interface]` / `[Peer]` block is taken together, repointed at your clean IP by rewriting its `Endpoint` line, and written back with every other byte intact — including AmneziaWG's obfuscation parameters (`Jc`, `Jmin`, `Jmax`, `S1`, `S2`, `H1`–`H4`). Dropping one of those silently breaks the handshake, so they are preserved exactly rather than re-serialised.

A block ends where the INI ends, so proxy URIs pasted directly underneath a tunnel are not swallowed into it. A config with no `Endpoint` line gets one added inside its `[Peer]` section; a config with no `[Peer]` section is returned untouched rather than guessed at.

**Amnezia's own `vpn://` share links work too.** The link is unpacked from its compressed envelope and rewritten structurally rather than against a fixed schema, so a config from any Amnezia version keeps every field it arrived with. The container's embedded copy of the tunnel is repointed as well — without that, the client keeps dialling the old address behind an updated host. A link that cannot be decoded passes through untouched instead of being replaced with something corrupt.

The `wireguard://`, `wg://` and `awg://` URI forms some clients emit are handled, and the reverse direction — pulling `IP:port` endpoints back out — reads all of these too.

**Each tunnel is also written as its own `.conf`.** WireGuard clients import one tunnel per file and cannot read the combined text output, so rewritten tunnels land in a folder beside it, named so the WireGuard Android client will actually accept them as tunnel names.

*Note:* WireGuard is UDP and the IP scanner probes TCP. This works for the case it is meant for — pointing a tunnel at clean edge addresses that serve UDP — but a clean IP found by a TCP scan is not automatically a working WireGuard endpoint.

## The Android app, redesigned

The interface leaned on colour and gradient where it needed hierarchy. A four-stop gradient banner, nine list cards each with a differently coloured icon chip, and a five-stop progress bar whose hue changed with position rather than with anything measured.

**The app is now styled as the measurement instrument it is.** A stepped graphite ramp carries structure, one signal colour marks what is live or actionable, and three status colours appear only when that status is true. Rows separated by hairlines replace the floating cards, and colour enters on press, so the signal colour still means something. Monospace is reserved for machine data — addresses, ports, counts, results — and prose is set in the UI face.

The home screen groups its nine tools by the job they do rather than listing them flat. The scan screen leads with the figure you are waiting on. The config maker reports what your paste actually parsed into, per protocol, before you run it — it asks the engine, so the count on screen is the count you will get.

## Fixes

- The Android banner read **v1.4.0** while the build declared 1.4.4. It now comes from the build itself and cannot drift again.
- The scan log **stopped auto-scrolling** once its 50-line buffer filled — which is exactly when a long scan needs it.
- Share buttons **did nothing** when a file was missing or unreadable. They now say what went wrong.
- Config labels were truncated by byte, mangling Persian names; they now cut by character.
- A multi-line config would have broken the desktop review list's layout.
- Back and Telegram icons now mirror correctly in right-to-left layouts.

Desktop binaries, Android APKs/AAB, and SHA-256 checksums are attached below.
