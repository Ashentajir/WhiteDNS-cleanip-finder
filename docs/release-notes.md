HTTP and proxy scanning reliability fixes:
- Preserve HTTP request contexts until response bodies are read.
- Parse fragmented and chunked proxy responses correctly, with bounded reads.
- Fix SOCKS5 verification and IPv4, IPv6, and domain-form connection replies.
- Preserve explicit proxy IP:port targets, including bracketed IPv6 endpoints.
- Reject empty/error responses when assigning proxy service tags.
- Respect HTTP proxy concurrency limits and report completed verification progress.
- Correct single-IP expansion and prevent IPv6-to-IPv4 conversion.
- Reduce IPv4 expansion time and allocations; preserve streaming order and callback errors.

Also includes the current Android and desktop scan controls, edge-provider picker, fast-scan mode, stricter TLS validation, and candidate-specific speed ranking improvements.

Desktop binaries, Android APKs/AAB, and SHA-256 checksums are built and attached by CI.