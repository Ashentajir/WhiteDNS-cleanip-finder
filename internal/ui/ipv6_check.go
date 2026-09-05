package ui

import (
	"net"
	"strings"
	"time"

	"whitedns-go/internal/config"
)

// hasIPv6Target reports whether any target is an IPv6 address or prefix.
func hasIPv6Target(targets []string) bool {
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if i := strings.IndexByte(t, '/'); i >= 0 {
			t = t[:i]
		}
		if ip := net.ParseIP(t); ip != nil && ip.To4() == nil {
			return true
		}
	}
	return false
}

// localIPv6Usable reports whether this host has a usable IPv6 route.
func localIPv6Usable() bool { return config.LocalIPv6Usable() }

// warnIfNoIPv6 logs a warning when IPv6 targets are queued on a host without an
// IPv6 route — otherwise every probe fails instantly and the scan looks broken.
func (m *tuiModel) warnIfNoIPv6(targets []string) {
	if !hasIPv6Target(targets) || localIPv6Usable() {
		return
	}
	m.addLog("[!] IPv6 targets selected but this host has no IPv6 route — every IPv6 probe will fail. Check your connection or pick the IPv4 dataset.")
	m.setToast(sError.Render("x No IPv6 route on this host"), 6*time.Second)
}
