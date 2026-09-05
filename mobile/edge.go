package mobile

import (
	"fmt"
	"strings"

	"whitedns-go/internal/config"
)

// EdgeProviderList returns the selectable edge platforms, one per line:
//
//	name \t seedHostCount \t publishedRangeCount \t probeDomainsCSV
//
// The UI shows these as a picker; the chosen name is passed back to
// EdgeProviderTargets and set on ScanConfig.EdgeProvider.
func EdgeProviderList() string {
	var b strings.Builder
	for _, p := range config.EdgeProviders {
		fmt.Fprintf(&b, "%s\t%d\t%d\t%s\n", p.Name, len(p.Hosts), len(p.CIDRs), strings.Join(p.ProbeDomains, ","))
	}
	return b.String()
}

// EdgeProviderTargets resolves the named provider's seed hostnames and returns
// its scan targets (published ranges, the /24 around every resolved IPv4, and
// resolved IPv6 addresses), newline separated. It performs DNS lookups, so call
// it off the UI thread.
func EdgeProviderTargets(name string) (string, error) {
	p := config.GetEdgeProvider(name)
	if p == nil {
		return "", fmt.Errorf("unknown edge provider %q", name)
	}
	targets := p.Targets(p.Resolve())
	if len(targets) == 0 {
		return "", fmt.Errorf("no edge IPs resolved for %s (check DNS)", name)
	}
	return strings.Join(targets, "\n"), nil
}

// edgeProbeDomains returns the probe hostnames for the config's selected edge
// provider, or nil when none is selected. Scoping the probe to a platform's own
// hostnames is what makes an accepted IP one that actually serves that platform.
func edgeProbeDomains(cfg *ScanConfig) []string {
	if cfg == nil {
		return nil
	}
	p := config.GetEdgeProvider(strings.TrimSpace(cfg.EdgeProvider))
	if p == nil {
		return nil
	}
	return append([]string(nil), p.ProbeDomains...)
}

// edgeSpeedSNI returns the hostname the speed test should present when a
// platform is selected, so the pinned transfer reaches that edge rather than
// only Cloudflare's.
func edgeSpeedSNI(cfg *ScanConfig) string {
	if domains := edgeProbeDomains(cfg); len(domains) > 0 {
		return domains[0]
	}
	return ""
}
