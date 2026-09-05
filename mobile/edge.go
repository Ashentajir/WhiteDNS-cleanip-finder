package mobile

import (
	"fmt"
	"strings"

	"whitedns-go/internal/config"
	"whitedns-go/internal/scanner"
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
// its scan targets, newline separated: the /24 around every address the platform
// answers with first, then its published ranges. IPv6 targets are left out on a
// device with no IPv6 route. It performs DNS lookups, so call it off the UI
// thread.
func EdgeProviderTargets(name string) (string, error) {
	p := config.GetEdgeProvider(name)
	if p == nil {
		return "", fmt.Errorf("unknown edge provider %q", name)
	}
	targets := p.Targets(p.Resolve(), config.LocalIPv6Usable())
	if len(targets) == 0 {
		return "", fmt.Errorf("no edge IPs resolved for %s (check DNS)", name)
	}
	return strings.Join(targets, "\n"), nil
}

// edgeProbeDomains returns the hostnames a scan scoped to the config's edge
// provider should probe: the platform's own names plus the standard set, so an
// accepted IP is judged on the same evidence a plain IP scan collects. Returns
// nil when no platform is selected.
func edgeProbeDomains(cfg *ScanConfig) []string {
	p := selectedEdgeProvider(cfg)
	if p == nil {
		return nil
	}
	return p.ScanDomains(defaultScanDomains())
}

// edgeRequiredDomains returns the names at least one of which an endpoint must
// serve before it counts as a hit for the selected platform.
func edgeRequiredDomains(cfg *ScanConfig) []string {
	p := selectedEdgeProvider(cfg)
	if p == nil {
		return nil
	}
	return p.RequiredScanDomains()
}

func selectedEdgeProvider(cfg *ScanConfig) *config.EdgeProvider {
	if cfg == nil {
		return nil
	}
	return config.GetEdgeProvider(strings.TrimSpace(cfg.EdgeProvider))
}

// defaultScanDomains is the standard probe set a plain IP scan uses, so a
// scoped scan collects the same evidence on top of the platform check.
func defaultScanDomains() []string { return scanner.DefaultProbeDomains() }

// edgeSpeedSNI returns the hostname the speed test should present when a
// platform is selected, so the pinned transfer reaches that edge rather than
// only Cloudflare's.
func edgeSpeedSNI(cfg *ScanConfig) string {
	if p := selectedEdgeProvider(cfg); p != nil && len(p.ProbeDomains) > 0 {
		return p.ProbeDomains[0]
	}
	return ""
}
