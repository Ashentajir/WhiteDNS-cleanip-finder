package config

import (
	"strings"
	"testing"
)

func TestEdgeProvidersWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range EdgeProviders {
		if seen[p.Name] {
			t.Fatalf("duplicate provider name %q", p.Name)
		}
		seen[p.Name] = true
		if len(p.Hosts) == 0 {
			t.Errorf("%s: no seed hosts to resolve", p.Name)
		}
		if len(p.ProbeDomains) == 0 {
			t.Errorf("%s: no probe domains, a scan could not confirm the platform", p.Name)
		}
		if GetEdgeProvider(p.Name) == nil {
			t.Errorf("%s: not found by GetEdgeProvider", p.Name)
		}
	}
	if GetEdgeProvider("nope") != nil {
		t.Error("unknown provider should not resolve")
	}
}

func TestEdgeTargetsDropIPv6WithoutRoute(t *testing.T) {
	p := EdgeProvider{CIDRs: []string{"104.16.0.0/13", "2606:4700::/32"}}
	got := p.Targets([]string{"9.9.9.9", "2606:4701::1"}, false)
	for _, target := range got {
		if strings.Contains(target, ":") {
			t.Errorf("IPv6 target %q kept on a host with no IPv6 route", target)
		}
	}
	if len(got) != 2 {
		t.Errorf("want the v4 /24 and the v4 range, got %v", got)
	}
}

func TestEdgeProviderTargets(t *testing.T) {
	p := EdgeProvider{CIDRs: []string{"104.16.0.0/13"}}
	// Live answers first, published ranges after; an address already inside a
	// published range adds nothing and is dropped.
	got := p.Targets([]string{"1.2.3.4", "1.2.3.9", "104.16.5.5", "2606:4700::1111", "not-an-ip", ""}, true)
	want := []string{"1.2.3.0/24", "2606:4700::1111", "104.16.0.0/13"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
