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
	// No published ranges: targets come from DNS, so the v4 answer is widened
	// and the v6 one is dropped on a host that cannot route it.
	p := EdgeProvider{}
	got := p.Targets([]string{"9.9.9.9", "2606:4701::1"}, false)
	for _, target := range got {
		if strings.Contains(target, ":") {
			t.Errorf("IPv6 target %q kept on a host with no IPv6 route", target)
		}
	}
	if len(got) != 1 || got[0] != "9.9.9.0/24" {
		t.Errorf("want just the v4 /24, got %v", got)
	}
}

func TestEdgeTargetsFromDNSOnly(t *testing.T) {
	// A platform that publishes nothing is mapped entirely from what it answers.
	p := EdgeProvider{}
	got := p.Targets([]string{"1.2.3.4", "1.2.3.9", "2606:4700::1111", "not-an-ip", ""}, true)
	want := []string{"1.2.3.0/24", "2606:4700::1111"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestEdgeProviderTargets(t *testing.T) {
	p := EdgeProvider{CIDRs: []string{"104.16.0.0/13"}}
	// A platform that publishes its ranges is scanned inside them. An answer
	// from outside is a seed hostname that has moved on, and widening it would
	// scan a stranger's network under this platform's name.
	got := p.Targets([]string{"104.16.5.5", "172.104.149.86", "not-an-ip", ""}, true)
	if len(got) != 1 || got[0] != "104.16.0.0/13" {
		t.Fatalf("want only the published range, got %v", got)
	}
}
