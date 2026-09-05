package mobile

import (
	"strings"
	"testing"

	"whitedns-go/internal/scanner"
)

// An edge scan has to collect the same evidence a plain IP scan does, so the
// standard probe domains must all be present alongside the platform's own.
// This caught the list being wired to the SNI scanner's TLS hostnames instead.
func TestEdgeScanKeepsTheIPScanDomains(t *testing.T) {
	cfg := &ScanConfig{EdgeProvider: "Vercel (vercel.app)"}
	got := edgeProbeDomains(cfg)
	if len(got) == 0 {
		t.Fatal("no probe domains for a selected provider")
	}
	index := map[string]int{}
	for i, d := range got {
		index[strings.ToLower(d)] = i
	}

	for _, want := range scanner.DefaultProbeDomains() {
		if _, ok := index[strings.ToLower(want)]; !ok {
			t.Errorf("standard IP-scan domain %q missing from the edge scan: %v", want, got)
		}
	}

	required := edgeRequiredDomains(cfg)
	if len(required) == 0 {
		t.Fatal("a scoped scan must require the platform's own domains")
	}
	for _, want := range required {
		pos, ok := index[strings.ToLower(want)]
		if !ok {
			t.Errorf("required domain %q is not probed at all", want)
			continue
		}
		// Required names go first so a fast scan confirms the deciding one
		// before it stops.
		if pos >= len(scanner.DefaultProbeDomains()) && pos >= len(required) {
			continue
		}
		if pos >= len(required) {
			t.Errorf("required domain %q should sort before the standard set, got position %d", want, pos)
		}
	}

	if edgeProbeDomains(&ScanConfig{}) != nil {
		t.Error("no provider selected should leave the probe list alone")
	}
}
