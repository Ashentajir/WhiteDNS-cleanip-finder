package mobile

import (
	"strings"
	"testing"

	"whitedns-go/internal/config"
)

// Picking a platform means asking every candidate address whether it serves
// that platform. Folding in the standard probe set would answer a different
// question and hand back addresses that passed on Cloudflare's or Google's
// names instead of the one the user chose.
func TestScopedScanProbesOnlyTheChosenPlatform(t *testing.T) {
	cfg := &ScanConfig{EdgeProvider: "Vercel (vercel.app)"}
	got := edgeProbeDomains(cfg)
	if len(got) == 0 {
		t.Fatal("no probe domains for a selected platform")
	}

	want := config.GetEdgeProvider("Vercel (vercel.app)").ProbeDomains
	if len(got) != len(want) {
		t.Fatalf("scoped scan probes %v, want exactly %v", got, want)
	}

	// The names that used to leak in from the standard set.
	for _, foreign := range []string{"workers.dev", "pages.dev", "gemini.google.com", "chatgpt.com"} {
		for _, d := range got {
			if strings.EqualFold(d, foreign) {
				t.Errorf("a Vercel scan is probing %q, which belongs to another platform", foreign)
			}
		}
	}

	// Every probed name must be one a hit can be credited to.
	required := edgeRequiredDomains(cfg)
	for _, d := range got {
		found := false
		for _, r := range required {
			if strings.EqualFold(d, r) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%q is probed but cannot credit a hit", d)
		}
	}

	if edgeProbeDomains(&ScanConfig{}) != nil {
		t.Error("no platform selected should leave the standard probe set in place")
	}
}
