package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// An edge-provider scan probes the platform's hostnames alongside the standard
// set. Passing the standard ones only proves the IP carries traffic — it says
// nothing about which platform's edge it is — so a hit must include one of the
// platform's own names.
func TestRequiredProbeDomainsGateAcceptance(t *testing.T) {
	// Serves every host except the platform's, so only the standard names pass.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.Host, "vercel.app") {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintf(w, "<html><body>%s</body></html>", r.Host)
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	probe := func(required []string, fast bool) *IPScanResult {
		return NewScanner(nil).probeHTTP(context.Background(), host, port, IPScanOptions{
			Ports:                     []int{port},
			Timeout:                   3 * time.Second,
			ProbeDomainsHTTP:          []string{"vercel.app", "alpha.example", "bravo.example", "charlie.example"},
			RequiredProbeDomains:      required,
			AdaptiveDomainConcurrency: 1,
			FastMode:                  fast,
		})
	}

	for _, fast := range []bool{false, true} {
		name := map[bool]string{false: "balanced", true: "fast"}[fast]

		scoped := probe([]string{"vercel.app"}, fast)
		if scoped.Status == "accept" {
			t.Errorf("%s: IP accepted as a Vercel edge on %v, none of which is Vercel's",
				name, scoped.PassedDomains)
		}

		// Without the requirement the same endpoint is a normal IP-scan hit.
		unscoped := probe(nil, fast)
		if unscoped.Status != "accept" {
			t.Errorf("%s: unscoped scan should still accept this endpoint, got %q (%s)",
				name, unscoped.Status, unscoped.Error)
		}
	}
}

// The fast path stops probing once the verdict is settled. It must not stop
// before the domain that decides the verdict has actually been tried.
func TestFastModeWaitsForARequiredDomain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body>%s</body></html>", r.Host)
	}))
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ := strconv.Atoi(portStr)

	// The required name is probed last, so an early exit would miss it.
	res := NewScanner(nil).probeHTTP(context.Background(), host, port, IPScanOptions{
		Ports:                     []int{port},
		Timeout:                   3 * time.Second,
		ProbeDomainsHTTP:          []string{"alpha.example", "bravo.example", "charlie.example", "vercel.app"},
		RequiredProbeDomains:      []string{"vercel.app"},
		AdaptiveDomainConcurrency: 1,
		FastMode:                  true,
	})
	if res.Status != "accept" {
		t.Fatalf("fast scan stopped before probing the required domain: %q (%s), passed=%v",
			res.Status, res.Error, res.PassedDomains)
	}
}
