package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// A fast scan must reach the same verdict as a normal one while asking fewer
// questions: once enough domains have confirmed an endpoint, the rest cannot
// change the answer and are dropped.
func TestFastModeStopsProbingOnceVerdictIsReached(t *testing.T) {
	var mu sync.Mutex
	hosts := map[string]int{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hosts[r.Host]++
		mu.Unlock()
		// Echoing the Host inside an HTML body is what the classifier accepts on.
		fmt.Fprintf(w, "<html><body>%s</body></html>", r.Host)
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split server addr: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	domains := []string{
		"alpha.example", "bravo.example", "charlie.example",
		"delta.example", "echo.example", "foxtrot.example",
	}

	probe := func(fast bool) (*IPScanResult, int) {
		mu.Lock()
		hosts = map[string]int{}
		mu.Unlock()

		s := NewScanner(nil)
		opts := IPScanOptions{
			Ports:                     []int{port},
			Timeout:                   3 * time.Second,
			ProbeDomainsHTTP:          domains,
			AdaptiveDomainConcurrency: 1, // serialize so the early exit is observable
			FastMode:                  fast,
		}
		res := s.probeHTTP(context.Background(), host, port, opts)

		mu.Lock()
		defer mu.Unlock()
		return res, len(hosts)
	}

	normal, normalHosts := probe(false)
	fast, fastHosts := probe(true)
	t.Logf("normal: status=%s score=%d hosts=%d passed=%v", normal.Status, normal.DomainScore, normalHosts, normal.PassedDomains)
	t.Logf("fast:   status=%s score=%d hosts=%d passed=%v", fast.Status, fast.DomainScore, fastHosts, fast.PassedDomains)

	if normal.Status != "accept" {
		t.Fatalf("normal scan: want accept, got %q (%s)", normal.Status, normal.Error)
	}
	if fast.Status != "accept" {
		t.Fatalf("fast scan reached a different verdict: want accept, got %q (%s)", fast.Status, fast.Error)
	}
	if normalHosts != len(domains) {
		t.Errorf("normal scan probed %d/%d domains; it should probe them all", normalHosts, len(domains))
	}
	if fastHosts >= normalHosts {
		t.Errorf("fast scan probed %d domains vs %d normal; it should stop early", fastHosts, normalHosts)
	}
	if fast.DomainScore < minimumDomainAcceptScore(len(domains)) {
		t.Errorf("fast scan accepted on %d confirmations, below the %d it needs",
			fast.DomainScore, minimumDomainAcceptScore(len(domains)))
	}
}
