package tlsprobe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Certificates are never verified during a probe, so almost every live TLS
// server completes a handshake for an SNI it has never heard of. Strict mode
// therefore has to key on the certificate actually covering the hostname —
// otherwise it reports every reachable IP as a domain-fronting candidate.
func TestStrictModeRequiresCertificateForTheSNI(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	// httptest's certificate covers example.com, not anything else.
	match := ProbeOne(host, "example.com", port, 5*time.Second, true)
	if !match.CertMatchesSNI {
		t.Fatalf("expected the test cert to cover example.com, got kind=%q err=%q", match.ResultKind, match.Error)
	}
	if !match.Success {
		t.Errorf("strict scan dropped a genuinely spoofable pair: %+v", match)
	}

	other := ProbeOne(host, "not-in-the-cert.example", port, 5*time.Second, true)
	if !other.SNIAccepted {
		t.Fatal("expected the handshake itself to succeed — that is the point of the test")
	}
	if other.Success {
		t.Error("strict scan reported a pair whose certificate does not cover the SNI as usable")
	}

	lenient := ProbeOne(host, "not-in-the-cert.example", port, 5*time.Second, false)
	if !lenient.Success {
		t.Error("lenient scan should still count a reachable TLS endpoint")
	}
}

// An endpoint that refuses TCP refuses it for every hostname, so the scan must
// not pay the full dial-with-retries cost once per hostname.
func TestUnreachableEndpointIsProbedOnce(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().(*net.TCPAddr)
	l.Close() // nothing is listening here now

	results := make(chan ProbeResult, 16)
	go RunScanContext(context.Background(), ScanConfig{
		Targets:     []string{"127.0.0.1"},
		Hostnames:   []string{"a.example", "b.example", "c.example", "d.example"},
		Ports:       []int{addr.Port},
		TimeoutSec:  1,
		Concurrency: 1, // sequential, so the skip is deterministic
	}, results, nil)

	total, skipped := 0, 0
	for r := range results {
		total++
		if strings.Contains(r.Error, "skipped:") {
			skipped++
		}
		if r.Success {
			t.Errorf("nothing is listening, yet %s reported success", r.Hostname)
		}
	}
	if total != 4 {
		t.Fatalf("every tuple must still produce a result: got %d of 4", total)
	}
	if skipped != 3 {
		t.Errorf("want 3 hostnames skipped after the first dial failure, got %d", skipped)
	}
}
