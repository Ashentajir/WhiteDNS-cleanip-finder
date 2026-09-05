package scanner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultSpeedEndpointsArePinnedToCandidate(t *testing.T) {
	// An endpoint that resolves normally measures the machine's own uplink, not
	// the candidate IP, so every candidate scores the same. Guard against one
	// creeping back in.
	for _, sni := range []string{"speed.cloudflare.com", "workers.dev"} {
		eps := DefaultSpeedEndpoints(10*1024*1024, sni)
		if len(eps) == 0 {
			t.Fatalf("sni %s: no download endpoints", sni)
		}
		if eps[0].Name != "cloudflare" {
			t.Fatalf("sni %s: want cloudflare first, got %q", sni, eps[0].Name)
		}
		for _, ep := range eps {
			if !ep.PinToCandidate {
				t.Errorf("sni %s: endpoint %q is not pinned to the candidate IP", sni, ep.Name)
			}
		}
	}
	if len(DefaultSpeedEndpoints(1, "workers.dev")) != 2 {
		t.Error("a non-Cloudflare SNI should add its own root as a second endpoint")
	}
	for _, ep := range DefaultUploadEndpoints() {
		if !ep.PinToCandidate {
			t.Errorf("upload endpoint %q is not pinned to the candidate IP", ep.Name)
		}
	}
}

func TestCopyForWindowStopsAtWindow(t *testing.T) {
	// A body that never ends must still yield a measurement.
	n, err := copyForWindow(slowInfiniteReader{delay: 20 * time.Millisecond}, 150*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n <= 0 {
		t.Fatal("expected some bytes to be counted")
	}
}

type slowInfiniteReader struct{ delay time.Duration }

func (r slowInfiniteReader) Read(p []byte) (int, error) {
	time.Sleep(r.delay)
	return len(p), nil
}

func TestMeasureUploadFallsBackOnFirstEndpointFailure(t *testing.T) {
	okServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer okServer.Close()
	okHost := okServer.Listener.Addr().String()

	opts := SpeedRankOptions{
		UploadBytes: 1024,
		Timeout:     2 * time.Second,
		UploadEndpoints: []SpeedEndpoint{
			{Name: "broken", URL: "https://127.0.0.1:1/__up"}, // nothing listens here -> dial error
			{Name: "ok", URL: "http://" + okHost + "/post"},
		},
	}
	opts.applyDefaults()

	mbps, source, err := measureUpload(context.Background(), okHost, opts)
	if err != nil {
		t.Fatalf("expected fallback to succeed, got err: %v", err)
	}
	if source != "ok" {
		t.Fatalf("expected fallback source 'ok', got %q", source)
	}
	if mbps <= 0 {
		t.Fatalf("expected positive mbps, got %f", mbps)
	}
}

func TestDedupeIPsStripsPortsAndDropsNonIPs(t *testing.T) {
	// Mirrors what the IP-scan -> speed-test auto-chain feeds in: "ip:port"
	// tokens plus passed-domain names split in as peers.
	in := []string{"1.1.1.1:443", "gemini.google.com", "chatgpt.com", "8.8.8.8:443", "instagram.com", "1.1.1.1:443", " 9.9.9.9 "}
	got := dedupeIPs(in)

	want := map[string]bool{"1.1.1.1": true, "8.8.8.8": true, "9.9.9.9": true}
	if len(got) != len(want) {
		t.Fatalf("expected %d unique IPs, got %d: %v", len(want), len(got), got)
	}
	for _, ip := range got {
		if !want[ip] {
			t.Fatalf("unexpected token survived dedupe: %q (full: %v)", ip, got)
		}
	}
}
