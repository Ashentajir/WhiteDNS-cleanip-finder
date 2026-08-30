package dnsscan

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunProbesConcurrentlyPreservesOrder(t *testing.T) {
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	probes := make([]func() DnsProbeResult, 4)
	for i := range probes {
		index := i
		probes[i] = func() DnsProbeResult {
			started <- struct{}{}
			<-release
			return DnsProbeResult{Protocol: fmt.Sprintf("probe-%d", index)}
		}
	}

	resultCh := make(chan []DnsProbeResult, 1)
	go func() { resultCh <- runProbesConcurrently(probes) }()
	for range probes {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("not all probes started concurrently")
		}
	}
	close(release)
	results := <-resultCh
	for i, result := range results {
		want := fmt.Sprintf("probe-%d", i)
		if result.Protocol != want {
			t.Fatalf("result %d = %q, want %q", i, result.Protocol, want)
		}
	}
}

func TestScanDepthDefaultsToFull(t *testing.T) {
	if got := (Options{}).withDefaults().ScanDepth; got != ScanDepthFull {
		t.Fatalf("default scan depth = %q, want %q", got, ScanDepthFull)
	}
	if got := (Options{ScanDepth: ScanDepthFast}).withDefaults().ScanDepth; got != ScanDepthFast {
		t.Fatalf("fast scan depth = %q, want %q", got, ScanDepthFast)
	}
	if got := (Options{ScanDepth: ScanDepthThorough}).withDefaults().ScanDepth; got != ScanDepthFull {
		t.Fatalf("thorough alias = %q, want canonical %q", got, ScanDepthFull)
	}
	if got := (Options{ScanDepth: ScanDepthFast, Timeout: 5 * time.Second}).withDefaults().Timeout; got != fastProbeTimeout {
		t.Fatalf("fast timeout = %s, want %s", got, fastProbeTimeout)
	}
	if got := (Options{ScanDepth: ScanDepthFast, Timeout: 500 * time.Millisecond}).withDefaults().Timeout; got != 500*time.Millisecond {
		t.Fatalf("explicit shorter fast timeout changed to %s", got)
	}
}

func TestFastUDPProbeSkipsCompatibilityRetry(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	var requests atomic.Int32
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, readErr := conn.ReadFrom(buf)
			if readErr != nil {
				return
			}
			requests.Add(1)
			response := append([]byte(nil), buf[:n]...)
			if len(response) >= 4 {
				response[2] |= 0x80                    // QR=response
				response[3] = (response[3] & 0xf0) | 1 // FORMERR
			}
			_, _ = conn.WriteTo(response, addr)
		}
	}()

	host, portText, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portText)
	_, _, _, _, _, _ = probeUDPWithFallback(context.Background(), host, "example.com", 1, time.Second, nil, port, false, false)
	if got := requests.Load(); got != 1 {
		t.Fatalf("fast UDP probe sent %d requests, want one", got)
	}
	_, _, _, _, _, _ = probeUDPWithFallback(context.Background(), host, "example.com", 1, time.Second, nil, port, false, true)
	if got := requests.Load(); got != 3 {
		t.Fatalf("thorough UDP probe total requests = %d, want one fast + two thorough", got)
	}
}

func TestClassifyStatusDoesNotCallRefusedResponsePoison(t *testing.T) {
	r := ResolverResult{
		Responded: true,
		Probes: []DnsProbeResult{{
			Protocol: "UDP/53",
			HeaderOK: true,
			Header:   DnsHeader{QR: true, Rcode: 5},
		}},
	}
	if got := classifyStatus(r); got != StatusInvalid {
		t.Fatalf("REFUSED resolver classified %q, want %q", got, StatusInvalid)
	}
}

func TestCompletedResultsDropsUnstartedSlots(t *testing.T) {
	results := []ResolverResult{{IP: "1.1.1.1"}, {}, {IP: "2001:db8::1"}}
	got := completedResults(results, []bool{true, false, true})
	if len(got) != 2 || got[0].IP != "1.1.1.1" || got[1].IP != "2001:db8::1" {
		t.Fatalf("completed results = %+v", got)
	}
}
