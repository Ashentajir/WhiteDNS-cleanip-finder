package dnsscan

import (
	"fmt"
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
}
