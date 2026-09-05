package scanner

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// A whole scan with the UI's callbacks attached and then detached, the way the
// TUI drives one. Run under -race this covers the worker goroutines, the
// progress and log sinks, and the teardown that used to race with them.
func TestScanIPsWithCallbacksUnderLoad(t *testing.T) {
	t.Setenv("WHITE_DISABLE_HEALTH_GATE", "1")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body>%s</body></html>", r.Host)
	}))
	defer srv.Close()

	host, portStr, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	for _, fast := range []bool{false, true} {
		t.Run(map[bool]string{false: "balanced", true: "fast"}[fast], func(t *testing.T) {
			s := NewScanner(nil)

			var mu sync.Mutex
			logs, progress := 0, 0
			s.SetLogCallback(func(string) {
				mu.Lock()
				logs++
				mu.Unlock()
			})

			results, err := s.ScanIPsWithProgress([]string{host}, IPScanOptions{
				Ports:            []int{port},
				Concurrency:      8,
				Timeout:          3 * time.Second,
				ProbeDomainsHTTP: []string{"alpha.example", "bravo.example", "charlie.example"},
				FastMode:         fast,
			}, func(_, _, _ int, _ string, _ int) {
				mu.Lock()
				progress++
				mu.Unlock()
			})
			// Detach the way the UI does, while anything still running logs on.
			s.SetLogCallback(nil)
			s.SetProxyProgressCallback(nil)

			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			if len(results) == 0 {
				t.Fatalf("expected the local server to be accepted, got no results")
			}
			mu.Lock()
			gotLogs, gotProgress := logs, progress
			mu.Unlock()
			if gotLogs == 0 {
				t.Error("no log lines reached the UI sink")
			}
			if gotProgress == 0 {
				t.Error("no progress updates reached the UI sink")
			}
		})
	}
}
