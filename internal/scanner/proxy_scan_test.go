package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type byteReader struct{ io.Reader }

func (r byteReader) Read(p []byte) (int, error) { return r.Reader.Read(p[:1]) }

func TestProxyHTTPResponses(t *testing.T) {
	for _, tc := range []struct {
		name, raw                   string
		fingerprint, redirect, want bool
	}{
		{"split response", "HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\nExample Domain", true, false, true},
		{"chunked body", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\nExample\r\n7\r\n Domain\r\n0\r\n\r\n", true, false, true},
		{"header fingerprint", "HTTP/1.1 200 OK\r\nX-Name: Example Domain\r\nContent-Length: 0\r\n\r\n", true, false, false},
		{"invalid status", "HTTP/1.1 2000 OK\r\n\r\nExample Domain", true, false, false},
		{"proxy auth", "HTTP/1.1 407 Auth Required\r\nContent-Length: 0\r\n\r\n", false, true, false},
		{"empty", "", false, true, false},
		{"redirect tag", "HTTP/1.1 301 Moved\r\nContent-Length: 0\r\n\r\n", false, true, true},
		{"truncated body", "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nExample Domain", true, false, false},
		{"large header", "HTTP/1.1 200 OK\r\nX-Large: " + strings.Repeat("a", httpWave3Limit) + "\r\n\r\n", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := readProxyHTTPResponse(byteReader{strings.NewReader(tc.raw)}, tc.fingerprint, tc.redirect); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSOCKS5ReplyAddressTypes(t *testing.T) {
	for _, reply := range [][]byte{
		append([]byte{5, 0, 0, 1}, make([]byte, 6)...),
		append([]byte{5, 0, 0, 4}, make([]byte, 18)...),
		{5, 0, 0, 3, 3, 'a', 'b', 'c', 0, 80},
	} {
		stream := bytes.NewReader(append(reply, []byte("HTTP/")...))
		if !readSOCKS5Reply(byteReader{stream}) {
			t.Fatalf("valid reply rejected: %v", reply)
		}
		rest, _ := io.ReadAll(stream)
		if string(rest) != "HTTP/" {
			t.Fatalf("reply consumed response: %q", rest)
		}
		for i := 0; i < len(reply); i++ {
			if readSOCKS5Reply(bytes.NewReader(reply[:i])) {
				t.Fatalf("truncated reply accepted: %v", reply[:i])
			}
		}
	}
	for _, reply := range [][]byte{{4, 0, 0, 1, 0, 0, 0, 0, 0, 0}, {5, 1, 0, 1, 0, 0, 0, 0, 0, 0}, {5, 0, 1, 1, 0, 0, 0, 0, 0, 0}, {5, 0, 0, 9}} {
		if readSOCKS5Reply(bytes.NewReader(reply)) {
			t.Fatalf("invalid reply accepted: %v", reply)
		}
	}
}

func TestSOCKS5VerifierLocalProxy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		greeting := make([]byte, 3)
		if _, err = io.ReadFull(conn, greeting); err != nil {
			done <- err
			return
		}
		conn.Write([]byte{5, 0})
		request := make([]byte, 10)
		if _, err = io.ReadFull(conn, request); err != nil {
			done <- err
			return
		}
		conn.Write(append([]byte{5, 0, 0, 4}, make([]byte, 18)...))
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			done <- err
			return
		}
		if req.Method != "HEAD" {
			done <- fmt.Errorf("unexpected method %s", req.Method)
			return
		}
		_, err = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		done <- err
	}()
	if !(socks5Verifier{}).verify(listener.Addr().String(), 2*time.Second) {
		t.Error("working SOCKS5 proxy rejected")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestHTTPProbeReadsDelayedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		time.Sleep(30 * time.Millisecond)
		fmt.Fprintf(w, "<html><body>%s</body></html>", r.Host)
	}))
	defer server.Close()
	host, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	result := NewScanner(nil).probeHTTP(context.Background(), host, port, IPScanOptions{
		Timeout: time.Second, ProbeDomainsHTTP: []string{"alpha.example"}, AdaptiveDomainConcurrency: 1,
	})
	if result.Status != "accept" {
		t.Fatalf("delayed body rejected: %+v", result)
	}
}

func TestHTTPWaveConcurrencyAndProgress(t *testing.T) {
	var active, peak, finished atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		if r.UserAgent() == "Mozilla/5.0" {
			finished.Add(1)
		}
		// Wave 2 succeeds; wave 3 rejects without running external benchmarks.
		io.WriteString(w, "unrelated body")
	}))
	defer server.Close()
	s := NewScanner(nil)
	const total = 12
	last := 0
	s.proxyProgressCb = func(done, count, found int, endpoint string, ips int) {
		if done < last {
			t.Errorf("progress regressed from %d to %d", last, done)
		}
		if done == total && finished.Load() != total {
			t.Errorf("completed before final verification: %d", finished.Load())
		}
		last = done
	}
	candidates := make([]string, total)
	for i := range candidates {
		candidates[i] = server.Listener.Addr().String()
	}
	s.scanProxyCandidatesWave3(candidates, 2, time.Second, "old")
	if peak.Load() > 2 {
		t.Fatalf("concurrency exceeded: %d", peak.Load())
	}
	if last != total {
		t.Fatalf("final progress=%d", last)
	}
}

func TestDirectProxyExplicitEndpoints(t *testing.T) {
	got, err := NewScanner(nil).collectProxyCandidates([]string{
		"192.0.2.1:3128", "192.0.2.1:3128", "[2001:db8::1]:1080", "192.0.2.2", "192.0.2.3:99999",
	}, []int{8080}, "direct")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"192.0.2.1:3128": true, "[2001:db8::1]:1080": true, "192.0.2.2:8080": true}
	if len(got) != len(want) {
		t.Fatalf("unexpected endpoints %v", got)
	}
	for _, endpoint := range got {
		if !want[endpoint] {
			t.Errorf("unexpected endpoint %s", endpoint)
		}
	}
}
