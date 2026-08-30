package dnsscan

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestNearbyIPsIPv6(t *testing.T) {
	got := NearbyIPs("2001:470:d:10b3::53")
	if len(got) != 256 {
		t.Fatalf("got %d nearby addresses, want 256", len(got))
	}
	if got[0] != "2001:470:d:10b3::" || got[0x53] != "2001:470:d:10b3::53" {
		t.Errorf("unexpected /120 sweep: first=%q [0x53]=%q", got[0], got[0x53])
	}
	if v4 := NearbyIPs("8.8.8.8"); len(v4) != 256 || v4[8] != "8.8.8.8" {
		t.Errorf("IPv4 /24 sweep regressed: len=%d [8]=%v", len(v4), v4)
	}
	if NearbyIPs("not-an-ip") != nil {
		t.Error("garbage input should yield nil")
	}
}

// Every dial/URL target must bracket IPv6 literals, or the probe never connects.
func TestIPv6AddressesAreBracketed(t *testing.T) {
	addr := net.JoinHostPort("2001:470:d:10b3::53", strconv.Itoa(853))
	if addr != "[2001:470:d:10b3::53]:853" {
		t.Fatalf("JoinHostPort = %q", addr)
	}
	url := "https://" + net.JoinHostPort("2001:470:d:10b3::53", strconv.Itoa(443)) + "/dns-query"
	if !strings.HasPrefix(url, "https://[2001:") {
		t.Errorf("DoH URL not bracketed: %q", url)
	}
}

// The report set must carry both a valid-DNS-server list and a tunnel-ready
// list, and "valid" must be a superset of "tunnel-ready".
func TestWriteReportsValidAndTunnelLists(t *testing.T) {
	results := []ResolverResult{
		{IP: "2001:470:d:10b3::53", Status: StatusValid, TunnelReady: true, Score: 6},
		{IP: "9.9.9.9", Status: StatusValid, TunnelReady: false, Score: 4},
		{IP: "10.0.0.1", Status: StatusPoison, TunnelReady: false, Score: 1},
		{IP: "10.0.0.2", Status: StatusInvalid},
	}
	dir := t.TempDir()
	paths, err := WriteReports(dir, results)
	if err != nil {
		t.Fatalf("WriteReports: %v", err)
	}

	read := func(p string) []string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", filepath.Base(p), err)
		}
		return strings.Fields(string(b))
	}

	valid := read(paths.Valid)
	if len(valid) != 2 || valid[0] != "2001:470:d:10b3::53" || valid[1] != "9.9.9.9" {
		t.Errorf("valid DNS list = %v, want both healthy resolvers (IPv6 first, best score)", valid)
	}
	tunnel := read(paths.TunnelReadyIPs)
	if len(tunnel) != 1 || tunnel[0] != "2001:470:d:10b3::53" {
		t.Errorf("tunnel-ready list = %v, want only the tunnel-capable resolver", tunnel)
	}
	if !strings.Contains(string(mustRead(t, paths.TunnelReady)), "2001:470:d:10b3::53") {
		t.Error("tunnel-ready detail report dropped the IPv6 resolver (column too narrow?)")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return b
}
