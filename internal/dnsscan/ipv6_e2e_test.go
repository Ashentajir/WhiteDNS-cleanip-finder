package dnsscan

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// --- a minimal, well-behaved DNS server used to drive the scanner over IPv6 ---

const (
	e2eDomain   = "ipv6probe.test"
	e2eAnswer   = "93.184.216.34" // public-looking, so it is not treated as a bogon
	e2eTxt      = "whitedns-ipv6-passthrough"
	e2ePoisonIP = "203.0.113.7"  // off-truth answer
	e2eHijackIP = "198.51.100.9" // forged answer for a nonexistent name
)

// buildResponse answers the target domain truthfully and NXDOMAINs everything
// else, which is exactly how an honest recursive resolver behaves. Answering
// every name would trip the scanner's hijack detection.
// serverMode selects how the fake resolver misbehaves, so the same harness can
// prove detection parity between IPv4 and IPv6.
type serverMode int

const (
	modeHonest serverMode = iota
	modePoison            // wrong A answer for the target domain
	modeHijack            // forged A answer for names that should NXDOMAIN
)

func buildResponse(req []byte) []byte { return buildResponseMode(req, modeHonest) }

func buildResponseMode(req []byte, mode serverMode) []byte {
	if len(req) < 12 {
		return nil
	}
	// Walk the question name to find where QTYPE/QCLASS start.
	off := 12
	for off < len(req) {
		l := int(req[off])
		if l == 0 {
			off++
			break
		}
		off += l + 1
	}
	if off+4 > len(req) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(req[off : off+2])
	qEnd := off + 4
	name, _, err := readDnsName(req, 12)
	if err != nil {
		return nil
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")

	resp := append([]byte(nil), req[:qEnd]...)
	resp[2] = 0x80 | (req[2] & 0x01) // QR=1, echo RD
	resp[3] = 0x80                   // RA=1, rcode NOERROR

	var rdata []byte
	switch {
	case name != e2eDomain:
		// An honest resolver NXDOMAINs an unknown name; a hijacking one forges
		// an A record pointing at its own block page.
		if mode == modeHijack && qtype == 1 {
			rdata = net.ParseIP(e2eHijackIP).To4()
		} else {
			resp[3] = 0x80 | 3 // NXDOMAIN
		}
	case qtype == 1: // A
		answer := e2eAnswer
		if mode == modePoison {
			answer = e2ePoisonIP
		}
		rdata = net.ParseIP(answer).To4()
	case qtype == 16: // TXT
		rdata = append([]byte{byte(len(e2eTxt))}, []byte(e2eTxt)...)
	default:
		resp[3] = 0x80 | 3
	}

	binary.BigEndian.PutUint16(resp[4:6], 1) // QDCOUNT
	if rdata == nil {
		binary.BigEndian.PutUint16(resp[6:8], 0)
		return resp
	}
	binary.BigEndian.PutUint16(resp[6:8], 1) // ANCOUNT
	rr := []byte{0xC0, 0x0C}                 // name pointer to the question
	rr = binary.BigEndian.AppendUint16(rr, qtype)
	rr = binary.BigEndian.AppendUint16(rr, 1)   // class IN
	rr = binary.BigEndian.AppendUint32(rr, 300) // TTL
	rr = binary.BigEndian.AppendUint16(rr, uint16(len(rdata)))
	return append(resp, append(rr, rdata...)...)
}

// startIPv6Resolver serves DNS on [::1] over both UDP and TCP on one port.
func startIPv6Resolver(t *testing.T) int { return startIPv6ResolverMode(t, modeHonest) }

func startIPv6ResolverMode(t *testing.T, mode serverMode) int {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		pc, err := net.ListenPacket("udp6", "[::1]:0")
		if err != nil {
			t.Skipf("IPv6 loopback unavailable: %v", err)
		}
		_, portText, _ := net.SplitHostPort(pc.LocalAddr().String())
		ln, err := net.Listen("tcp6", "[::1]:"+portText)
		if err != nil {
			pc.Close()
			continue // port taken on TCP; try another
		}
		t.Cleanup(func() { pc.Close(); ln.Close() })

		go func() {
			buf := make([]byte, 4096)
			for {
				n, addr, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				if resp := buildResponseMode(buf[:n], mode); resp != nil {
					_, _ = pc.WriteTo(resp, addr)
				}
			}
		}()
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					var hdr [2]byte
					for {
						c.SetDeadline(time.Now().Add(5 * time.Second))
						if _, err := readFullConn(c, hdr[:]); err != nil {
							return
						}
						msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
						if _, err := readFullConn(c, msg); err != nil {
							return
						}
						resp := buildResponseMode(msg, mode)
						if resp == nil {
							return
						}
						out := binary.BigEndian.AppendUint16(nil, uint16(len(resp)))
						if _, err := c.Write(append(out, resp...)); err != nil {
							return
						}
					}
				}(conn)
			}
		}()
		p := 0
		fmt.Sscanf(portText, "%d", &p)
		return p
	}
	t.Fatal("could not bind matching UDP+TCP IPv6 port")
	return 0
}

func readFullConn(c net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		if err != nil {
			return got, err
		}
		got += n
	}
	return got, nil
}

// TestIPv6ScanEndToEnd drives the real scan pipeline against a real IPv6
// resolver: UDP + TCP probes, header decode, truth verification, hijack
// validation, tunnel classification, and the written report set.
func TestIPv6ScanEndToEnd(t *testing.T) {
	port := startIPv6Resolver(t)

	truth := NewTruthTable(e2eDomain)
	truth.TruthIPs[e2eAnswer] = true

	opts := Options{
		TargetDomain: e2eDomain,
		TxtDomain:    e2eDomain,
		Timeout:      3 * time.Second,
		Protocol:     "both", // UDP + TCP only; no DoT/DoH against this server
		Ports:        []int{port},
		ScanDepth:    ScanDepthFull, // include NXDOMAIN hijack validation
	}

	res := ScanResolver(context.Background(), "::1", opts, truth, nil, nil)

	if !res.Responded {
		t.Fatalf("IPv6 resolver did not respond: reason=%q probes=%+v", res.TunnelReason, res.HeaderDump())
	}
	if !res.UDPOK {
		t.Error("UDP over IPv6 failed — the UDP probe is not IPv6-clean")
	}
	if !res.TCPOK {
		t.Error("TCP over IPv6 failed — the TCP probe is not IPv6-clean")
	}
	if !res.RA {
		t.Error("RA not detected over IPv6")
	}
	if res.Poisoned {
		t.Errorf("truthful IPv6 answer flagged as poisoned (got %q)", res.PoisonIP)
	}
	if res.Transparent {
		t.Errorf("honest IPv6 resolver flagged as hijacked: %s", res.HijackReason)
	}
	if !res.TxtPass {
		t.Error("TXT passthrough failed over IPv6")
	}
	if res.Status != StatusValid {
		t.Errorf("status = %q, want %q (reason=%s)", res.Status, StatusValid, res.TunnelReason)
	}
	if res.IP != "::1" {
		t.Errorf("result IP = %q, want ::1", res.IP)
	}
	// BestLatency is deliberately not asserted: a sub-millisecond loopback RTT
	// rounds to 0 on Windows' coarse clock, so it measures the OS, not IPv6.
	if res.Score < 4 {
		t.Errorf("IPv6 compatibility score = %d/6, want >= 4 for a clean resolver", res.Score)
	}
}

// TestIPv6ScanResolversAndReports proves an IPv6 resolver survives the pooled
// entry point and lands in the written valid-DNS-server list.
func TestIPv6ScanResolversAndReports(t *testing.T) {
	port := startIPv6Resolver(t)
	truthCacheSeed(t, e2eDomain, e2eAnswer)

	opts := Options{
		TargetDomain: e2eDomain,
		TxtDomain:    e2eDomain,
		Timeout:      3 * time.Second,
		Protocol:     "both",
		Ports:        []int{port},
		Concurrency:  4,
		ScanDepth:    ScanDepthFast,
	}
	results := ScanResolvers(context.Background(), []string{"::1"}, opts, nil)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	if results[0].Status != StatusValid {
		t.Fatalf("pooled IPv6 scan status = %q, want valid (reason=%s)", results[0].Status, results[0].TunnelReason)
	}

	paths, err := WriteReports(t.TempDir(), results)
	if err != nil {
		t.Fatalf("WriteReports: %v", err)
	}
	valid := mustRead(t, paths.Valid)
	if strings.TrimSpace(string(valid)) != "::1" {
		t.Errorf("valid DNS server list = %q, want the IPv6 resolver", string(valid))
	}
}

// truthCacheSeed primes the shared truth cache so ScanResolvers does not need
// outbound internet to build its reference answers.
func truthCacheSeed(t *testing.T, domain, ip string) {
	t.Helper()
	table := NewTruthTable(domain)
	table.Prefer = ReferenceGoogle
	table.TruthIPs[ip] = true
	key := strings.ToLower(domain) + "\x00" + ReferenceGoogle
	truthCache.Lock()
	truthCache.entries[key] = truthCacheEntry{table: table, expiresAt: time.Now().Add(time.Hour)}
	truthCache.Unlock()
	t.Cleanup(func() {
		truthCache.Lock()
		delete(truthCache.entries, key)
		truthCache.Unlock()
	})
}

// TestIPv6DetectionParity proves the IPv6 path detects a lying resolver exactly
// as the IPv4 path does: an off-truth answer is poison, and a forged answer for
// a nonexistent name is a hijack.
func TestIPv6DetectionParity(t *testing.T) {
	truth := NewTruthTable(e2eDomain)
	truth.TruthIPs[e2eAnswer] = true

	newOpts := func(port int) Options {
		return Options{
			TargetDomain: e2eDomain, TxtDomain: e2eDomain,
			Timeout: 3 * time.Second, Protocol: "both",
			Ports: []int{port}, ScanDepth: ScanDepthFull,
		}
	}

	t.Run("poison", func(t *testing.T) {
		port := startIPv6ResolverMode(t, modePoison)
		res := ScanResolver(context.Background(), "::1", newOpts(port), truth, nil, nil)
		if !res.Responded {
			t.Fatal("poisoning IPv6 resolver did not respond")
		}
		if !res.Poisoned {
			t.Error("off-truth IPv6 answer was NOT detected as poisoned")
		}
		if res.Status != StatusPoison {
			t.Errorf("status = %q, want %q", res.Status, StatusPoison)
		}
		if res.Passed() {
			t.Error("poisoned IPv6 resolver must never be reported tunnel-ready")
		}
	})

	t.Run("hijack", func(t *testing.T) {
		port := startIPv6ResolverMode(t, modeHijack)
		res := ScanResolver(context.Background(), "::1", newOpts(port), truth, nil, nil)
		if !res.Responded {
			t.Fatal("hijacking IPv6 resolver did not respond")
		}
		if !res.Transparent {
			t.Errorf("forged NXDOMAIN answer over IPv6 was NOT detected (confidence=%q reason=%q)",
				res.HijackConfidence, res.HijackReason)
		}
		if res.Status != StatusHijack {
			t.Errorf("status = %q, want %q", res.Status, StatusHijack)
		}
		if res.Passed() {
			t.Error("hijacked IPv6 resolver must never be reported tunnel-ready")
		}
	})
}
