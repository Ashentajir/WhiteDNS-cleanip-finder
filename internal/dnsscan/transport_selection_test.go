package dnsscan

import "testing"

func TestProtocolProbePlanHonorsSingleTransport(t *testing.T) {
	tests := []struct {
		protocol            string
		udp, tcp, encrypted bool
	}{
		{protocol: "udp", udp: true},
		{protocol: "tcp", tcp: true},
		{protocol: "both", udp: true, tcp: true},
		{protocol: "all", udp: true, tcp: true, encrypted: true},
	}
	for _, test := range tests {
		udp, tcp, encrypted := protocolProbePlan(test.protocol)
		if udp != test.udp || tcp != test.tcp || encrypted != test.encrypted {
			t.Errorf("%s plan = udp:%v tcp:%v encrypted:%v, want udp:%v tcp:%v encrypted:%v",
				test.protocol, udp, tcp, encrypted, test.udp, test.tcp, test.encrypted)
		}
	}
}

func TestTXTProbeUsesSelectedTransport(t *testing.T) {
	tests := []struct {
		protocol string
		port     int
		want     string
	}{
		{protocol: "udp", port: 53, want: "udp"},
		{protocol: "tcp", port: 53, want: "tcp"},
		{protocol: "both", port: 53, want: "udp"},
		{protocol: "all", port: 853, want: "dot"},
		{protocol: "all", port: 443, want: "doh"},
	}
	for _, test := range tests {
		got := txtProbeKind(Options{Protocol: test.protocol}, test.port)
		if got != test.want {
			t.Errorf("%s/%d TXT probe = %s, want %s", test.protocol, test.port, got, test.want)
		}
	}
}

func TestTunnelPassAcceptsCleanTCPWhenUDPIsPoisoned(t *testing.T) {
	r := ResolverResult{
		Responded: true,
		Probes: []DnsProbeResult{
			{Protocol: "UDP/53", Responded: true, HeaderOK: true, Header: DnsHeader{QR: true, RA: true}, EDNS: true, IsPoisoned: true},
			{Protocol: "TCP/53", Responded: true, HeaderOK: true, Header: DnsHeader{QR: true, RA: true}},
		},
		TxtProbes: []DnsProbeResult{
			{Protocol: "UDP/53", HeaderOK: true, Header: DnsHeader{QR: true, TC: true}},
			{Protocol: "TCP/53", Responded: true, HeaderOK: true, Header: DnsHeader{QR: true, RA: true}, AnswerTXT: []string{"tunnel-ok"}},
		},
		TxtPass:  true,
		Poisoned: true,
	}
	r.TunnelReady, r.TunnelTransport, r.TunnelReason = classifyTunnel(r)
	r.Status = classifyStatus(r)
	if !r.Passed() {
		t.Fatalf("clean TCP fallback should pass: status=%s ready=%v transport=%s reason=%s", r.Status, r.TunnelReady, r.TunnelTransport, r.TunnelReason)
	}
	if r.TunnelTransport != "tcp" {
		t.Fatalf("tunnel transport = %q, want tcp", r.TunnelTransport)
	}
}

func TestTunnelPassRejectsTXTFromDifferentDirtyTransport(t *testing.T) {
	r := ResolverResult{
		Responded: true,
		Probes: []DnsProbeResult{
			{Protocol: "UDP/53", HeaderOK: true, Header: DnsHeader{QR: true, RA: true}, EDNS: true, IsPoisoned: true},
			{Protocol: "TCP/53", HeaderOK: true, Header: DnsHeader{QR: true, RA: true}},
		},
		TxtProbes: []DnsProbeResult{
			{Protocol: "UDP/53", Responded: true, HeaderOK: true, Header: DnsHeader{QR: true, RA: true}, EDNS: true, AnswerTXT: []string{"udp-only"}},
		},
		TxtPass: true,
	}
	r.TunnelReady, r.TunnelTransport, r.TunnelReason = classifyTunnel(r)
	if r.TunnelReady {
		t.Fatalf("TXT only on poisoned UDP must not validate clean TCP: transport=%s reason=%s", r.TunnelTransport, r.TunnelReason)
	}
}

func TestStreamTunnelDoesNotRequireEDNS(t *testing.T) {
	r := ResolverResult{
		Responded: true,
		Probes:    []DnsProbeResult{{Protocol: "TCP/53", HeaderOK: true, Header: DnsHeader{QR: true, RA: true}}},
		TxtProbes: []DnsProbeResult{{Protocol: "TCP/53", Responded: true, HeaderOK: true, Header: DnsHeader{QR: true, RA: true}, AnswerTXT: []string{"ok"}}},
		TxtPass:   true,
	}
	ready, transport, reason := classifyTunnel(r)
	if !ready || transport != "tcp" {
		t.Fatalf("TCP tunnel rejected without EDNS: ready=%v transport=%q reason=%q", ready, transport, reason)
	}
}

func TestCanonicalPassRejectsHijack(t *testing.T) {
	r := ResolverResult{TunnelReady: true, Status: StatusHijack}
	if r.Passed() {
		t.Fatal("hijacked resolver passed canonical rule")
	}
}
