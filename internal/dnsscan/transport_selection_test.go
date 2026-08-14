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
