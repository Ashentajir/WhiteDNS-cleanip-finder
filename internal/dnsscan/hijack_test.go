package dnsscan

import (
	"archive/zip"
	"encoding/csv"
	"io"
	"os"
	"strings"
	"testing"
)

func negativeObservation(transport, name string, rcode uint8, answers uint16, ips ...string) hijackObservation {
	return hijackObservation{
		Transport: transport,
		Name:      name,
		Header:    DnsHeader{QR: true, Rcode: rcode, ANCount: answers},
		HeaderOK:  true,
		AnswerIPs: ips,
	}
}

func TestExpandedXLSXUsesValidColumnsBeyondZ(t *testing.T) {
	if got := xlsxCol(25); got != "Z" {
		t.Fatalf("column 25 = %q, want Z", got)
	}
	if got := xlsxCol(26); got != "AA" {
		t.Fatalf("column 26 = %q, want AA", got)
	}
	if got := xlsxCol(28); got != "AC" {
		t.Fatalf("column 28 = %q, want AC", got)
	}

	path := t.TempDir() + "/scan.xlsx"
	result := ResolverResult{
		IP: "192.0.2.53", Status: StatusHijack, Transparent: true,
		HijackConfidence: "high", HijackReason: "forged-a;stable-redirect",
		HijackUDP: true, HijackChecks: 4, HijackAnomalies: 2,
	}
	if err := writeXLSX(path, []ResolverResult{result}); err != nil {
		t.Fatal(err)
	}
	book, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer book.Close()
	var sheet string
	for _, entry := range book.File {
		if entry.Name != "xl/worksheets/sheet1.xml" {
			continue
		}
		reader, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		sheet = string(data)
	}
	for _, want := range []string{`dimension ref="A1:AI2"`, "AA", "RCODE", "QD", "AN", "Confidence", "Hijack evidence", "forged-a;stable-redirect"} {
		if !strings.Contains(sheet, want) {
			t.Errorf("XLSX sheet missing %q", want)
		}
	}
}

func TestHeaderSummaryAndDumpStayCompact(t *testing.T) {
	result := ResolverResult{
		Probes: []DnsProbeResult{{
			Protocol: "UDP/53",
			HeaderOK: true,
			Header: DnsHeader{
				ID: 0x1234, QR: true, AA: true, RD: true, RA: true,
				Rcode: 0, QDCount: 1, ANCount: 2, NSCount: 3, ARCount: 4,
			},
			AnswerIPs: []string{"192.0.2.1"},
		}},
	}
	mergeHeaderSummary(&result, result.Probes[0])
	if !result.AA || result.TC || !result.RD || result.RCodes != "UDP/53=0" || result.QDCount != 1 || result.ANCount != 2 {
		t.Fatalf("unexpected aggregate header summary: %+v", result)
	}
	dump := strings.Join(result.HeaderDump(), "\n")
	for _, want := range []string{"aa=Y", "tc=N", "rd=Y", "rcode=0", "qd=1", "an=2", "answer=192.0.2.1"} {
		if !strings.Contains(dump, want) {
			t.Errorf("compact probe details missing %q: %s", want, dump)
		}
	}
	for _, duplicated := range []string{"id=", "qr=", "ra=", "ns=", "ar="} {
		if strings.Contains(dump, duplicated) {
			t.Errorf("compact probe details repeat %q: %s", duplicated, dump)
		}
	}
}

func TestHijackClassifierAcceptsConsistentNXDOMAIN(t *testing.T) {
	got := classifyHijackObservations([]hijackObservation{
		negativeObservation("udp", "a.invalid", 3, 0),
		negativeObservation("udp", "b.invalid", 3, 0),
		negativeObservation("tcp", "a.invalid", 3, 0),
		negativeObservation("tcp", "b.invalid", 3, 0),
	})
	if got.Hijacked || got.Confidence != "none" || got.Anomalies != 0 {
		t.Fatalf("clean NXDOMAIN responses classified as hijack: %+v", got)
	}
}

func TestHijackClassifierFindsStableUDPRedirect(t *testing.T) {
	got := classifyHijackObservations([]hijackObservation{
		negativeObservation("udp", "a.invalid", 0, 1, "10.10.34.34"),
		negativeObservation("udp", "b.invalid", 0, 1, "10.10.34.34"),
		negativeObservation("tcp", "a.invalid", 3, 0),
		negativeObservation("tcp", "b.invalid", 3, 0),
	})
	if !got.Hijacked || got.Confidence != "high" || !got.UDP || got.TCP {
		t.Fatalf("stable transport-specific redirect was missed: %+v", got)
	}
	reasons := strings.Join(got.Reasons, ",")
	for _, want := range []string{"forged-a", "stable-redirect", "transport-specific"} {
		if !strings.Contains(reasons, want) {
			t.Fatalf("hijack evidence missing %q: %+v", want, got)
		}
	}
}

func TestHijackClassifierRequiresRepeatedWeakRewrite(t *testing.T) {
	one := classifyHijackObservations([]hijackObservation{
		negativeObservation("udp", "a.invalid", 0, 0),
		negativeObservation("udp", "b.invalid", 3, 0),
	})
	if one.Hijacked || one.Confidence != "low" {
		t.Fatalf("one weak anomaly should stay low-confidence: %+v", one)
	}
	two := classifyHijackObservations([]hijackObservation{
		negativeObservation("udp", "a.invalid", 0, 0),
		negativeObservation("udp", "b.invalid", 0, 0),
	})
	if !two.Hijacked || two.Confidence != "medium" {
		t.Fatalf("repeated NOERROR rewrite was not classified: %+v", two)
	}
}

func TestCSVAndHTMLContainTransportAndHijackEvidence(t *testing.T) {
	dir := t.TempDir()
	result := ResolverResult{
		IP: "192.0.2.53", Status: StatusHijack, Responded: true,
		UDPOK: true, TCPOK: true, PreferredTransport: "tcp", FallbackTransport: "udp",
		UDPPoisoned: true, TransportDisagreement: true, InjectionObserved: true,
		RA: true, AA: true, TC: true, RD: true, RCodes: "UDP/53=0,TCP/53=2", QDCount: 1, ANCount: 2,
		Transparent: true, HijackConfidence: "high", HijackReason: "forged-a;transport-specific",
		HijackUDP: true, HijackChecks: 4, HijackAnomalies: 2, HijackRCodes: "tcp:3,udp:0",
		HijackIP: "10.10.34.34",
	}
	csvPath := dir + "/scan.csv"
	htmlPath := dir + "/scan.html"
	if err := writeCSV(csvPath, []ResolverResult{result}); err != nil {
		t.Fatal(err)
	}
	if err := writeHTML(htmlPath, []ResolverResult{result}); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	rows, err := csv.NewReader(file).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	header := strings.Join(rows[0], ",")
	values := strings.Join(rows[1], ",")
	for _, want := range []string{"preferred_transport", "udp_poisoned", "injection_observed", "aa", "tc", "rd", "rcodes", "qd_records", "an_records", "hijack_confidence", "hijack_reason", "hijack_rcodes"} {
		if !strings.Contains(header, want) {
			t.Errorf("CSV header missing %q: %s", want, header)
		}
	}
	for _, want := range []string{"tcp", "high", "forged-a;transport-specific", "10.10.34.34"} {
		if !strings.Contains(values, want) {
			t.Errorf("CSV values missing %q: %s", want, values)
		}
	}
	htmlBody, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	body := string(htmlBody)
	for _, want := range []string{"Preferred", "UDP poison", "Injection", "AA", "TC", "RD", "RCODE", "QD", "AN", "Confidence", "Hijack evidence", "forged-a;transport-specific"} {
		if !strings.Contains(body, want) {
			t.Errorf("HTML missing %q", want)
		}
	}
	if strings.Contains(body, "Headers (qr/aa/tc/rd/ra rcode qd/an/ns/ar)") {
		t.Error("HTML still contains the unreadable full-header column")
	}
	if got, want := strings.Count(body, "<th>"), 35; got != want {
		t.Errorf("HTML has %d headers, want %d", got, want)
	}
	if got, want := strings.Count(body, "<td"), 35; got != want {
		t.Errorf("HTML row has %d cells, want %d", got, want)
	}
}
