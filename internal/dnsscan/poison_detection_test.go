package dnsscan

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func dnsAResponseForTest(query []byte, rcode uint8, ip net.IP) []byte {
	questionEnd := skipDnsName(query, 12) + 4
	response := append([]byte(nil), query[:questionEnd]...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180|uint16(rcode))
	binary.BigEndian.PutUint16(response[10:12], 0)
	if ip == nil {
		binary.BigEndian.PutUint16(response[6:8], 0)
		return response
	}
	binary.BigEndian.PutUint16(response[6:8], 1)
	answer := []byte{
		0xc0, 0x0c,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x1e,
		0x00, 0x04,
	}
	answer = append(answer, ip.To4()...)
	return append(response, answer...)
}

func TestParseDnsMessageBindsQuestion(t *testing.T) {
	query, txid := buildDnsQuery("expected.example", 1, false)
	response := dnsAResponseForTest(query, 0, net.IPv4(192, 0, 2, 1))

	if _, _, _, err := parseDnsMessage(response, 1, txid, true, "expected.example"); err != nil {
		t.Fatalf("matching response rejected: %v", err)
	}
	if _, _, _, err := parseDnsMessage(response, 1, txid, true, "other.example"); err == nil ||
		!strings.Contains(err.Error(), "question mismatch") {
		t.Fatalf("response for wrong question accepted: %v", err)
	}
}

func TestReadUDPResponseWaitsPastInjectedNXDOMAIN(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))

	query, txid := buildDnsQuery("expected.example", 1, false)
	go func() {
		_, _ = server.Write(dnsAResponseForTest(query, 3, nil))
		_, _ = server.Write(dnsAResponseForTest(query, 0, net.IPv4(192, 0, 2, 9)))
	}()

	_, answers, _, injected, err := readUDPResponse(client, txid, 1, "expected.example", true)
	if err != nil {
		t.Fatalf("genuine answer after injection was lost: %v", err)
	}
	if !injected {
		t.Fatal("NXDOMAIN race was not reported")
	}
	if len(answers) != 1 || answers[0] != "192.0.2.9" {
		t.Fatalf("unexpected genuine answers: %v", answers)
	}
}
