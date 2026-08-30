package scanner

import (
	"net"
	"testing"
)

func TestExpandCIDRSamplesBroadIPv6Prefix(t *testing.T) {
	got, err := expandCIDR("2001:db8::/48", 65536)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxIPv6PerCIDR {
		t.Fatalf("got %d IPv6 samples, want %d", len(got), maxIPv6PerCIDR)
	}
	if got[0] != "2001:db8::1" || got[len(got)-1] != "2001:db8:0:ffff::1" {
		t.Fatalf("samples do not span /48: first=%q last=%q", got[0], got[len(got)-1])
	}
	_, prefix, _ := net.ParseCIDR("2001:db8::/48")
	for _, value := range got {
		if !prefix.Contains(net.ParseIP(value)) {
			t.Fatalf("sample %q escaped %s", value, prefix)
		}
	}
}

func TestExpandCIDRKeepsLowAddressSweepForIPv6Slash64(t *testing.T) {
	got, err := expandCIDR("2001:db8:1::/64", 65536)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != maxIPv6PerCIDR || got[0] != "2001:db8:1::" || got[255] != "2001:db8:1::ff" {
		t.Fatalf("unexpected /64 sweep: len=%d first=%q last=%q", len(got), got[0], got[len(got)-1])
	}
}
