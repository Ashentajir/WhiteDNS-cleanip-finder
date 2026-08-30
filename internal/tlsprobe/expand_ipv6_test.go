package tlsprobe

import (
	"net"
	"testing"
)

// IPv6 prefixes must be capped far below the IPv4 cap, and must include the
// "prefix::" address itself (IPv6 reserves no network/broadcast address).
func TestExpandTargetsIPv6(t *testing.T) {
	got := ExpandTargets([]string{"2001:470:d:10b3::/64"})
	if len(got) != maxIPv6PerCIDR {
		t.Fatalf("a /64 expanded to %d addresses, want %d", len(got), maxIPv6PerCIDR)
	}
	if got[0] != "2001:470:d:10b3::" {
		t.Errorf("first address = %q, want the prefix itself", got[0])
	}
	if got[len(got)-1] != "2001:470:d:10b3::ff" {
		t.Errorf("last address = %q, want ...::ff", got[len(got)-1])
	}
	for _, s := range got {
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() != nil {
			t.Fatalf("expanded %q is not an IPv6 address", s)
		}
	}

	// A single IPv6 host and a /128 both yield exactly that address.
	for _, in := range []string{"2606:4700:4700::1111", "2606:4700:4700::1111/128"} {
		one := ExpandTargets([]string{in})
		if len(one) != 1 || one[0] != "2606:4700:4700::1111" {
			t.Errorf("ExpandTargets(%q) = %v, want the single host", in, one)
		}
	}

	// IPv4 behaviour is unchanged: /30 still skips network + broadcast.
	if v4 := ExpandTargets([]string{"10.0.0.0/30"}); len(v4) != 2 || v4[0] != "10.0.0.1" {
		t.Errorf("IPv4 /30 = %v, want the two usable hosts", v4)
	}

	// A broad ASN aggregate must sample across routed /64s rather than spending
	// the entire budget on 2001:db8::0 through 2001:db8::ff.
	broad := ExpandTargets([]string{"2001:db8::/48"})
	if len(broad) != maxIPv6PerCIDR {
		t.Fatalf("a /48 expanded to %d samples, want %d", len(broad), maxIPv6PerCIDR)
	}
	if broad[0] != "2001:db8::1" || broad[len(broad)-1] != "2001:db8:0:ffff::1" {
		t.Fatalf("/48 samples do not span the prefix: first=%q last=%q", broad[0], broad[len(broad)-1])
	}
	_, prefix, _ := net.ParseCIDR("2001:db8::/48")
	for _, sample := range broad {
		if !prefix.Contains(net.ParseIP(sample)) {
			t.Fatalf("sample %q escaped %s", sample, prefix)
		}
	}
}
