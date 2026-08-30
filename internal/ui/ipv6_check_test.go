package ui

import "testing"

func TestHasIPv6Target(t *testing.T) {
	cases := map[string]bool{
		"192.168.1.1":          false,
		"10.0.0.0/8":           false,
		"2001:470:d:10b3::53":  true,
		"2001:470:d:10b3::/64": true,
		"not-an-ip":            false,
		"":                     false,
	}
	for in, want := range cases {
		if got := hasIPv6Target([]string{in}); got != want {
			t.Errorf("hasIPv6Target(%q) = %v, want %v", in, got, want)
		}
	}
	if !hasIPv6Target([]string{"1.2.3.4", "2606:4700::1"}) {
		t.Error("mixed list containing an IPv6 target should report true")
	}
}
