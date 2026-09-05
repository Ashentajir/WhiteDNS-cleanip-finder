package scanner

import (
	"errors"
	"net"
	"reflect"
	"testing"
)

func TestIPToIntRepresentations(t *testing.T) {
	for _, ip := range []net.IP{net.ParseIP("203.0.113.9"), net.ParseIP("203.0.113.9").To4(), net.ParseIP("::ffff:203.0.113.9")} {
		if got := ipToInt(ip); got != 3405803785 {
			t.Fatalf("%v became %d", ip, got)
		}
	}
	for _, ip := range []net.IP{nil, {1, 2}, net.ParseIP("2001:db8::1")} {
		if got := ipToInt(ip); got != -1 {
			t.Fatalf("%v became %d", ip, got)
		}
	}
}

func TestExpansionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		input string
		limit int
		want  []string
	}{
		{"203.0.113.9", 10, []string{"203.0.113.9"}},
		{"2001:db8::1", 10, []string{"2001:db8::1"}},
		{"255.255.255.255/32", 10, []string{"255.255.255.255"}},
		{"192.0.2.3/30", 3, []string{"192.0.2.0", "192.0.2.1", "192.0.2.2"}},
		{"::ffff:192.0.2.1/128", 10, []string{"192.0.2.1"}},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", 10, []string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}},
		{"0.0.0.0/0", 2, []string{"0.0.0.0", "0.0.0.1"}},
		{"192.0.2.0/24", 0, nil},
	} {
		got, err := expandCIDR(tc.input, tc.limit)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %v, %v; want %v", tc.input, got, err, tc.want)
		}
	}
}

func TestStreamRangesOrderAndErrors(t *testing.T) {
	ranges := ParseIPRanges([]string{"203.0.113.9", "192.0.2.0/27", "2001:db8::1", "192.0.2.9-192.0.2.1", "255.255.255.255"})
	var batches [][]string
	err := StreamIPsFromRanges(ranges, 2, func(batch []string) error {
		batches = append(batches, batch)
		return nil
	})
	var got []string
	for _, batch := range batches {
		got = append(got, batch...)
	}
	if err != nil || len(got) != 34 || got[0] != "203.0.113.9" || got[1] != "192.0.2.0" || got[33] != "255.255.255.255" {
		t.Fatalf("unexpected stream: %v, %v", got, err)
	}
	stop := errors.New("stop")
	calls := 0
	err = StreamIPsFromRanges(ranges, 2, func([]string) error { calls++; return stop })
	if !errors.Is(err, stop) || calls != 1 {
		t.Fatalf("callback error lost: %v, calls %d", err, calls)
	}
	if err := StreamIPsFromRanges(ranges, 0, func([]string) error { t.Fatal("unexpected callback"); return nil }); err == nil {
		t.Fatal("zero batch size accepted")
	}
}

var expansionBenchResult []string

func BenchmarkIPExpansion(b *testing.B) {
	for _, input := range []string{"203.0.113.9", "192.0.0.0/16"} {
		b.Run(input, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				expansionBenchResult, _ = expandCIDR(input, 65536)
			}
		})
	}
}
