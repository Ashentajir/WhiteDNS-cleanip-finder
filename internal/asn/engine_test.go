package asn

import (
	"strings"
	"testing"
)

func TestSearchSummariesPrioritizesTypedName(t *testing.T) {
	eng := NewASNEngine(t.TempDir())
	data := strings.NewReader(`cidr,c1,c2,c3,c4,asn,name,c7,type
10.0.0.0/32,,,,,AS65000,Target Network Alpha,,isp
10.0.0.1/32,,,,,AS65000,Target Network Alpha,,isp
10.0.1.0/32,,,,,AS65001,Target Network,,isp
`)
	if err := eng.loadCSVReader(data, true); err != nil {
		t.Fatal(err)
	}
	eng.loadedV4 = true

	rows, err := eng.SearchSummaries("Target Network", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one row, got %d", len(rows))
	}
	if rows[0].ASN != "AS65001" {
		t.Fatalf("expected exact name match first, got %+v", rows[0])
	}
}

func TestSearchSummariesBlankKeepsSubnetSort(t *testing.T) {
	eng := NewASNEngine(t.TempDir())
	data := strings.NewReader(`cidr,c1,c2,c3,c4,asn,name,c7,type
10.0.0.0/32,,,,,AS65000,Small,,isp
10.0.1.0/32,,,,,AS65001,Large,,isp
10.0.1.1/32,,,,,AS65001,Large,,isp
`)
	if err := eng.loadCSVReader(data, true); err != nil {
		t.Fatal(err)
	}
	eng.loadedV4 = true

	rows, err := eng.SearchSummaries("*", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one row, got %d", len(rows))
	}
	if rows[0].ASN != "AS65001" {
		t.Fatalf("expected largest ASN first for blank list, got %+v", rows[0])
	}
}

func TestLoadCSVReaderKeepsFinalLineWithoutNewline(t *testing.T) {
	eng := NewASNEngine(t.TempDir())
	data := strings.NewReader("cidr,c1,c2,c3,c4,asn,name,c7,type\n2001:db8::/48,,,,,AS65002,IPv6 Test,,isp")
	if err := eng.loadCSVReader(data, false); err != nil {
		t.Fatal(err)
	}
	if len(eng.dataV6) != 1 || eng.dataV6[0].asn != "AS65002" {
		t.Fatalf("final IPv6 CSV row was dropped: %+v", eng.dataV6)
	}
}

func TestFamilyAwareSummariesAndCIDRs(t *testing.T) {
	eng := NewASNEngine(t.TempDir())
	v4 := strings.NewReader("cidr,c1,c2,c3,c4,asn,name,c7,type\n192.0.2.0/24,,,,,AS65010,Dual Stack,,isp\n")
	v6 := strings.NewReader("cidr,c1,c2,c3,c4,asn,name,c7,type\n2001:db8::/48,,,,,AS65010,Dual Stack,,isp\n2001:db8:1::/48,,,,,AS65011,V6 Only,,isp\n")
	if err := eng.loadCSVReader(v4, true); err != nil {
		t.Fatal(err)
	}
	if err := eng.loadCSVReader(v6, false); err != nil {
		t.Fatal(err)
	}
	eng.loadedV4, eng.loadedV6, eng.loaded = true, true, true

	rows, err := eng.SearchSummariesFamily("*", 0, "ipv6")
	if err != nil || len(rows) != 2 {
		t.Fatalf("IPv6 summaries = %+v, err=%v", rows, err)
	}
	cidrs, err := eng.CIDRsForASNs([]string{"AS65010"}, "both")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(cidrs, ","); got != "192.0.2.0/24,2001:db8::/48" {
		t.Fatalf("dual-family CIDRs = %q", got)
	}
}
