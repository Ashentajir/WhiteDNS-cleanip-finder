package dnsscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	truthFetchTimeout = 4 * time.Second
	truthCacheTTL     = 30 * time.Minute
)

type truthCacheEntry struct {
	table     *TruthTable
	expiresAt time.Time
}

var truthCache = struct {
	sync.Mutex
	entries map[string]truthCacheEntry
}{entries: make(map[string]truthCacheEntry)}

// trustedDoHProvider defines a DoH endpoint for fetching the truth table.
type trustedDoHProvider struct {
	Name string
	URL  string // %s is replaced with the domain
}

// trustedProviders is the ordered fallback list of DoH providers used to build
// the truth table. Google Public DNS is the default reference (widely reachable
// and geo-accurate); Cloudflare and Quad9 are fallbacks.
var trustedProviders = []trustedDoHProvider{
	{Name: "Google", URL: "https://dns.google/dns-query?name=%s&type=A"},
	{Name: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query?name=%s&type=A"},
	{Name: "Quad9", URL: "https://dns.quad9.net/dns-query?name=%s&type=A"},
}

// Reference provider identifiers selectable by the operator.
const (
	ReferenceGoogle     = "google"
	ReferenceCloudflare = "cloudflare"
	ReferenceQuad9      = "quad9"
)

// orderedProviders returns the provider list with the preferred reference tried
// first; the rest stay as fallbacks so a blocked primary still yields a truth
// table.
func orderedProviders(prefer string) []trustedDoHProvider {
	prefer = strings.ToLower(strings.TrimSpace(prefer))
	if prefer == "" {
		return trustedProviders
	}
	out := make([]trustedDoHProvider, 0, len(trustedProviders))
	for _, p := range trustedProviders {
		if strings.EqualFold(p.Name, prefer) {
			out = append(out, p)
		}
	}
	for _, p := range trustedProviders {
		if !strings.EqualFold(p.Name, prefer) {
			out = append(out, p)
		}
	}
	return out
}

// TruthTable holds the verified "correct" IPs for a target domain. If a resolver
// returns IPs not in this set, it is flagged as poisoned.
type TruthTable struct {
	Domain   string
	TruthIPs map[string]bool
	Provider string
	Prefer   string // preferred reference provider (ReferenceGoogle / ReferenceCloudflare)
	mu       sync.RWMutex
}

// NewTruthTable creates an empty truth table for a domain, defaulting to Google
// Public DNS as the reference resolver.
func NewTruthTable(domain string) *TruthTable {
	return &TruthTable{Domain: domain, TruthIPs: make(map[string]bool), Prefer: ReferenceGoogle}
}

// FetchTruth populates the table from trusted DoH providers, falling back to
// hardcoded well-known IPs for a few domains when every provider is blocked.
func (t *TruthTable) FetchTruth() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), truthFetchTimeout)
	defer cancel()
	client := &http.Client{
		Timeout: truthFetchTimeout,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
		},
	}

	type providerResult struct {
		name string
		ips  []string
	}
	providers := orderedProviders(t.Prefer)
	results := make(chan providerResult, len(providers))
	for _, provider := range providers {
		provider := provider
		go func() {
			result := providerResult{name: provider.Name}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf(provider.URL, t.Domain), nil)
			if err == nil {
				req.Header.Set("Accept", "application/dns-json")
				if resp, requestErr := client.Do(req); requestErr == nil {
					body, readErr := io.ReadAll(io.LimitReader(resp.Body, 8192))
					resp.Body.Close()
					var dohResp dohJSONResponse
					if readErr == nil && resp.StatusCode == http.StatusOK && json.Unmarshal(body, &dohResp) == nil && dohResp.Status == 0 {
						for _, ans := range dohResp.Answer {
							if ans.Type == 1 && net.ParseIP(strings.TrimSpace(ans.Data)) != nil {
								result.ips = append(result.ips, strings.TrimSpace(ans.Data))
							}
						}
					}
				}
			}
			results <- result
		}()
	}

	answers := make(map[string][]string, len(providers))
	for range providers {
		select {
		case result := <-results:
			if len(result.ips) > 0 {
				answers[result.name] = result.ips
				// The first ordered provider is the user's preferred source. As
				// soon as it succeeds there is no reason to wait for blocked
				// fallback endpoints to exhaust their deadlines.
				if result.name == providers[0].Name {
					for _, ip := range result.ips {
						t.TruthIPs[ip] = true
					}
					t.Provider = result.name
					return nil
				}
			}
		case <-ctx.Done():
			goto chooseProvider
		}
	}

chooseProvider:
	for _, provider := range providers {
		if ips := answers[provider.Name]; len(ips) > 0 {
			for _, ip := range ips {
				t.TruthIPs[ip] = true
			}
			t.Provider = provider.Name
			return nil
		}
	}

	fallbacks := map[string][]string{
		"google.com":    {"142.250.80.46", "142.250.80.78", "142.250.80.110"},
		"speedtest.net": {"151.139.72.2"},
		"facebook.com":  {"157.240.1.35", "157.240.3.35"},
	}
	if ips, ok := fallbacks[t.Domain]; ok {
		for _, ip := range ips {
			t.TruthIPs[ip] = true
		}
		t.Provider = "Hardcoded Fallback"
		return nil
	}
	return fmt.Errorf("truth table: all DoH providers failed and no fallback for %q", t.Domain)
}

// cachedTruthTable avoids repeating external truth-source lookups for every
// mobile scan chunk or nearby-IP pass. Truth tables are immutable after fetch.
func cachedTruthTable(domain, prefer string) *TruthTable {
	key := strings.ToLower(strings.TrimSpace(domain)) + "\x00" + strings.ToLower(strings.TrimSpace(prefer))
	now := time.Now()
	truthCache.Lock()
	entry, ok := truthCache.entries[key]
	truthCache.Unlock()
	if ok && now.Before(entry.expiresAt) {
		return entry.table
	}

	table := NewTruthTable(domain)
	table.Prefer = prefer
	_ = table.FetchTruth() // best-effort; Verify treats missing truth as clean
	truthCache.Lock()
	truthCache.entries[key] = truthCacheEntry{table: table, expiresAt: now.Add(truthCacheTTL)}
	truthCache.Unlock()
	return table
}

// knownGoodV4Prefixes lists the /16 (first-two-octet) blocks a domain is known
// to legitimately answer from. Heavily GeoDNS/anycast domains (google.com most
// of all) return hundreds of rotating IPs across many netblocks, so an exact
// match against the handful of truth IPs a single DoH lookup returns would
// falsely flag most honest resolvers as poisoned. These prefixes are always
// accepted for the domain regardless of what the truth fetch returned.
var knownGoodV4Prefixes = map[string][]string{
	"google.com": {
		"142.250", "142.251", "172.217", "172.253", "216.58",
		"74.125", "108.177", "209.85", "173.194", "64.233", "216.239",
	},
	"facebook.com": {"157.240", "31.13", "179.60", "185.60", "129.134"},
}

// knownFilterIPs are documented DNS block-page / sinkhole targets a censoring
// resolver injects instead of the real answer. The 10.10.34.x set is Iran's
// national filternet redirect (also caught by the bogon rule, listed here for
// clarity); 185.55.225.25 / 185.55.226.26 are its public block-page servers,
// which are NOT bogons and would otherwise slip through. Any of these in an
// answer is an unambiguous poisoning signal.
var knownFilterIPs = map[string]bool{
	"10.10.34.34":   true,
	"10.10.34.35":   true,
	"10.10.34.36":   true,
	"10.10.34.1":    true,
	"185.55.225.25": true,
	"185.55.226.26": true,
}

// Verify reports whether an A-record answer set looks honest (clean). It is
// deliberately lenient about legitimate IP rotation but strict about the two
// unambiguous poisoning signatures used by DNS censors: sinkhole/bogon answers
// (private, loopback, unspecified, reserved) and answers that land in none of
// the domain's known-good netblocks.
//
// Clean when:
//   - no truth data AND no known-good prefixes to compare against, OR
//   - any answer matches a truth IP exactly, shares a /16 with a truth IP, or
//     falls inside a known-good prefix for the domain.
//
// Poisoned when a bogon/private IP is returned, or when we have a reference set
// and no answer matches it at all.
func (t *TruthTable) Verify(ips []string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// A private/reserved answer for a public domain is the classic sinkhole
	// poisoning signature, as is any documented block-page IP — always dirty,
	// whatever the truth table holds.
	for _, ip := range ips {
		if isBogonIP(ip) || knownFilterIPs[strings.TrimSpace(ip)] {
			return false
		}
	}

	prefixes := knownGoodV4Prefixes[t.Domain]
	if len(t.TruthIPs) == 0 && len(prefixes) == 0 {
		return true // nothing trustworthy to compare against => treat as clean
	}

	for _, ip := range ips {
		if t.TruthIPs[ip] {
			return true
		}
		for truth := range t.TruthIPs {
			if sameSlash16(ip, truth) {
				return true
			}
		}
		if p := v4Prefix16(ip); p != "" {
			for _, good := range prefixes {
				if p == good {
					return true
				}
			}
		}
	}
	return false
}

// isBogonIP reports whether an IP is private, loopback, link-local,
// unspecified, or otherwise reserved — none of which a public domain should
// legitimately resolve to, so seeing one is a poisoning/sinkhole signal.
func isBogonIP(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return true
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	// 240.0.0.0/4 (reserved for future use) and 0.0.0.0/8.
	if v4 := ip.To4(); v4 != nil && (v4[0] >= 240 || v4[0] == 0) {
		return true
	}
	return false
}

// v4Prefix16 returns the "a.b" first-two-octet /16 label of an IPv4 address, or
// "" for non-IPv4 input.
func v4Prefix16(s string) string {
	v4 := net.ParseIP(strings.TrimSpace(s)).To4()
	if v4 == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d", v4[0], v4[1])
}

// sameSlash16 reports whether two IPv4 addresses share a /16 prefix.
func sameSlash16(a, b string) bool {
	pa, pb := v4Prefix16(a), v4Prefix16(b)
	return pa != "" && pa == pb
}
