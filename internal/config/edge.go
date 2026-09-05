package config

import (
	"net"
	"strings"
	"sync"
)

// EdgeProvider describes a CDN / PaaS edge network whose front IPs can be
// discovered by resolving hostnames the platform serves (its workers, pages and
// app subdomains) and then probed like any other target.
type EdgeProvider struct {
	Name string // menu label
	// Hosts are seed hostnames resolved to collect candidate edge IPs.
	Hosts []string
	// ProbeDomains are the Host/SNI values a candidate IP is probed with; a hit
	// means that IP actually serves the platform (e.g. "workers.dev").
	ProbeDomains []string
	// Signatures are lowercase substrings expected in the probe response. Empty
	// means "any HTTP answer counts".
	Signatures []string
	// CIDRs are published edge ranges scanned as-is. Providers that do not
	// publish ranges leave this empty; their targets come from DNS instead.
	CIDRs []string
}

// cloudflareEdgeCIDRs is Cloudflare's published edge range list, shared by the
// CDN and Pages entries (Pages is served from the same edge).
var cloudflareEdgeCIDRs = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

// EdgeProviders is the provider menu: Cloudflare plus the PaaS/edge platforms
// that host reachable apps behind a small set of front IPs.
var EdgeProviders = []EdgeProvider{
	{
		Name:         "Cloudflare (CDN / Workers)",
		Hosts:        CloudflareCNAMEDomains,
		ProbeDomains: []string{"workers.dev", "pages.dev", "static.cloudflareinsights.com", "speed.cloudflare.com"},
		Signatures:   []string{"cloudflare", "cf-ray"},
		CIDRs:        cloudflareEdgeCIDRs,
	},
	{
		Name:         "Cloudflare Pages (pages.dev)",
		Hosts:        []string{"pages.cloudflare.com", "developers.cloudflare.com", "blog.cloudflare.com", "dash.cloudflare.com"},
		ProbeDomains: []string{"pages.dev", "pages.cloudflare.com", "workers.dev"},
		Signatures:   []string{"cloudflare", "cf-ray"},
		CIDRs:        cloudflareEdgeCIDRs,
	},
	{
		Name:         "Render (onrender.com)",
		Hosts:        []string{"render.com", "www.render.com", "dashboard.render.com", "docs.render.com", "api.render.com", "community.render.com"},
		ProbeDomains: []string{"onrender.com", "render.com"},
		Signatures:   []string{"render"},
	},
	{
		Name:         "Fly.io (fly.dev)",
		Hosts:        []string{"fly.io", "www.fly.io", "fly.dev", "community.fly.io", "api.machines.dev"},
		ProbeDomains: []string{"fly.dev", "fly.io"},
		Signatures:   []string{"fly"},
	},
	{
		Name:         "Railway (up.railway.app)",
		Hosts:        []string{"railway.com", "railway.app", "docs.railway.com", "backboard.railway.app", "up.railway.app"},
		ProbeDomains: []string{"up.railway.app", "railway.app", "railway.com"},
		Signatures:   []string{"railway"},
	},
	{
		Name:         "Vercel (vercel.app)",
		Hosts:        []string{"vercel.com", "www.vercel.com", "vercel.app", "vercel.live", "react.dev", "nextjs.org", "sdk.vercel.ai"},
		ProbeDomains: []string{"vercel.app", "vercel.com", "react.dev", "nextjs.org"},
		Signatures:   []string{"vercel"},
	},
	{
		Name:         "Netlify (netlify.app)",
		Hosts:        []string{"netlify.com", "www.netlify.com", "netlify.app", "docs.netlify.com", "app.netlify.com", "api.netlify.com"},
		ProbeDomains: []string{"netlify.app", "netlify.com"},
		Signatures:   []string{"netlify"},
	},
	{
		Name:         "Koyeb (koyeb.app)",
		Hosts:        []string{"koyeb.com", "www.koyeb.com", "app.koyeb.com", "koyeb.app"},
		ProbeDomains: []string{"koyeb.app", "koyeb.com"},
		Signatures:   []string{"koyeb"},
	},
	{
		Name:         "Glitch (glitch.com)",
		Hosts:        []string{"glitch.com", "www.glitch.com", "blog.glitch.com", "cdn.glitch.me"},
		ProbeDomains: []string{"glitch.com", "cdn.glitch.me"},
		Signatures:   []string{"glitch"},
	},
}

// Resolve looks up the provider's seed hostnames and returns the edge IPs they
// answer with, deduped, in host order.
func (p EdgeProvider) Resolve() []string { return ResolveHosts(p.Hosts) }

// ResolveHosts resolves hostnames in parallel: a seed list runs to ~20 names and
// a single lookup can take a second, which would otherwise stall a caller (and
// the UI behind it) for half a minute. Names that fail to resolve are skipped.
func ResolveHosts(hosts []string) []string {
	perHost := make([][]net.IP, len(hosts))
	var wg sync.WaitGroup
	for i, host := range hosts {
		wg.Add(1)
		go func(i int, host string) {
			defer wg.Done()
			resolved, err := net.LookupIP(host)
			if err != nil {
				return
			}
			perHost[i] = resolved
		}(i, host)
	}
	wg.Wait()

	seen := make(map[string]struct{})
	var ips []string
	for _, resolved := range perHost {
		for _, ip := range resolved {
			addr := ip.String()
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			ips = append(ips, addr)
		}
	}
	return ips
}

// GetEdgeProvider returns the provider with the given Name, or nil.
func GetEdgeProvider(name string) *EdgeProvider {
	for i := range EdgeProviders {
		if EdgeProviders[i].Name == name {
			return &EdgeProviders[i]
		}
	}
	return nil
}

// Targets turns resolved edge IPs into a scan target list: the provider's
// published ranges, plus the /24 around every resolved IPv4 (neighbouring edge
// IPs live there) and the resolved IPv6 addresses as-is. Order is preserved and
// duplicates dropped.
// ponytail: /24 widening only; walk the owning ASN prefix if that proves too narrow.
func (p EdgeProvider) Targets(resolved []string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(t string) {
		if _, ok := seen[t]; ok {
			return
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	for _, c := range p.CIDRs {
		add(c)
	}
	for _, raw := range resolved {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil {
			add(net.IPv4(v4[0], v4[1], v4[2], 0).String() + "/24")
			continue
		}
		add(ip.String())
	}
	return out
}
