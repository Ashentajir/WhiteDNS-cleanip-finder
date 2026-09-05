package tlsprobe

// ScanConfig configures a TLS hostname probe run
type ScanConfig struct {
	Targets     []string // IPs or CIDR strings
	Hostnames   []string // SNI hostname values to test
	Port        int      // default 443
	Ports       []int    // optional multi-port scan; falls back to Port
	TimeoutSec  float64  // default 5.0
	Concurrency int      // default 50
	OutputPath  string
	Verbose     bool
	PauseFunc   func() bool // optional; workers wait while it returns true
	// StrictSNI, when true, only counts a pair as a success if the edge answers
	// the presented SNI with a certificate that covers that hostname — the pair
	// is then actually usable for SNI spoofing / domain fronting. It also
	// disables the "retry without SNI" fallback, so an IP that merely serves TLS
	// under some other name is not reported as a hit.
	StrictSNI bool
}
