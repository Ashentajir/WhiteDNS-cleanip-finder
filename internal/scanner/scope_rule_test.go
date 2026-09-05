package scanner

import "testing"

func TestScopeAcceptsOnCertificate(t *testing.T) {
	required := []string{"netlify.app", "netlify.com"}

	if !scopeAcceptsOnCertificate(true, "netlify.app", required) {
		t.Error("an edge holding a certificate for the wildcard app suffix must settle a scoped scan")
	}
	if !scopeAcceptsOnCertificate(true, "NETLIFY.APP", required) {
		t.Error("the name comparison must not be case sensitive")
	}
	if scopeAcceptsOnCertificate(false, "netlify.app", required) {
		t.Error("no certificate match, nothing to credit")
	}
	if scopeAcceptsOnCertificate(true, "chatgpt.com", required) {
		t.Error("a certificate for some other name says nothing about this platform")
	}
	// An unscoped IP scan keeps its own accept rules; this must not become a
	// blanket "any TLS host with a valid certificate passes".
	if scopeAcceptsOnCertificate(true, "netlify.app", nil) {
		t.Error("rule leaked into an unscoped scan")
	}
}
