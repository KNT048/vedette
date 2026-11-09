package channel

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// sample is a realistic incident message used by every adapter test.
var sample = Message{
	ID:       "al-4",
	Kind:     "incident",
	Severity: "critical",
	Title:    "PC-HR-01 touched the SMB trap on FILESRV-OLD",
	Device:   "PC-HR-01 (192.168.10.107)",
	What:     "PC-HR-01 opened an SMB connection to the trap machine 3 times.",
	Action:   "Take the machine off the network, then ask its user what they were doing.",
	Link:     "https://192.168.10.2/incidents/al-4",
}

// rewrite sends every request to the fake server instead of the real host, so
// adapters with a fixed https host (Slack) can be tested without a base-URL knob.
type rewrite struct{ to *url.URL }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	c := req.Clone(req.Context())
	c.URL.Scheme, c.URL.Host = r.to.Scheme, r.to.Host
	return http.DefaultTransport.RoundTrip(c)
}

func clientTo(t *testing.T, base string) *http.Client {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: rewrite{u}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func mustNot(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			t.Errorf("%q must not contain %q", haystack, n)
		}
	}
}
