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
// It owns its transport: httptest.Server.Close calls CloseIdleConnections on
// http.DefaultTransport, which would break a parallel test's in-flight request.
type rewrite struct {
	to *url.URL
	rt http.RoundTripper
}

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	c := req.Clone(req.Context())
	c.URL.Scheme, c.URL.Host = r.to.Scheme, r.to.Host
	return r.rt.RoundTrip(c)
}

func clientTo(t *testing.T, base string) *http.Client {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: rewrite{u, tr}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func mustNot(t *testing.T, haystack string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			t.Errorf("%q must not contain %q", haystack, n)
		}
	}
}

// The Telegram and Zalo API addresses are not configurable (a configurable
// address would ship the token anywhere); tests point the adapter at a fake from
// inside the package.
func newTelegramAt(base string, cfg TelegramConfig) (Sender, error) {
	s, err := NewTelegram(cfg)
	if err == nil {
		s.(*telegramSender).base = strings.TrimRight(base, "/")
	}
	return s, err
}

func newZaloAt(base string, cfg ZaloConfig) (Sender, error) {
	s, err := NewZalo(cfg)
	if err == nil {
		s.(*zaloSender).endpoint = strings.TrimRight(base, "/") + zaloSendPath
	}
	return s, err
}
