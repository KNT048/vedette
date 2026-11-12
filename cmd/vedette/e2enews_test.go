package main

// The fake internet of the CVE news spec in web/e2e-real (S-AI-3, D-426): NVD, the GitHub search, one vendor page and the six blogs answered by
// an HTTPS server on loopback of this test binary. The fetcher of the box (modules/ai/news_fetch.go) keeps every check (host list, port 443, a
// public resolved address, sizes); only the name lookup and the final connect are replaced, so a run sends nothing out. Only TestE2EBox sets
// testNewsNetwork, so CI and the release binary use the real network.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io/fs"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/knt048/vedette/core/audit"
	"github.com/knt048/vedette/core/secrets"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/ai"
	"github.com/knt048/vedette/modules/ai/provider"
	"github.com/knt048/vedette/modules/core"
)

const (
	e2eNewsCVE    = "CVE-2026-0001"
	e2eNewsVendor = "https://fortiguard.fortinet.com/psirt/FG-E2E-0001"
)

// e2eNewsHosts are the hosts of the fake internet: the fetcher contacts only these (and the other blogs of its list, which answer empty feeds).
var e2eNewsHosts = []string{"services.nvd.nist.gov", "api.github.com", "fortiguard.fortinet.com", "labs.watchtowr.com", "www.greynoise.io",
	"isc.sans.edu", "www.rapid7.com", "unit42.paloaltonetworks.com", "projectzero.google"}

const e2eNewsNVD = `{"resultsPerPage":1,"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-0001","published":"2026-11-10T00:00:00.000","lastModified":"2026-11-11T00:00:00.000","vulnStatus":"Analyzed",
"descriptions":[{"lang":"en","value":"A fixture vulnerability of the end-to-end run."}],
"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
"references":[{"url":"` + e2eNewsVendor + `","tags":["Vendor Advisory"]}]}}]}`

const e2eNewsVendorPage = `<html><head><title>FG-E2E-0001</title></head><body><h1>Advisory for CVE-2026-0001</h1><p>Upgrade E2E Product to 2.0 or later.</p></body></html>`

const e2eNewsGitHub = `{"total_count":1,"incomplete_results":false,"items":[{"full_name":"e2e/CVE-2026-0001-poc","html_url":"https://github.com/e2e/CVE-2026-0001-poc","description":"PoC for CVE-2026-0001","stargazers_count":1,"fork":false,"created_at":"2026-11-10T00:00:00Z","pushed_at":"2026-11-11T00:00:00Z"}]}`

const e2eNewsPost = `<item><title>Exploiting CVE-2026-0001 in the wild</title><link>https://labs.watchtowr.com/e2e/</link><description>We saw exploitation of CVE-2026-0001.</description></item>`

// e2eNewsPages maps host+path to the body the fake internet answers.
var e2eNewsPages = map[string]string{
	"services.nvd.nist.gov/rest/json/cves/2.0":  e2eNewsNVD,
	"fortiguard.fortinet.com/psirt/FG-E2E-0001": e2eNewsVendorPage,
	"api.github.com/search/repositories":        e2eNewsGitHub,
	"labs.watchtowr.com/rss/":                   sprintRSS(e2eNewsPost),
	"www.greynoise.io/blog/rss.xml":             sprintRSS(""),
	"isc.sans.edu/rssfeed.xml":                  sprintRSS(""),
	"www.rapid7.com/rss.xml":                    sprintRSS(""),
	"unit42.paloaltonetworks.com/feed/":         sprintRSS(""),
	"projectzero.google/feed.xml":               sprintRSS(""),
}

func sprintRSS(items string) string {
	return `<?xml version="1.0"?><rss version="2.0"><channel><title>t</title>` + items + `</channel></rss>`
}

// startE2ENews starts the fake internet and wires it to the news fetcher of every box of this process. It returns the pages it serves
// (host/path, for ready.json). Call it once, before any box starts.
func startE2ENews(t *testing.T) []string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vedette-e2e fake internet"}, DNSNames: e2eNewsHosts,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := e2eNewsPages[r.Host+r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	resolve := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	} // a public address the fetcher accepts
	connect := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}
	testNewsNetwork = func(s *ai.Service) { s.SetNewsNetwork(resolve, connect, pool) }
	pages := make([]string, 0, len(e2eNewsPages))
	for k := range e2eNewsPages {
		pages = append(pages, k)
	}
	sort.Strings(pages)
	return pages
}

type e2eNewsFacts struct{}

func (e2eNewsFacts) CVE(_ context.Context, id string) (ai.CVEFacts, bool, error) {
	return ai.CVEFacts{CVE: id, Vendor: "E2E Vendor", Product: "E2E Product", Name: "E2E fixture vulnerability"}, id == e2eNewsCVE, nil
}

func (e2eNewsFacts) AffectedAssets(context.Context, string) ([]ai.AssetFact, error) { return nil, nil }

type e2eNewsModel struct{}

func (e2eNewsModel) Complete(context.Context, provider.Request) (provider.Response, error) {
	return provider.Response{Text: `{"exploited":"Yes.","public_exploit":"Appears to exist.","workaround":"Upgrade.","other":[]}`, Stop: provider.StopEnd}, nil
}

// TestE2ENewsFakeInternet runs in CI: through the seam the fetcher reads every fake page (NVD, the vendor page, GitHub, the blogs) and
// never leaves the machine, so the spec that depends on it does not fail on its first run.
func TestE2ENewsFakeInternet(t *testing.T) {
	ctx := context.Background()
	pages := startE2ENews(t)
	db := storetest.New(t)
	for name, m := range map[string]fs.FS{"core": core.Migrations, "ai": ai.Migrations} {
		if err := store.Migrate(ctx, db, name, m); err != nil {
			t.Fatal(err)
		}
	}
	sec, err := secrets.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := ai.New(ctx, ai.Config{DB: db, Secrets: sec, Audit: audit.New(time.Now), Log: slog.New(slog.DiscardHandler), Facts: e2eNewsFacts{},
		Factory: func(ai.Profile) (provider.Provider, error) { return e2eNewsModel{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	testNewsNetwork(svc)
	t.Cleanup(func() { testNewsNetwork = nil })
	p, err := svc.AddProfile(ctx, "test", ai.ProfileInput{Name: "Fake", Kind: "anthropic", APIStyle: provider.StyleAnthropic, BaseURL: "https://api.anthropic.com", //nolint:gosec // a fake key for a fake model
		Model: "claude-haiku-5-5", APIKey: "e2e-fake-key-0123456789abcd",
		Location: ai.LocationCloud, DailyCap: 60000})
	if err != nil {
		t.Fatal(err)
	}
	asg := svc.Assignments()
	asg.Jobs[string(ai.JobCVENews)] = ai.SlotView{Primary: &p.ID}
	if _, err := svc.SetAssignments(ctx, "test", asg); err != nil {
		t.Fatal(err)
	}
	res, err := svc.NewsCVE(ctx, "test", e2eNewsCVE)
	if err != nil {
		t.Fatal(err)
	}
	ok := 0
	for _, s := range res.Sources {
		if s.Status == "ok" {
			ok++
		}
	}
	if len(pages) != 9 || ok != len(res.Sources) || len(res.Sources) != 9 {
		t.Fatalf("pages %d, sources %+v: every source should be read from the fake internet", len(pages), res.Sources)
	}
}
