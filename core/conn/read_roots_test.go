package conn_test

import (
	"strings"
	"testing"

	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/conn/read"
)

// A connection whose first Test was vouched for by a public authority (pin kind tls_roots) refuses a self-signed certificate on a
// read too: the reader holds the same roots and the same rule as Test and the writer, and nothing is sent.
func TestReadRefusesASelfSignedCertificateOnAPubliclyTrustedConnection(t *testing.T) {
	t.Parallel()
	r := newTester(t)
	f := conntest.NewHTTPS(t, nil)
	r.svc.SetRootsForTest(f.Roots())
	c := r.httpTo(f, "http")
	if _, err := r.test(c.ID); err != nil {
		t.Fatal(err)
	}
	if got := r.get(c.ID); got.Pin == nil || got.Pin.Kind != "tls_roots" {
		t.Fatalf("pin %+v", got.Pin)
	}
	in := conn.Input{Name: c.Name, Kind: c.Kind, Target: c.Target, AuthType: "token", Allow: []string{f.URL + "/api/x"}, Enabled: true,
		Tools: []conn.ToolInput{{Name: "fetch_url", Enabled: true}}}
	if _, err := r.update(c.ID, in); err != nil {
		t.Fatal(err)
	}
	rd, err := read.New(read.Config{Conns: r.svc})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rd.CallRead(t.Context(), c.ID, "fetch_url", map[string]any{"path": "/api/x"}); err != nil {
		t.Fatalf("a read with the certificate that a public authority vouches for: %v", err)
	}
	f.Rotate(t) // an interceptor with a certificate that nobody vouches for
	n := len(f.Requests())
	_, err = rd.CallRead(t.Context(), c.ID, "fetch_url", map[string]any{"path": "/api/x"})
	if err == nil || !strings.Contains(err.Error(), "not trusted") && !strings.Contains(err.Error(), "not the one pinned") {
		t.Fatalf("got %v", err)
	}
	if len(f.Requests()) != n {
		t.Error("a request reached a server that no public authority vouches for")
	}
}
