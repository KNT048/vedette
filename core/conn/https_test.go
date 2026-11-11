package conn_test

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/secrets"
)

// The facade of D-305: the same transport as the connections, with the trust decision and the address policy of this package.

func TestHTTPSFacade_TOFUThenPin(t *testing.T) {
	r := newRig(t)
	srv := conntest.NewHTTPS(t, nil)

	if _, err := r.svc.NewHTTPS(conn.HTTPSOptions{}).Do(t.Context(), conn.HTTPSRequest{URL: srv.URL + "/"}); !errors.Is(err, conn.ErrUnverified) {
		t.Fatalf("self-signed without TOFU or pin: %v, want ErrUnverified", err)
	}
	if n := len(srv.Requests()); n != 0 {
		t.Fatalf("an unverified server got %d requests", n)
	}

	c := r.svc.NewHTTPS(conn.HTTPSOptions{TOFU: true})
	resp, err := c.Do(t.Context(), conn.HTTPSRequest{URL: srv.URL + "/"})
	if err != nil || resp.Status != 200 {
		t.Fatalf("TOFU: %v %v", resp, err)
	}
	pin, trusted := c.Seen()
	if pin != srv.SPKISHA256() || trusted {
		t.Fatalf("Seen = %q %v, want the server's key and not trusted", pin, trusted)
	}

	if _, err := r.svc.NewHTTPS(conn.HTTPSOptions{Pin: pin}).Do(t.Context(), conn.HTTPSRequest{URL: srv.URL + "/"}); err != nil {
		t.Fatalf("with the pin: %v", err)
	}
	srv.Rotate(t)
	before := len(srv.Requests())
	_, err = r.svc.NewHTTPS(conn.HTTPSOptions{Pin: pin}).Do(t.Context(), conn.HTTPSRequest{URL: srv.URL + "/", BasicUser: "vedette", Secret: secrets.NewValue("s3cret-password")})
	if !errors.Is(err, conn.ErrPinMismatch) {
		t.Fatalf("a new key under the pin: %v, want ErrPinMismatch", err)
	}
	if len(srv.Requests()) != before {
		t.Fatal("the request (and its password) reached a server whose key is not the pinned one")
	}
}

func TestHTTPSFacade_PublicRoots(t *testing.T) {
	r := newRig(t)
	srv := conntest.NewHTTPS(t, nil)
	c := r.svc.NewHTTPS(conn.HTTPSOptions{Roots: srv.Roots()})
	if _, err := c.Do(t.Context(), conn.HTTPSRequest{URL: srv.URL + "/"}); err != nil {
		t.Fatalf("a server the roots vouch for: %v", err)
	}
	if _, trusted := c.Seen(); !trusted {
		t.Fatal("Seen says not trusted for a server the roots vouch for")
	}
}

func TestHTTPSFacade_SignInAndHeaders(t *testing.T) {
	r := newRig(t)
	srv := conntest.NewHTTPS(t, nil)
	c := r.svc.NewHTTPS(conn.HTTPSOptions{TOFU: true})
	if _, err := c.Do(t.Context(), conn.HTTPSRequest{Method: http.MethodPost, URL: srv.URL + "/login", BasicUser: "vedette", Secret: secrets.NewValue("pw-1234")}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(t.Context(), conn.HTTPSRequest{URL: srv.URL + "/x", Bearer: true, Secret: secrets.NewValue("jwt-abcd")}); err != nil {
		t.Fatal(err)
	}
	reqs := srv.Requests()
	if u, p, ok := (&http.Request{Header: reqs[0].Header}).BasicAuth(); !ok || u != "vedette" || p != "pw-1234" || reqs[0].Method != http.MethodPost {
		t.Fatalf("basic sign-in: %s %v", reqs[0].Method, reqs[0].Header)
	}
	if got := reqs[1].Header.Get("Authorization"); got != "Bearer jwt-abcd" {
		t.Fatalf("bearer = %q", got)
	}
	if _, err := c.Do(t.Context(), conn.HTTPSRequest{URL: srv.URL + "/", BasicUser: "a", Bearer: true}); err == nil {
		t.Fatal("two ways of signing in at once were accepted")
	}
	var de *conn.DeviceError
	if _, err := c.Do(t.Context(), conn.HTTPSRequest{URL: srv.URL + "/", Header: http.Header{"Authorization": {"x"}}}); !errors.As(err, &de) {
		t.Fatalf("a caller-set Authorization header: %v, want a DeviceError", err)
	}
}

func TestHTTPSFacade_AddressPolicy(t *testing.T) {
	r := newRig(t)
	c := r.svc.NewHTTPS(conn.HTTPSOptions{TOFU: true})
	for _, u := range []string{"https://127.0.0.1:55000/", "https://169.254.169.254/", "https://" + boxAddr + ":55000/", "https://10.88.1.2/"} {
		var re *conn.RefusedError
		if _, err := c.Do(t.Context(), conn.HTTPSRequest{URL: u}); !errors.As(err, &re) {
			t.Errorf("%s: %v, want a RefusedError", u, err)
		}
	}
	for target, want := range map[string]string{
		"https://192.168.10.7:55000":    "",
		"https://wazuh.lan:55000":       "",
		"http://192.168.10.7:55000":     "https://",
		"https://u:p@192.168.10.7":      "user name",
		"https://localhost:55000":       "loopback",
		"https://192.168.10.7:55000/?a": "?",
		"https://" + boxAddr:            "the box itself",
	} {
		got := r.svc.HTTPSTargetProblem(t.Context(), target)
		if (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("HTTPSTargetProblem(%q) = %q, want it to contain %q", target, got, want)
		}
	}
}
