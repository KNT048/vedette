package ops

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// D-591 (FULL-5 slice 2): the host makes the fence key once and keeps it, gives a domain's box-bound token, checks the fence for OpenVAS
// and for zap.baseline, and the key's copy reaches the scan container only. No test asks real DNS.

func TestFenceKeyIsMadeOnceAndKept(t *testing.T) {
	t.Parallel()
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{StateDir: state, CoreUnit: "vedette-core.service", OwnerUID: os.Getuid(), Logger: slog.New(slog.DiscardHandler)}
	o1, err := NewWithDeps(cfg, Deps{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	o1.Close()
	fi, err := os.Lstat(filepath.Join(state, fenceKeyName))
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() != domainfence.KeySize {
		t.Fatalf("fence.key: %v %v", fi, err)
	}
	o2, err := NewWithDeps(cfg, Deps{Root: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer o2.Close()
	if o1.fence == nil || o2.fence == nil || o1.fence.Token("acme.example") != o2.fence.Token("acme.example") {
		t.Fatal("a second start made another key: every domain's token would change")
	}
}

func TestExposureTokenGivesTheBoxBoundToken(t *testing.T) {
	t.Parallel()
	w := newZapWorld(t, Deps{})
	if _, err := w.o.exposureToken(api.ExposureTokenArgs{Domain: "Acme.example;reboot"}); err == nil {
		t.Fatal("a bad domain was accepted")
	}
	got, err := w.o.exposureToken(api.ExposureTokenArgs{Domain: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if res, ok := got.(api.ExposureTokenResult); !ok || res.Token != zapTestTok {
		t.Fatalf("token %+v, want %s", got, zapTestTok)
	}
}

func TestExposureFenceCheck(t *testing.T) {
	t.Parallel()
	other := domainfence.Token([]byte(strings.Repeat("o", domainfence.KeySize)), "example.com")
	args := func(tok string, disruptive bool) api.ExposureFenceCheckArgs {
		return api.ExposureFenceCheckArgs{Domain: "example.com", Name: "www.example.com", IP: zapTestIP, Token: tok, Disruptive: disruptive}
	}
	outside := func(context.Context, string) (string, error) { return "example.cdn.example.net.", nil }
	gone := func(context.Context, string) ([]string, error) { return nil, nil }
	moved := func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	down := func(context.Context, string) ([]string, error) { return nil, errors.New("timeout") }
	for name, c := range map[string]struct {
		d    Deps
		a    api.ExposureFenceCheckArgs
		want string
	}{
		"yes":                       {Deps{}, args(zapTestTok, false), ""},
		"another box's token":       {Deps{}, args(other, false), api.CodeTokenForeign},
		"TXT gone":                  {Deps{ZapTXT: gone}, args(zapTestTok, false), api.CodeTargetNotOwned},
		"name moved":                {Deps{ZapLookupIP: moved}, args(zapTestTok, false), api.CodeNameMoved},
		"DNS down":                  {Deps{ZapTXT: down}, args(zapTestTok, false), api.CodeOwnershipUnchecked},
		"disruptive, CNAME outside": {Deps{FenceCNAME: outside}, args(zapTestTok, true), api.CodeCNAMEOutside},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			w := newZapWorld(t, c.d)
			_, err := w.o.fenceCheck(t.Context(), nolog, c.a)
			if code := fenceCode(err); code != c.want {
				t.Fatalf("%v, want %q", err, c.want)
			}
		})
	}
	if _, err := fenceJob(api.ExposureFenceCheckArgs{Domain: "example.com", Name: "www.evil.example", IP: zapTestIP, Token: zapTestTok}); err == nil {
		t.Fatal("a name outside the domain was accepted")
	}
	if _, err := fenceJob(api.ExposureFenceCheckArgs{Domain: "example.com", Name: "www.example.com", IP: "10.0.0.1", Token: zapTestTok}); err == nil {
		t.Fatal("a private address was accepted")
	}
}

// zap.baseline of a domain's page checks the box-bound token: a page whose domain carries another box's (public) token is refused.
func TestZapBaselineRefusesAForeignToken(t *testing.T) {
	t.Parallel()
	other := domainfence.Token([]byte(strings.Repeat("o", domainfence.KeySize)), "example.com")
	w := newZapWorld(t, Deps{ZapTXT: func(context.Context, string) ([]string, error) { return []string{"vedette-verify=" + other}, nil }})
	p := zapDomainPage(t)
	p.token = other
	_, err := w.o.zapBaseline(t.Context(), nolog, p)
	if code := fenceCode(err); code != api.CodeTokenForeign {
		t.Fatalf("%v", err)
	}
	if calls := w.Calls(); len(calls) != 1 {
		t.Fatalf("calls after the refusal: %q", calls)
	}
}

// Core never reads the fence key: core's unit mounts neither the scan container's copy nor the host's state directory, and the scan
// unit mounts the copy read-only.
func TestCoreNeverMountsTheFenceKey(t *testing.T) {
	t.Parallel()
	for _, text := range []string{coreUnitText, sensorUnitText, honeypotUnitText} {
		if strings.Contains(text, fenceScanDir) || strings.Contains(text, "/var/lib/vedette-host") {
			t.Fatalf("a unit other than scan mounts the fence key:\n%s", text)
		}
	}
	if !strings.Contains(scanUnitText, "\nVolume="+fenceScanDir+":"+fenceScanDir+":ro\n") {
		t.Fatal("the scan unit does not mount the key's copy read-only")
	}
}

func fenceCode(err error) string {
	var ref *server.Refusal
	var f *server.Failure
	switch {
	case err == nil:
		return ""
	case errors.As(err, &ref):
		return ref.Code
	case errors.As(err, &f):
		return f.Code
	}
	return "?" + err.Error()
}
