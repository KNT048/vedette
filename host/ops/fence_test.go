package ops

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/knt048/vedette/core/domainfence"
	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/server"
)

// The host makes the fence key once and keeps it, gives a domain's box-bound token, checks the fence for OpenVAS
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

// noteRec records the host's audit notes (the bootstrap's AuditTo seam); fail makes every note fail.
type noteRec struct {
	codes []string
	fail  bool
}

func (n *noteRec) Note(_, code string, detail map[string]any) error {
	if n.fail {
		return errors.New("disk full")
	}
	n.codes = append(n.codes, code+" "+detail["domain"].(string)) //nolint:forcetypeassert // the fence's own detail
	return nil
}

// Review r1 H1: the host issues a token only for a domain on its own list: a new domain is added (state file 0600, audited), the same
// domain again gets the same token without a second line, the cap refuses the next new one, and an audit that cannot be written adds
// nothing.
func TestExposureTokenIsListedCappedAndAudited(t *testing.T) {
	t.Parallel()
	w := newZapWorld(t, Deps{})
	rec := &noteRec{}
	w.o.noteOnly = rec
	if _, err := w.o.exposureToken(api.ExposureTokenArgs{Domain: "Acme.example;reboot"}); err == nil {
		t.Fatal("a bad domain was accepted")
	}
	for _, suffix := range []string{"co.uk", "ddns.net", "github.io"} { // Never a public suffix
		got, err := w.o.exposureToken(api.ExposureTokenArgs{Domain: suffix})
		if l, _ := w.o.loadFenceList(); err == nil || got != nil || l[suffix] {
			t.Fatalf("%s: %+v %v, listed %v", suffix, got, err, l[suffix])
		}
	}
	got, err := w.o.exposureToken(api.ExposureTokenArgs{Domain: "example.com"})
	if res, ok := got.(api.ExposureTokenResult); err != nil || !ok || res.Token != zapTestTok || len(rec.codes) != 0 {
		t.Fatalf("a listed domain: %+v %v, notes %q", got, err, rec.codes)
	}
	for i := range fenceMaxDomains - 1 {
		d := "d" + strings.Repeat("x", i) + ".example"
		got, err := w.o.exposureToken(api.ExposureTokenArgs{Domain: d})
		if res, ok := got.(api.ExposureTokenResult); err != nil || !ok || res.Token != domainfence.Token(zapTestKey, d) {
			t.Fatalf("%s: %+v %v", d, got, err)
		}
	}
	again, _ := w.o.exposureToken(api.ExposureTokenArgs{Domain: "dx.example"})
	if again.(api.ExposureTokenResult).Token != domainfence.Token(zapTestKey, "dx.example") || len(rec.codes) != fenceMaxDomains-1 { //nolint:forcetypeassert // checked by the loop
		t.Fatalf("a domain asked again: %+v, notes %d", again, len(rec.codes))
	}
	if rec.codes[0] != auditDomainAdded+" d.example" {
		t.Fatalf("notes %q", rec.codes)
	}
	if _, err := w.o.exposureToken(api.ExposureTokenArgs{Domain: "one-too-many.example"}); fenceCode(err) != api.CodeFenceDomainsFull {
		t.Fatalf("over the cap: %v", err)
	}
	fi, err := os.Lstat(filepath.Join(w.state, fenceListName))
	l, _ := w.o.loadFenceList()
	if err != nil || fi.Mode().Perm() != 0o600 || len(l) != fenceMaxDomains || l["one-too-many.example"] {
		t.Fatalf("list file %v %v, %d domains", fi, err, len(l))
	}
	w2 := newZapWorld(t, Deps{})
	w2.o.noteOnly = &noteRec{fail: true}
	if _, err := w2.o.exposureToken(api.ExposureTokenArgs{Domain: "new.example"}); err == nil || w2.o.fenceListed("new.example") {
		t.Fatalf("an unaudited domain was added: %v", err)
	}
}

// Review r1 H1: a domain the host never issued a token for is refused by the fence even when its DNS carries this box's token.
func TestFenceRefusesADomainOffTheList(t *testing.T) {
	t.Parallel()
	tok := domainfence.Token(zapTestKey, "attacker.example")
	w := newZapWorld(t, Deps{ZapTXT: func(context.Context, string) ([]string, error) { return []string{"vedette-verify=" + tok}, nil }})
	_, err := w.o.fenceCheck(t.Context(), nolog, api.ExposureFenceCheckArgs{Domain: "attacker.example", Name: "www.attacker.example", IP: zapTestIP, Token: tok})
	if fenceCode(err) != api.CodeTokenForeign {
		t.Fatalf("%v", err)
	}
}

// Review r1 M2: the re-check of a running task asks DNS again: the TXT record removed after a yes is seen at once, while the check
// before the task may answer from the 5-minute cache.
func TestFenceRecheckNeverUsesTheCache(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	txt := []string{"vedette-verify=" + zapTestTok}
	w := newZapWorld(t, Deps{ZapTXT: func(context.Context, string) ([]string, error) { mu.Lock(); defer mu.Unlock(); return txt, nil }})
	a := api.ExposureFenceCheckArgs{Domain: "example.com", Name: "www.example.com", IP: zapTestIP, Token: zapTestTok}
	if _, err := w.o.fenceCheck(t.Context(), nolog, a); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	txt = nil
	mu.Unlock()
	if _, err := w.o.fenceCheck(t.Context(), nolog, a); err != nil {
		t.Fatalf("the start check within 5 minutes: %v (the cache answers it)", err)
	}
	a.Recheck = true
	if _, err := w.o.fenceCheck(t.Context(), nolog, a); fenceCode(err) != api.CodeTargetNotOwned {
		t.Fatalf("the re-check: %v", err)
	}
}

// zap.baseline of a domain verified by an older release (its own random token, not the box-bound one) runs exactly as before:
// the TXT record carries that token and the name points at the address; without the record it is refused as before.
func TestZapBaselineKeepsAnOldDomainsToken(t *testing.T) {
	t.Parallel()
	const old = "00112233aabbccdd"
	var mu sync.Mutex
	txt := []string{"vedette-verify=" + old}
	w := newZapWorld(t, Deps{ZapTXT: func(context.Context, string) ([]string, error) { mu.Lock(); defer mu.Unlock(); return txt, nil }})
	p := zapDomainPage(t)
	p.token = old
	var log []string
	if _, err := w.o.zapBaseline(t.Context(), func(l string) { log = append(log, l) }, p); err != nil {
		t.Fatalf("an old domain's passive scan: %v", err)
	}
	if !strings.HasPrefix(log[0], "legacy_token: ") {
		t.Fatalf("run log %q", log)
	}
	mu.Lock()
	txt = nil
	mu.Unlock()
	w2 := newZapWorld(t, Deps{ZapTXT: func(context.Context, string) ([]string, error) { return nil, nil }})
	if _, err := w2.o.zapBaseline(t.Context(), nolog, p); fenceCode(err) != api.CodeTargetNotOwned {
		t.Fatalf("an old domain without its record: %v", err)
	}
}

// The older-token path of zap.baseline asks the one ownership rule (domainfence.Owned): the record on
// _vedette-verify.<domain> proves the domain, and a record reached through a CNAME on that name does not.
func TestZapBaselineOldTokenUsesTheOwnershipRule(t *testing.T) {
	t.Parallel()
	const old = "00112233aabbccdd"
	txt := func(_ context.Context, name string) ([]string, error) {
		if strings.TrimSuffix(name, ".") == "_vedette-verify.example.com" {
			return []string{"vedette-verify=" + old}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	p := zapDomainPage(t)
	p.token = old
	w := newZapWorld(t, Deps{ZapTXT: txt})
	if _, err := w.o.zapBaseline(t.Context(), nolog, p); err != nil {
		t.Fatalf("the record on _vedette-verify.example.com: %v", err)
	}
	cname := func(_ context.Context, name string) (string, error) {
		if strings.TrimSuffix(name, ".") == "_vedette-verify.example.com" {
			return "lb.lapsed-vendor.example.", nil
		}
		return name, nil
	}
	w2 := newZapWorld(t, Deps{ZapTXT: txt, FenceCNAME: cname})
	if _, err := w2.o.zapBaseline(t.Context(), nolog, p); fenceCode(err) != api.CodeTargetNotOwned {
		t.Fatalf("through a CNAME: %v", err)
	}
}

func TestExposureFenceCheck(t *testing.T) {
	t.Parallel()
	other := domainfence.Token([]byte(strings.Repeat("o", domainfence.KeySize)), "example.com")
	args := func(tok string, disruptive bool) api.ExposureFenceCheckArgs {
		return api.ExposureFenceCheckArgs{Domain: "example.com", Name: "www.example.com", IP: zapTestIP, Token: tok, Disruptive: disruptive}
	}
	outside := func(_ context.Context, name string) (string, error) { // the page's name only: the domain itself is no CNAME
		if name == "www.example.com" {
			return "example.cdn.example.net.", nil
		}
		return name + ".", nil
	}
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
	// The record's parent name (ProofAt) is checked like the domain, and never a public suffix, whatever core sends
	if j, err := fenceJob(api.ExposureFenceCheckArgs{Domain: "git.example.com", Name: "git.example.com", IP: zapTestIP, Token: zapTestTok, ProofAt: "example.com"}); err != nil || j.ProofAt != "example.com" {
		t.Fatalf("a parent name: %+v %v", j, err)
	}
	if _, err := fenceJob(api.ExposureFenceCheckArgs{Domain: "x.example.ddns.net", Name: "x.example.ddns.net", IP: zapTestIP, Token: zapTestTok, ProofAt: "ddns.net"}); err == nil {
		t.Fatal("a public suffix as the record's name was accepted")
	}
	if _, err := fenceJob(api.ExposureFenceCheckArgs{Domain: "example.com", Name: "www.evil.example", IP: zapTestIP, Token: zapTestTok}); err == nil {
		t.Fatal("a name outside the domain was accepted")
	}
	// A name under the proof name is covered by the record of a domain beside it; never one outside it, above it, or across a suffix
	if j, err := fenceJob(api.ExposureFenceCheckArgs{Domain: "git.example.com", Name: "www.example.com", IP: zapTestIP, Token: zapTestTok, ProofAt: "example.com"}); err != nil || j.Name != "www.example.com" {
		t.Fatalf("a name under the proof name: %+v %v", j, err)
	}
	for _, bad := range []struct{ domain, name, at string }{
		{"git.example.com", "www.example.org", "example.com"},
		{"git.example.com", "notexample.com", "example.com"},
		{"a.b.example.com", "example.com", "b.example.com"},
		{"x.example.ddns.net", "y.ddns.net", "example.ddns.net"},
	} {
		if _, err := fenceJob(api.ExposureFenceCheckArgs{Domain: bad.domain, Name: bad.name, IP: zapTestIP, Token: zapTestTok, ProofAt: bad.at}); err == nil {
			t.Fatalf("name %s with proof name %s for %s accepted", bad.name, bad.at, bad.domain)
		}
	}
	if _, err := fenceJob(api.ExposureFenceCheckArgs{Domain: "example.com", Name: "www.example.com", IP: "10.0.0.1", Token: zapTestTok}); err == nil {
		t.Fatal("a private address was accepted")
	}
}

// Core never reads the fence key (review r1 L2): every unit the host can write (each service's current template and every earlier one,
// rendered with real ids) is read Volume= line by Volume= line: only the scan unit mounts fenceScanDir, read-only, and no unit mounts
// the host's state directory, fenceScanDir or a directory above either. ZAP's container mounts only its own work folder.
func TestCoreNeverMountsTheFenceKey(t *testing.T) {
	t.Parallel()
	const stateDir = "/var/lib/vedette-host"
	above := func(src, p string) bool { return src == p || strings.HasPrefix(p, strings.TrimSuffix(src, "/")+"/") }
	check := func(svc, name string, text []byte) {
		for _, l := range strings.Split(string(text), "\n") {
			v, ok := strings.CutPrefix(l, "Volume=")
			if !ok {
				continue
			}
			src := strings.Split(v, ":")[0]
			if src == fenceScanDir && svc == api.ServiceScan && v == fenceScanDir+":"+fenceScanDir+":ro" {
				continue
			}
			if above(src, stateDir) || above(src, fenceScanDir) {
				t.Errorf("%s unit %s mounts %q, which holds the fence key", svc, name, v)
			}
		}
	}
	n := 0
	for svc, u := range services {
		text, err := u.render(u.tmpl, goldFill(true))
		if err != nil {
			t.Fatal(err)
		}
		check(svc, "current", text)
		if svc == api.ServiceScan && !strings.Contains(string(text), "\nVolume="+fenceScanDir+":"+fenceScanDir+":ro\n") {
			t.Error("the scan unit does not mount the key's copy read-only")
		}
		for i, tmpl := range legacyTemplates[svc] {
			old, err := u.render(tmpl, goldFill(true))
			if err != nil {
				t.Fatal(err)
			}
			check(svc, "legacy "+strconv.Itoa(i+1), old)
			n++
		}
	}
	if n == 0 {
		t.Fatal("no earlier template was checked")
	}
	wrk := filepath.Join(stateDir, "zap", "wrk")
	for _, a := range zapRunArgv("https://www.example.com/", "", wrk) {
		if strings.HasPrefix(a, "/") && (above(strings.Split(a, ":")[0], stateDir) || strings.Contains(a, fenceScanDir) || strings.Contains(a, fenceKeyName)) {
			t.Errorf("ZAP's container mounts %q", a)
		}
	}
}

// Review r1 L3: the scan container's copies: the directory 0500, the key and the list 0400, owned by the sensor user, the key equal to
// the host's own; a second start leaves the copies alone (same files).
func TestFenceScanCopy(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := Config{StateDir: state, CoreUnit: "vedette-core.service", OwnerUID: os.Getuid(), SensorUID: os.Getuid(), SensorGID: os.Getgid(), Logger: slog.New(slog.DiscardHandler)}
	o1, err := NewWithDeps(cfg, Deps{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	o1.Close()
	dir := filepath.Join(root, fenceScanDir)
	key := filepath.Join(dir, fenceKeyName)
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // a directory: the 0500 one, so the test's TempDir can be removed
	stat := func(p string) os.FileInfo {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		return fi
	}
	master, _ := os.ReadFile(filepath.Join(state, fenceKeyName)) //nolint:gosec // a test path
	copyKey, _ := os.ReadFile(key)                               //nolint:gosec // a test path
	if stat(dir).Mode().Perm() != 0o500 || stat(key).Mode().Perm() != 0o400 || stat(filepath.Join(dir, fenceScanList)).Mode().Perm() != 0o400 ||
		string(copyKey) != string(master) || len(master) != domainfence.KeySize {
		t.Fatalf("dir %v key %v", stat(dir).Mode(), stat(key).Mode())
	}
	before := stat(key)
	o2, err := NewWithDeps(cfg, Deps{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	o2.Close()
	if !os.SameFile(before, stat(key)) || stat(dir).Mode().Perm() != 0o500 {
		t.Fatal("a second start rewrote the scan container's copy")
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

// Review r2 M-A: exposure.token_forget takes a domain off the list (audited), is idempotent, and frees a slot under the cap.
func TestExposureTokenForget(t *testing.T) {
	t.Parallel()
	w := newZapWorld(t, Deps{})
	rec := &noteRec{}
	w.o.noteOnly = rec
	for i := range fenceMaxDomains - 1 { // example.com is listed already: the list is full after these
		if _, err := w.o.exposureToken(api.ExposureTokenArgs{Domain: "d" + strconv.Itoa(i) + ".example"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.o.exposureToken(api.ExposureTokenArgs{Domain: "new.example"}); fenceCode(err) != api.CodeFenceDomainsFull {
		t.Fatalf("full: %v", err)
	}
	got, err := w.o.exposureTokenForget(api.ExposureTokenArgs{Domain: "d0.example"})
	if err != nil || !got.(api.ExposureTokenForgetResult).Removed || w.o.fenceListed("d0.example") || rec.codes[len(rec.codes)-1] != auditDomainRemoved+" d0.example" { //nolint:forcetypeassert // the op's own result
		t.Fatalf("forget: %+v %v, notes %q", got, err, rec.codes)
	}
	n := len(rec.codes)
	got, err = w.o.exposureTokenForget(api.ExposureTokenArgs{Domain: "d0.example"})
	if err != nil || got.(api.ExposureTokenForgetResult).Removed || len(rec.codes) != n { //nolint:forcetypeassert // the op's own result
		t.Fatalf("forget again: %+v %v", got, err)
	}
	if l, _ := w.o.loadFenceList(); l["d0.example"] || len(l) != fenceMaxDomains-1 {
		t.Fatalf("state list %v", l)
	}
	if _, err := w.o.exposureToken(api.ExposureTokenArgs{Domain: "new.example"}); err != nil {
		t.Fatalf("the freed slot: %v", err)
	}
	if _, err := w.o.exposureTokenForget(api.ExposureTokenArgs{Domain: "Bad..example"}); err == nil {
		t.Fatal("a bad domain was accepted")
	}
}

// Review r2 L-3 and L-7: a fence op writes the worker's copy again even when nothing changed (a damaged copy is put right); a key that
// cannot be used leaves the scan container's directory in place (0500, no key copy), so the scan unit still starts without domain_ip.
func TestFenceScanCopyIsRewrittenAndSurvivesABadKey(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, fenceScanDir)
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) //nolint:gosec // a directory: the 0500 one, so the test's TempDir can be removed
	cfg := Config{StateDir: state, CoreUnit: "vedette-core.service", OwnerUID: os.Getuid(), SensorUID: os.Getuid(), SensorGID: os.Getgid(), Logger: slog.New(slog.DiscardHandler)}
	o, err := NewWithDeps(cfg, Deps{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(dir, 0o700)                                //nolint:gosec // as root would: the host writes through the 0500 directory
	if _, err := o.issueToken("acme.example"); err != nil { // new: listed and copied
		t.Fatal(err)
	}
	list := filepath.Join(dir, fenceScanList)
	_ = os.Remove(list)
	if err := os.WriteFile(list, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := o.issueToken("acme.example"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(list) //nolint:gosec // a test path
	if fi, err := os.Lstat(list); err != nil || string(b) != "acme.example\n" || fi.Mode().Perm() != 0o400 {
		t.Fatalf("copy %q %v %v", b, fi, err)
	}
	o.Close()

	root2 := t.TempDir()
	state2 := filepath.Join(root2, "state")
	if err := os.Mkdir(state2, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state2, fenceKeyName), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir2 := filepath.Join(root2, fenceScanDir)
	t.Cleanup(func() { _ = os.Chmod(dir2, 0o700) }) //nolint:gosec // as above
	cfg.StateDir = state2
	o2, err := NewWithDeps(cfg, Deps{Root: root2})
	if err != nil {
		t.Fatal(err)
	}
	defer o2.Close()
	fi, err := os.Lstat(dir2)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o500 || o2.fence != nil {
		t.Fatalf("dir %v %v, fence %v", fi, err, o2.fence)
	}
	if _, err := os.Lstat(filepath.Join(dir2, fenceKeyName)); err == nil {
		t.Fatal("a key copy was written from an unusable key")
	}
}

// A page of git.example.com whose own record sits on example.com goes through the domain fence
// with ProofAt (git's box-bound token, git on the host's list), never through the older-token path; a ProofAt with a token that is
// not git's bound one is refused, and so is one outside git's registered domain.
func TestZapBaselineProofAtGoesThroughTheFence(t *testing.T) {
	t.Parallel()
	git := domainfence.Token(zapTestKey, "git.example.com")
	txt := func(_ context.Context, name string) ([]string, error) {
		if strings.TrimSuffix(name, ".") == "example.com" { // the zone apex holds git's own record
			return []string{"v=spf1 -all", "vedette-verify=" + git}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	args := api.ZapBaselineArgs{URL: "https://git.example.com/", Host: "git.example.com", IP: zapTestIP, Port: 443, Kind: api.ZapKindDomain, Domain: "git.example.com", TXTToken: git, ProofAt: "example.com"}
	p, err := zapArgs(args)
	if err != nil {
		t.Fatal(err)
	}
	w := newZapWorld(t, Deps{ZapTXT: txt})
	w.o.fenceMu.Lock()
	w.o.fenceList["git.example.com"] = true // the host issued git's token
	w.o.fenceMu.Unlock()
	var log []string
	if _, err := w.o.zapBaseline(t.Context(), func(l string) { log = append(log, l) }, p); err != nil {
		t.Fatalf("git's own record on the apex: %v (log %q)", err, log)
	}
	for _, l := range log {
		if strings.HasPrefix(l, "legacy_token") {
			t.Fatalf("went the older-token path: %q", log)
		}
	}
	old := p
	old.token = "00112233aabbccdd" // an older token: no parent-name proof outside the fence
	if _, err := w.o.zapBaseline(t.Context(), nolog, old); fenceCode(err) != api.CodeTokenForeign {
		t.Fatalf("an older token with ProofAt: %v", err)
	}
	// a page of a name beside the donor, covered by the donor's token on the shared name: accepted by the host's own re-check; a host outside it is not
	sib := args
	sib.URL, sib.Host = "https://www.example.com/", "www.example.com"
	ps, err := zapArgs(sib)
	if err != nil {
		t.Fatalf("a page under the proof name: %v", err)
	}
	if _, err := w.o.zapBaseline(t.Context(), nolog, ps); err != nil {
		t.Fatalf("the page of a name under the proof name: %v", err)
	}
	for _, host := range []string{"www.example.org", "notexample.com", "example.com.evil.net"} {
		out := sib
		out.URL, out.Host = "https://"+host+"/", host
		if _, err := zapArgs(out); err == nil {
			t.Fatalf("the page of %s accepted with proof_at example.com", host)
		}
	}
	for _, bad := range []struct{ domain, host, at string }{
		{"bucket.s3.amazonaws.com", "bucket.s3.amazonaws.com", "amazonaws.com"},
		{"x.example.ddns.net", "x.example.ddns.net", "ddns.net"},
		{"victim.github.io", "victim.github.io", "github.io"},
		{"a.b.co.uk", "a.b.co.uk", "co.uk"},
		{"git.example.com", "git.example.com", "git.example.com"},
	} {
		a := args
		a.URL, a.Host, a.Domain, a.ProofAt = "https://"+bad.host+"/", bad.host, bad.domain, bad.at
		if _, err := zapArgs(a); err == nil {
			t.Fatalf("zap proof_at %s for %s accepted", bad.at, bad.domain)
		}
		if _, err := fenceJob(api.ExposureFenceCheckArgs{Domain: bad.domain, Name: bad.host, IP: zapTestIP, Token: zapTestTok, ProofAt: bad.at}); err == nil {
			t.Fatalf("fence_check proof_at %s for %s accepted", bad.at, bad.domain)
		}
	}
}
