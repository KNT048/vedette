package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/core/server"
)

// The certificate and the allowlist take only a name the host reported, checked again and never IP-shaped; the device row's name
// (used while the host has not answered) never reaches them.
func TestCertBoxNameIsOnlyAValidReportedName(t *testing.T) {
	t.Parallel()
	for give, want := range map[string]string{
		"office-box": "office-box", "Office-Box.corp.example": "office-box.corp.example", "box1": "box1",
		"10.0.0.5": "", "192.168.1.1": "", "1.2.3": "", "123": "", "box_1": fallbackBoxName, "bad name": fallbackBoxName, "": fallbackBoxName,
	} {
		b := newBoxHostNameFrom((&fakeInfo{name: give}).Info, time.Now)
		if got := certBoxName(t.Context(), b); got != want {
			t.Errorf("host name %q: %q, want %q", give, got, want)
		}
	}
	down := newBoxHostNameFrom((&fakeInfo{err: errors.New("down")}).Info, time.Now)
	down.useRow(func(context.Context) (string, error) { return "office-box", nil })
	if name, _ := down.Get(t.Context()); name != "office-box" {
		t.Fatalf("the row's name is not used while the host is down: %q", name)
	}
	if got := certBoxName(t.Context(), down); got != "" {
		t.Fatalf("the row's name reached the certificate: %q", got)
	}
	if got := certBoxName(t.Context(), nil); got != fallbackBoxName {
		t.Fatalf("nil: %q", got)
	}
}

// line 3 of fix-host-reports-hostname (r2 LOW 2): after a restart of core while the host is down, the name is the device row's, read
// until one read succeeds (a failed read is tried again); ok stays false; a name the row should not hold is not passed on; the host's
// answer wins as soon as it comes.
func TestBoxHostNameUsesTheRowUntilTheHostAnswers(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	f := &fakeInfo{err: errors.New("host restarting")}
	b := newBoxHostNameFrom(f.Info, func() time.Time { return now })
	reads := 0
	rowErr := errors.New("database busy")
	b.useRow(func(context.Context) (string, error) { reads++; return "office-box", rowErr })
	if got, ok := b.Get(t.Context()); got != fallbackBoxName || ok {
		t.Fatalf("row read failed: %q %v", got, ok)
	}
	rowErr = nil
	for range 3 {
		if got, ok := b.Get(t.Context()); got != "office-box" || ok {
			t.Fatalf("host down: %q %v", got, ok)
		}
	}
	if reads != 2 {
		t.Fatalf("the row was read %d times, want 2 (one failed, one kept)", reads)
	}
	f.err, f.name = nil, "lab-box"
	now = now.Add(boxNameRetry)
	if got, ok := b.Get(t.Context()); got != "lab-box" || !ok {
		t.Fatalf("after the host answered: %q %v", got, ok)
	}

	bad := newBoxHostNameFrom((&fakeInfo{err: errors.New("down")}).Info, time.Now)
	bad.useRow(func(context.Context) (string, error) { return "box\nINJECT", nil })
	if got, ok := bad.Get(t.Context()); got != fallbackBoxName || ok {
		t.Fatalf("an invalid row name: %q %v", got, ok)
	}
	var none *boxHostName
	none.useRow(nil) // safe on nil
}

func boxTransport(t *testing.T, dir string, ca *boxCAStore, box *boxHostName) ([]string, *selfSignedRenewer) {
	t.Helper()
	_, hosts, _, renew, err := transport(t.Context(), options{db: filepath.Join(dir, "vedette.db"), listen: "0.0.0.0:8443"}, ca, box)
	if err != nil {
		t.Fatal(err)
	}
	return hosts, renew
}

// First start with the host up: the certificate and the default allowlist hold the host's name besides "vedette", loopback and the
// addresses; the name is answered to, an IP-shaped or foreign name is not.
func TestFirstStartCertAndAllowlistCarryTheHostName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	hosts, renew := boxTransport(t, dir, testCA(t, dir), newBoxHostNameFrom((&fakeInfo{name: "Office-Box"}).Info, time.Now))
	leaf := servedLeaf(t, renew)
	for _, n := range []string{"office-box", fallbackBoxName, "localhost"} {
		if !slices.Contains(leaf.DNSNames, n) || !slices.Contains(hosts, n) {
			t.Errorf("%s: certificate %v, allowlist %v", n, leaf.DNSNames, hosts)
		}
	}
	allowed := server.HostMatcher(hosts, nil)
	if !allowed("office-box:8443") || !allowed("vedette") || allowed("evil.example") {
		t.Fatalf("allowlist %v", hosts)
	}
}

// An upgraded box: its certificate (made when the container was named "vedette") lacks the host's name. Every name of before stays
// in the allowlist and in the certificate; the name is in the allowlist at once and in the certificate after the first Check, for the
// same key; a second Check changes nothing.
func TestUpgradedBoxAddsTheHostNameAndKeepsEveryOldName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ca := testCA(t, dir)
	oldHosts, oldRenew := boxTransport(t, dir, ca, nil) // before: no name from the host
	before := servedLeaf(t, oldRenew)
	if slices.Contains(before.DNSNames, "office-box") {
		t.Fatal("the old certificate already has the name")
	}
	hosts, renew := boxTransport(t, dir, ca, newBoxHostNameFrom((&fakeInfo{name: "office-box"}).Info, time.Now))
	for _, n := range oldHosts {
		if !slices.Contains(hosts, n) {
			t.Errorf("%s left the allowlist: %v", n, hosts)
		}
	}
	if !slices.Contains(hosts, "office-box") {
		t.Fatalf("the allowlist lacks the name: %v", hosts)
	}
	if err := renew.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	after := servedLeaf(t, renew)
	if !slices.Contains(after.DNSNames, "office-box") || after.SerialNumber.Cmp(before.SerialNumber) == 0 {
		t.Fatalf("not re-issued with the name: %v", after.DNSNames)
	}
	for _, n := range before.DNSNames {
		if !slices.Contains(after.DNSNames, n) {
			t.Errorf("%s left the certificate", n)
		}
	}
	if !after.PublicKey.(*ecdsa.PublicKey).Equal(before.PublicKey) {
		t.Error("the key changed")
	}
	if onDisk := readCert(t, renew.certPath); onDisk.SerialNumber.Cmp(after.SerialNumber) != 0 {
		t.Error("the file is not the served certificate")
	}
	if err := renew.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if servedLeaf(t, renew).SerialNumber.Cmp(after.SerialNumber) != 0 {
		t.Error("an unchanged name re-issued the certificate")
	}
}

// The host does not answer at start: nothing is added (no row name, no wait beyond one call); once it answers, Check puts the name in
// the certificate. A re-issue while the host is down again keeps the names the certificate has.
func TestHostDownAtStartTheNameComesWithTheFirstAnswer(t *testing.T) {
	t.Parallel()
	now := time.Now()
	f := &fakeInfo{err: errors.New("host restarting")}
	box := newBoxHostNameFrom(f.Info, func() time.Time { return now })
	box.useRow(func(context.Context) (string, error) { return "stale-row", nil })
	dir := t.TempDir()
	hosts, renew := boxTransport(t, dir, testCA(t, dir), box)
	first := servedLeaf(t, renew)
	if slices.Contains(first.DNSNames, "stale-row") || slices.Contains(hosts, "stale-row") || !slices.Contains(hosts, fallbackBoxName) {
		t.Fatalf("certificate %v, allowlist %v", first.DNSNames, hosts)
	}
	if err := renew.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if servedLeaf(t, renew).SerialNumber.Cmp(first.SerialNumber) != 0 {
		t.Fatal("re-issued while the host had not answered")
	}
	f.err, f.name = nil, "office-box"
	now = now.Add(boxNameRetry)
	if err := renew.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	named := servedLeaf(t, renew)
	if !slices.Contains(named.DNSNames, "office-box") || !slices.Contains(named.DNSNames, fallbackBoxName) {
		t.Fatalf("after the first answer: %v", named.DNSNames)
	}

	// A fresh core (memory empty), the host down, and a certificate that must be re-issued (expiring): the name stays in it.
	down := newBoxHostNameFrom((&fakeInfo{err: errors.New("down")}).Info, time.Now)
	renew.box = func(ctx context.Context) string { return certBoxName(ctx, down) }
	renew.now = func() time.Time { return named.NotAfter.Add(-time.Hour) }
	if err := renew.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if l := servedLeaf(t, renew); l.SerialNumber.Cmp(named.SerialNumber) == 0 || !slices.Contains(l.DNSNames, "office-box") {
		t.Fatalf("re-issued while the host is down: %v", l.DNSNames)
	}
}

// With -hosts the allowlist is -hosts only, as before; the box's own certificate still names the box, as it named the container.
func TestHostsFlagAllowlistGetsNoName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	box := newBoxHostNameFrom((&fakeInfo{name: "office-box"}).Info, time.Now)
	_, hosts, _, renew, err := transport(t.Context(), options{db: filepath.Join(dir, "vedette.db"), listen: "0.0.0.0:8443", hosts: "box.acme.example"}, testCA(t, dir), box)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(hosts, []string{"box.acme.example"}) {
		t.Fatalf("-hosts allowlist %v", hosts)
	}
	if l := servedLeaf(t, renew); !slices.Contains(l.DNSNames, "office-box") || !slices.Contains(l.DNSNames, "box.acme.example") {
		t.Fatalf("certificate %v", l.DNSNames)
	}
}

// Review r1 L1 (DNS rebinding): DHCP can set the machine's name, so a name in a public domain goes into the certificate but never
// into the default allowlist, at the first start, after the first Check, or at the next start when the certificate already has it.
// A single label or a name under .local, .lan, .home.arpa or .internal is answered to.
func TestPublicDomainBoxNameIsNotAnswered(t *testing.T) {
	t.Parallel()
	for name, answered := range map[string]bool{
		"rb.attacker.example": false, "box.corp.example": false, "lan.example": false, "evil.local.example": false,
		"office-box": true, "office-box.local": true, "box.lan": true, "box.home.arpa": true, "box.corp.internal": true,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			ca := testCA(t, dir)
			box := newBoxHostNameFrom((&fakeInfo{name: name}).Info, time.Now)
			for start := range 2 {
				hosts, renew := boxTransport(t, dir, ca, box)
				if err := renew.Check(t.Context(), nil); err != nil {
					t.Fatal(err)
				}
				if !slices.Contains(servedLeaf(t, renew).DNSNames, name) {
					t.Fatalf("start %d: the certificate lacks %s", start, name)
				}
				allowed := server.HostMatcher(hosts, nil)
				if allowed(name) != answered || allowed(name+":8443") != answered || !allowed("vedette") {
					t.Fatalf("start %d: %s answered %t, want %t (allowlist %v)", start, name, allowed(name), answered, hosts)
				}
			}
		})
	}
}

// D-465 (replaces the r1 L3 test that pinned https://vedette:8443): the certificate still holds "vedette" (old bookmarks keep working),
// but links never take a name from the certificate: they carry the Box address, the management IPv4 by default, and none at all while
// the box knows no address. Before D-465 every link of an appliance read https://vedette:8443, which nothing on a LAN resolves.
func TestLinksCarryTheBoxAddressNeverTheCertificateName(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ca := testCA(t, dir)
	box := newBoxHostNameFrom((&fakeInfo{name: "office-box"}).Info, time.Now)
	hosts, renew := boxTransport(t, dir, ca, box)
	if err := renew.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if dns := servedLeaf(t, renew).DNSNames; !slices.Contains(dns, fallbackBoxName) || !slices.Contains(dns, "office-box") {
		t.Fatalf("certificate names %v, want vedette and office-box", dns)
	}
	if !server.HostMatcher(hosts, nil)("vedette:8443") {
		t.Fatalf("an old bookmark of https://vedette:8443 is refused (allowlist %v)", hosts)
	}
	mgmt := newBoxAddr(func(context.Context) (string, error) { return "192.168.18.141", nil }, flagAddress(nil))
	if got := mgmt.URL(t.Context(), "0.0.0.0:8443"); got != "https://192.168.18.141:8443" {
		t.Fatalf("default Box address: links start %q, want the management address", got)
	}
	// no Box address and no -hosts (an appliance whose host has not answered): no link at all, never one from the certificate's names
	unknown := newBoxAddr(func(context.Context) (string, error) { return "", nil }, flagAddress(nil))
	if got := unknown.URL(t.Context(), "0.0.0.0:8443"); got != "" {
		t.Fatalf("no Box address known: links start %q, want none", got)
	}
}

// D-465: the Box address is a name of the box's own certificate. A saved name or address the certificate lacks re-issues it at the next
// Check (a save kicks one); a later change re-issues it again with the new one; an unknown address ("") changes nothing.
func TestCertCoversTheBoxAddress(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	_, renew := boxTransport(t, dir, testCA(t, dir), newBoxHostNameFrom((&fakeInfo{name: "office-box"}).Info, time.Now))
	addr := ""
	renew.addr = func(context.Context) string { return addr }
	if err := renew.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	before := servedLeaf(t, renew).SerialNumber
	if err := renew.Check(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if servedLeaf(t, renew).SerialNumber.Cmp(before) != 0 {
		t.Fatal("an unknown Box address re-issued the certificate")
	}
	for _, a := range []string{"vedette.office.lan", "box2.office.lan", "10.9.9.9"} {
		addr = a
		if err := renew.Check(t.Context(), nil); err != nil {
			t.Fatal(err)
		}
		if l := servedLeaf(t, renew); l.VerifyHostname(a) != nil {
			t.Fatalf("after saving %s the certificate names %v %v", a, l.DNSNames, l.IPAddresses)
		}
	}
}

// D-465: a Box address an administrator saves is a name the box answers to (Allows), at once after Invalidate; the Box address in
// memory survives a failed read; the flag address (-hosts without a host) is used only while core gives none.
func TestBoxAddrReadsCoreAndKeepsTheLastAnswer(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	answer, fail := "vedette.office.lan", false
	b := newBoxAddr(func(context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return "", errors.New("host down")
		}
		return answer, nil
	}, "box.corp.example")
	now := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	b.now = func() time.Time { return now }
	if b.Allows("vedette.office.lan") {
		t.Fatal("Allows before any read")
	}
	if got := b.Host(t.Context()); got != "vedette.office.lan" || !b.Allows("Vedette.Office.LAN:8443") || b.Allows("evil.example") {
		t.Fatalf("Host %q, Allows wrong", got)
	}
	mu.Lock()
	fail = true
	mu.Unlock()
	now = now.Add(boxAddrTTL)
	if got := b.Host(t.Context()); got != "vedette.office.lan" {
		t.Fatalf("a failed read dropped the address: %q", got)
	}
	mu.Lock()
	fail, answer = false, ""
	mu.Unlock()
	now = now.Add(boxAddrRetry)
	if got := b.Host(t.Context()); got != "box.corp.example" || b.Allows("vedette.office.lan") {
		t.Fatalf("no Box address from core: %q, want the -hosts address and the old name no longer answered", got)
	}
	var none *boxAddr
	if none.Host(t.Context()) != "" || none.Allows("x") || none.URL(t.Context(), ":8443") != "" {
		t.Fatal("nil boxAddr")
	}
	none.Invalidate()
}

// Review r1 L4: Cached never asks the host; it gives what Get last learned.
func TestBoxHostNameCachedNeverAsksTheHost(t *testing.T) {
	t.Parallel()
	f := &fakeInfo{name: "office-box"}
	b := newBoxHostNameFrom(f.Info, time.Now)
	if got := b.Cached(t.Context()); got != fallbackBoxName || f.calls != 0 {
		t.Fatalf("before any Get: %q after %d calls", got, f.calls)
	}
	b.Get(t.Context())
	for range 3 {
		if got := b.Cached(t.Context()); got != "office-box" || f.calls != 1 {
			t.Fatalf("after Get: %q after %d calls", got, f.calls)
		}
	}
	var none *boxHostName
	if got := none.Cached(t.Context()); got != fallbackBoxName {
		t.Fatalf("nil: %q", got)
	}
}
