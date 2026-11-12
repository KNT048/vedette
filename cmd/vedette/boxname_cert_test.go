package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"path/filepath"
	"slices"
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
	down.useRow(func(context.Context) string { return "office-box" })
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
// once; ok stays false; a name the row should not hold is not passed on; the host's answer wins as soon as it comes.
func TestBoxHostNameUsesTheRowUntilTheHostAnswers(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	f := &fakeInfo{err: errors.New("host restarting")}
	b := newBoxHostNameFrom(f.Info, func() time.Time { return now })
	reads := 0
	row := "office-box"
	b.useRow(func(context.Context) string { reads++; return row })
	for range 3 {
		if got, ok := b.Get(t.Context()); got != "office-box" || ok {
			t.Fatalf("host down: %q %v", got, ok)
		}
	}
	if reads != 1 {
		t.Fatalf("the row was read %d times", reads)
	}
	f.err, f.name = nil, "lab-box"
	now = now.Add(boxNameRetry)
	if got, ok := b.Get(t.Context()); got != "lab-box" || !ok {
		t.Fatalf("after the host answered: %q %v", got, ok)
	}

	bad := newBoxHostNameFrom((&fakeInfo{err: errors.New("down")}).Info, time.Now)
	bad.useRow(func(context.Context) string { return "box\nINJECT" })
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
	box.useRow(func(context.Context) string { return "stale-row" })
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
