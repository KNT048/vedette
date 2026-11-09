package exposure

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/store"
)

const day = 24 * time.Hour

func certAt(host string, d time.Duration) CertRow {
	return CertRow{Host: host, Issuer: "R11", ExpiresAt: store.FormatTS(t0.Add(d))}
}

func sampleContent() Content {
	return Content{
		Hosts:       []HostRow{{"acme.example", ipA}, {"www.acme.example", ipA}, {"mail.acme.example", ipB}},
		Ports:       []PortRow{{ipA, 80, "http", "nginx"}, {ipA, 443, "https", "nginx"}, {ipB, 25, "smtp", ""}},
		AdminPanels: []AdminRow{{"https://acme.example:10443", "FortiGate (admin)", ipA, 10443, "danger"}},
		Certs:       []CertRow{certAt("acme.example", 62*day), certAt("mail.acme.example", 9*day)},
	}
}

// committedDomain is a verified domain with its commitment, ready to scan.
func (e *env) committedDomain(value string) TargetView {
	e.t.Helper()
	v := e.addVerifiedDomain(value)
	v, err := e.svc.Commit(e.ctx(), "admin@acme.example", v.ID, true)
	if err != nil {
		e.t.Fatal(err)
	}
	return v
}

func TestContract_INV1_NoScanWithoutProof(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)

	// (a) not verified
	v, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", "Acme.Example")
	if err != nil {
		t.Fatal(err)
	}
	if v.Value != "acme.example" || v.Status != "unverified" || v.Scannable || str((*string)(v.BlockedReason)) != "unverified" {
		t.Fatalf("new domain = %+v", v)
	}
	_, err = e.svc.Scan(e.ctx(), "operator@acme.example", v.ID)
	wantAPI(t, err, 409, "not_verified")
	if ok, why, err := e.svc.CheckScannable(e.ctx(), v.ID); err != nil || ok || why != BlockedUnverified {
		t.Fatalf("CheckScannable = %v %v %v", ok, why, err)
	}

	// (c) verified, but the record is looked up again before every scan, and (d) the commitment is missing
	e.dns.put("acme.example", txtRecord(v.Token))
	if r, err := e.svc.Verify(e.ctx(), "operator@acme.example", v.ID); err != nil || !r.Verified {
		t.Fatalf("verify = %+v %v", r, err)
	}
	_, err = e.svc.Scan(e.ctx(), "operator@acme.example", v.ID)
	wantAPI(t, err, 400, "commitment_required")
	if ok, why, _ := e.svc.CheckScannable(e.ctx(), "ext:"+v.ID); ok || why != BlockedNoCommitment { // the scan module's id form
		t.Fatalf("CheckScannable(ext:) = %v %v", ok, why)
	}
	if _, err := e.svc.Commit(e.ctx(), "admin@acme.example", v.ID, true); err != nil {
		t.Fatal(err)
	}
	before := e.dns.lookups()
	snap, err := e.svc.Scan(e.ctx(), "operator@acme.example", v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if e.dns.lookups() != before+1 || run.calls != 1 || snap.Counts.Subdomains != 3 {
		t.Fatalf("lookups %d->%d, runner calls %d, counts %+v", before, e.dns.lookups(), run.calls, snap.Counts)
	}

	// the record disappears: the next scan is refused, whatever was verified before
	e.dns.put("acme.example")
	_, err = e.svc.Scan(e.ctx(), "operator@acme.example", v.ID)
	wantAPI(t, err, 409, "txt_missing")
	if run.calls != 1 {
		t.Fatal("the runner ran although the TXT record was missing")
	}
	if got := e.target(v.ID); got.Scannable || str((*string)(got.BlockedReason)) != "txt_missing" || got.LastCheck.OK {
		t.Fatalf("target after the failed recheck = %+v", got)
	}
	// a lookup that fails is not a yes (fail closed)
	e.dns.put("acme.example", txtRecord(v.Token))
	e.dns.err = errors.New("dns down")
	if ok, why, _ := e.svc.CheckScannable(e.ctx(), v.ID); ok || why != BlockedTxtMissing {
		t.Fatalf("CheckScannable with DNS down = %v %v", ok, why)
	}
	e.dns.err = nil
	if ok, _, _ := e.svc.CheckScannable(e.ctx(), v.ID); !ok {
		t.Fatal("not scannable although the record is back")
	}

	// (b) an IP: not more than 30 days since the box last saw it
	ip := e.detect(ipA)[0]
	_, err = e.svc.Scan(e.ctx(), "operator@acme.example", ip.ID)
	wantAPI(t, err, 400, "commitment_required")
	if _, err := e.svc.Commit(e.ctx(), "admin@acme.example", ip.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", ip.ID); err != nil {
		t.Fatal(err)
	}
	e.advance(31 * day)
	_, err = e.svc.Scan(e.ctx(), "operator@acme.example", ip.ID)
	wantAPI(t, err, 409, "expired")
	if ok, why, _ := e.svc.CheckScannable(e.ctx(), ip.ID); ok || why != BlockedExpired {
		t.Fatalf("CheckScannable(expired IP) = %v %v", ok, why)
	}
	if _, _, err := e.svc.CheckScannable(e.ctx(), "xt-nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown target: %v", err)
	}
}

func TestContract_INV12_ScanGate(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	v := e.committedDomain("acme.example")
	// no runner yet: the gate passes and the answer is 501 (the scan module has not registered one)
	_, err := e.svc.Scan(e.ctx(), "operator@acme.example", v.ID)
	wantAPI(t, err, 501, "not_implemented")
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", v.ID); err != nil {
		t.Fatal(err)
	}
	// a failing runner is a failure of the box, and leaves no snapshot
	e.advance(day)
	run.err = errors.New("nuclei crashed")
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", v.ID); err == nil || errors.As(err, new(*APIError)) {
		t.Fatalf("runner error = %v", err)
	}
	if n := e.count(`SELECT count(*) FROM exp_snapshot`); n != 1 {
		t.Fatalf("%d snapshots", n)
	}
	// the runner is told what to scan and nothing else
	run.err = nil
	e.svc.SetRunner(nil)
	_, err = e.svc.Scan(e.ctx(), "operator@acme.example", v.ID)
	wantAPI(t, err, 501, "not_implemented")
}

func TestContract_INV2_OnlyObservedIPs(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, in := range []string{ipA, "10.0.0.1", " " + ipB + " "} {
		_, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", in)
		wantAPI(t, err, 400, "ip_not_allowed")
	}
	if n := e.count(`SELECT count(*) FROM exp_target`); n != 0 {
		t.Fatalf("%d targets after typing IPs", n)
	}
	// an IP exists only because the box saw it, and only the addresses it saw
	e.prober.set(ipC)
	r, err := e.svc.Detect(e.ctx(), "admin@acme.example", true)
	if err != nil {
		t.Fatal(err)
	}
	if got := e.ipValues(); !slices.Equal(got, []string{ipC}) || len(r.Items) != 1 || e.prober.count() != DeepRounds {
		t.Fatalf("IPs %v, probes %d, items %d", got, e.prober.count(), len(r.Items))
	}
	// verifying an IP the box does not use is a normal "no", never an addition
	ipv := r.Items[0]
	e.prober.set(ipD)
	res, err := e.svc.Verify(e.ctx(), "operator@acme.example", ipv.ID)
	if err != nil || res.Verified || !strings.Contains(res.Message, "currently reaches the Internet via "+ipD+", not "+ipC) {
		t.Fatalf("verify = %+v %v", res, err)
	}
	if got := e.ipValues(); !slices.Equal(got, []string{ipC}) {
		t.Fatalf("verify added an IP: %v", got)
	}
}

func TestContract_INV2_MultiIPDetect(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	// a load balancer: three probes over separate connections leave through two IPs
	items := e.detect(ipA, ipB, ipA)
	if len(items) != 2 || items[0].Value != ipA || items[1].Value != ipB {
		t.Fatalf("items = %+v", items)
	}
	if got := e.ipValues(); !slices.Equal(got, []string{ipA, ipB}) {
		t.Fatalf("IPs = %v", got)
	}
	b, _ := e.svc.Settings(e.ctx())
	if b.LastRun == nil || !b.LastRun.OK || b.LastRun.Message != "The box reaches the Internet via 2 public IPs: "+ipA+", "+ipB+". Each is verified until 2026-12-09." {
		t.Fatalf("last run = %+v", b.LastRun)
	}
	// a failed probe among answered ones is ignored
	e.prober.set("!", ipC, ipC)
	r, err := e.svc.Detect(e.ctx(), "admin@acme.example", true)
	if err != nil || len(r.Items) != 1 || r.Items[0].Value != ipC {
		t.Fatalf("one failed probe: %+v %v", r, err)
	}
	// no probe answered: unreachable, and nothing is lost
	e.prober.offline()
	_, err = e.svc.Detect(e.ctx(), "admin@acme.example", true)
	wantAPI(t, err, 502, "unreachable")
	if got := e.ipValues(); !slices.Equal(got, []string{ipA, ipB, ipC}) {
		t.Fatalf("IPs after an offline check = %v", got)
	}
	if b, _ := e.svc.Settings(e.ctx()); b.LastRun.OK || !strings.Contains(b.LastRun.Message, "could not reach the public IP services") {
		t.Fatalf("last run = %+v", b.LastRun)
	}
}

func TestContract_INV3_RefusesNonPublic(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for _, ip := range []string{"10.0.0.1", "192.168.1.5", "172.20.0.4", "100.64.12.5", "127.0.0.1", "169.254.1.1", "203.0.113.10", "198.51.100.7"} {
		e.prober.set(ip)
		_, err := e.svc.Detect(e.ctx(), "admin@acme.example", true)
		wantAPI(t, err, 400, "not_public")
		var ae *APIError
		errors.As(err, &ae)
		if !strings.Contains(ae.Message, "which is a private, reserved or shared carrier (CGNAT) address") || !strings.Contains(ae.Message, ip) {
			t.Fatalf("message for %s: %q", ip, ae.Message)
		}
	}
	if n := e.count(`SELECT count(*) FROM exp_target`); n != 0 {
		t.Fatalf("%d targets stored from refused addresses", n)
	}
	// several refused: plural text; refused ones next to a public one are ignored and reported
	e.prober.set("10.0.0.1", "100.64.0.9", "10.0.0.1")
	_, err := e.svc.Detect(e.ctx(), "admin@acme.example", true)
	var ae *APIError
	if !errors.As(err, &ae) || !strings.Contains(ae.Message, "10.0.0.1") || !strings.Contains(ae.Message, "100.64.0.9") || !strings.Contains(ae.Message, ", which are private, reserved or shared carrier (CGNAT) addresses") {
		t.Fatalf("plural message: %v", err)
	}
	e.prober.set("10.0.0.1", ipA, ipA)
	r, err := e.svc.Detect(e.ctx(), "admin@acme.example", true)
	if err != nil || len(r.Items) != 1 || !strings.HasSuffix(r.Message, "Ignored, not public: 10.0.0.1.") {
		t.Fatalf("mixed: %+v %v", r, err)
	}
	if got := e.ipValues(); !slices.Equal(got, []string{ipA}) {
		t.Fatalf("IPs = %v", got)
	}
	if !slices.Contains(e.auditActions(), "exposure.verify_fail") {
		t.Fatal("refused addresses were not audited")
	}
}

func TestContract_INV4_RenewAndExpire(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ip := e.detect(ipA)[0]
	if str(ip.VerifiedAt) != store.FormatTS(t0) || str(ip.ExpiresAt) != store.FormatTS(t0.Add(30*day)) || str(ip.Validity) != "valid" {
		t.Fatalf("new IP = %+v", ip)
	}
	if _, err := e.svc.Commit(e.ctx(), "admin@acme.example", ip.ID, true); err != nil {
		t.Fatal(err)
	}

	// every sighting renews: 30 days from the last one
	e.advance(20 * day)
	if got := e.target(ip.ID); str(got.Validity) != "valid" {
		t.Fatalf("day 20 = %+v", got)
	}
	e.detect(ipA)
	got := e.target(ip.ID)
	if str(got.VerifiedAt) != store.FormatTS(t0.Add(20*day)) || str(got.ExpiresAt) != store.FormatTS(t0.Add(50*day)) {
		t.Fatalf("renewed = %+v", got)
	}

	// expiring at 5 days or less; valid at 6
	e.advance(24 * day) // day 44: 6 days left
	if got := e.target(ip.ID); str(got.Validity) != "valid" {
		t.Fatalf("6 days left = %s", str(got.Validity))
	}
	e.advance(day) // day 45: 5 days left
	if got := e.target(ip.ID); str(got.Validity) != "expiring" || got.Status != "verified" || !got.Scannable {
		t.Fatalf("5 days left = %+v", got)
	}

	// not seen for 30 days: expired; the box seeing it again makes it valid again, with the old commitment
	e.advance(6 * day) // day 51
	got = e.target(ip.ID)
	if str(got.Validity) != "expired" || got.Status != "expired" || got.Scannable || str((*string)(got.BlockedReason)) != "expired" {
		t.Fatalf("expired = %+v", got)
	}
	e.pub.got = nil
	e.detect(ipA)
	got = e.target(ip.ID)
	if str(got.Validity) != "valid" || !got.Scannable || got.Commitment == nil {
		t.Fatalf("seen again = %+v", got)
	}
	if !slices.Equal(e.pub.names(), []string{EventTargetVerified}) {
		t.Fatalf("events = %v", e.pub.names())
	}

	// a domain has no expiry (its TXT record is checked before every scan)
	d := e.addVerifiedDomain("acme.example")
	if d.ExpiresAt != nil || d.Validity != nil {
		t.Fatalf("domain = %+v", d)
	}
	e.advance(400 * day)
	if got := e.target(d.ID); got.Status != "verified" {
		t.Fatalf("domain after a year = %+v", got)
	}
}

func TestContract_INV5_AttemptLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ip := e.detect(ipA)[0] // Detect itself is not an attempt
	if n := e.count(`SELECT count(*) FROM exp_attempt`); n != 0 {
		t.Fatalf("%d attempts after Detect", n)
	}
	for i := range MaxAttemptsPerHour {
		if r, err := e.svc.Verify(e.ctx(), "operator@acme.example", ip.ID); err != nil || !r.Verified {
			t.Fatalf("attempt %d: %+v %v", i+1, r, err)
		}
	}
	_, err := e.svc.Verify(e.ctx(), "operator@acme.example", ip.ID)
	wantAPI(t, err, 429, "rate_limited")
	if err := e.svc.attempt(e.ctx()); err == nil {
		t.Fatal("an attempt passed over the limit")
	}
	var ae *APIError
	errors.As(err, &ae)
	// the automatic checks do not use the people's attempts up
	for range 15 {
		if _, err := e.svc.Detect(e.ctx(), SystemUser, true); err != nil {
			t.Fatal(err)
		}
	}
	e.advance(61 * time.Minute)
	if _, err := e.svc.Verify(e.ctx(), "operator@acme.example", ip.ID); err != nil {
		t.Fatalf("after an hour: %v", err)
	}
	e.advance(25 * time.Hour)
	if err := e.svc.attempt(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM exp_attempt`); n != 1 { // everything older than 24 hours is gone
		t.Fatalf("%d attempts kept", n)
	}
	// the message says how long to wait
	e2 := newEnv(t)
	ip2 := e2.detect(ipA)[0]
	for range MaxAttemptsPerHour {
		_, _ = e2.svc.Verify(e2.ctx(), "u@acme.example", ip2.ID)
		e2.advance(time.Minute)
	}
	_, err = e2.svc.Verify(e2.ctx(), "u@acme.example", ip2.ID)
	if !errors.As(err, &ae) || ae.Message != "Too many verification attempts (limit 10 per hour). Try again in about 50 minutes." {
		t.Fatalf("message = %v", err)
	}
}

func TestContract_INV5_TargetLimitAndDuplicate(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for i := range MaxTargets {
		if _, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", "d"+string(rune('a'+i))+".example"); err != nil {
			t.Fatalf("domain %d: %v", i, err)
		}
	}
	_, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", "extra.example")
	wantAPI(t, err, 400, "too_many")
	_, err = e.svc.AddDomain(e.ctx(), "admin@acme.example", "DA.example")
	wantAPI(t, err, 409, "duplicate")
	// the list is full: the box does not add IPs and says so
	e.prober.set(ipA)
	_, err = e.svc.Detect(e.ctx(), SystemUser, true)
	wantAPI(t, err, 400, "too_many")
	if b, _ := e.svc.Settings(e.ctx()); b.LastRun.OK || !strings.Contains(b.LastRun.Message, "At most 20 targets") {
		t.Fatalf("last run = %+v", b.LastRun)
	}
	// room again: it adds the IP; with a renewal in a full list nothing is skipped
	if err := e.svc.Delete(e.ctx(), "admin@acme.example", e.firstID()); err != nil {
		t.Fatal(err)
	}
	if got := e.detect(ipA); len(got) != 1 {
		t.Fatalf("items = %+v", got)
	}
	r, err := e.svc.Detect(e.ctx(), SystemUser, true)
	if err != nil || len(r.Items) != 1 {
		t.Fatalf("renewal in a full list: %+v %v", r, err)
	}
}

func (e *env) firstID() string {
	all, err := e.svc.Targets(e.ctx())
	if err != nil || len(all) == 0 {
		e.t.Fatal(err)
	}
	return all[0].ID
}

func TestContract_INV7_Commitment(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	d, err := e.svc.AddDomain(e.ctx(), "admin@acme.example", "acme.example")
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.Commit(e.ctx(), "admin@acme.example", d.ID, true)
	wantAPI(t, err, 409, "not_verified")
	e.dns.put("acme.example", txtRecord(d.Token))
	if _, err := e.svc.Verify(e.ctx(), "operator@acme.example", d.ID); err != nil {
		t.Fatal(err)
	}
	_, err = e.svc.Commit(e.ctx(), "admin@acme.example", d.ID, false)
	wantAPI(t, err, 400, "not_confirmed")
	e.advance(time.Hour)
	c, err := e.svc.Commit(e.ctx(), "admin@acme.example", d.ID, true)
	if err != nil || c.Commitment == nil || c.Commitment.By != "admin@acme.example" || c.Commitment.At != store.FormatTS(t0.Add(time.Hour)) || !c.Scannable {
		t.Fatalf("commitment = %+v %v", c.Commitment, err)
	}
	if !slices.Contains(e.auditActions(), "exposure.commitment") {
		t.Fatal("who ticked and when was not audited")
	}
	// an expired IP cannot be committed
	ip := e.detect(ipA)[0]
	e.advance(31 * day)
	_, err = e.svc.Commit(e.ctx(), "admin@acme.example", ip.ID, true)
	wantAPI(t, err, 409, "expired")
	// deleting removes the snapshots and the commitment, not the audit log
	e.svc.SetRunner(&fakeRunner{content: sampleContent()})
	e.dns.put("acme.example", txtRecord(d.Token))
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", d.ID); err != nil {
		t.Fatal(err)
	}
	audits := len(e.audits())
	if err := e.svc.Delete(e.ctx(), "admin@acme.example", d.ID); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT count(*) FROM exp_snapshot`) != 0 || e.count(`SELECT count(*) FROM exp_target WHERE id = ?`, d.ID) != 0 {
		t.Fatal("snapshots or target left after delete")
	}
	if got := len(e.audits()); got != audits+1 {
		t.Fatalf("audit rows %d -> %d", audits, got)
	}
	wantAPI(t, e.svc.Delete(e.ctx(), "admin@acme.example", d.ID), 404, "not_found")
}

func TestContract_INV8_SnapshotsAndDiff(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	run := &fakeRunner{content: sampleContent()}
	e.svc.SetRunner(run)
	d := e.committedDomain("acme.example")
	s1, err := e.svc.Scan(e.ctx(), "operator@acme.example", d.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := Counts{Subdomains: 3, IPs: 2, Ports: 3, AdminPanels: 1, CertsExpiring: 1}
	if s1.Date != "2026-11-09" || s1.Counts != want {
		t.Fatalf("day 1 = %s %+v", s1.Date, s1.Counts)
	}
	if v := e.target(d.ID); v.Latest == nil || *v.Latest != want || str(v.LastScanAt) != store.FormatTS(t0) {
		t.Fatalf("target after the scan = %+v", v)
	}
	// a second scan the same day replaces the first
	e.advance(time.Hour)
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", d.ID); err != nil {
		t.Fatal(err)
	}
	if metas, _ := e.svc.Snapshots(e.ctx(), d.ID); len(metas) != 1 {
		t.Fatalf("%d snapshots for one day", len(metas))
	}
	// day 2: a new subdomain and port, the admin page is gone, mail's certificate was renewed
	e.advance(day)
	c2 := sampleContent()
	c2.Hosts = append(c2.Hosts, HostRow{"staging.acme.example", ipB})
	c2.Ports = append(c2.Ports, PortRow{ipB, 8080, "http", "Jenkins"})
	c2.AdminPanels = nil
	c2.Certs[1] = certAt("mail.acme.example", 100*day)
	run.content = c2
	s2, err := e.svc.Scan(e.ctx(), "operator@acme.example", d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Date != "2026-11-10" || s2.Counts.CertsExpiring != 0 {
		t.Fatalf("day 2 = %s %+v", s2.Date, s2.Counts)
	}
	metas, err := e.svc.Snapshots(e.ctx(), d.ID)
	if err != nil || len(metas) != 2 || metas[0].Date != "2026-11-10" || metas[1].Date != "2026-11-09" {
		t.Fatalf("snapshots newest first: %+v %v", metas, err)
	}
	got, err := e.svc.SnapshotOf(e.ctx(), d.ID, "2026-11-09")
	if err != nil || len(got.Hosts) != 3 || got.Counts != want {
		t.Fatalf("day 1 again = %+v %v", got, err)
	}
	// the earlier day is always the from side
	for _, order := range [][2]string{{"2026-11-09", "2026-11-10"}, {"2026-11-10", "2026-11-09"}} {
		df, err := e.svc.Diff(e.ctx(), d.ID, order[0], order[1])
		if err != nil {
			t.Fatal(err)
		}
		if df.From != "2026-11-09" || df.To != "2026-11-10" || len(df.Added) != 2 || len(df.Removed) != 1 || len(df.Changed) != 1 {
			t.Fatalf("diff = %+v", df)
		}
		if df.Added[0].Key != "h:staging.acme.example" || df.Added[1].Key != "p:"+ipB+":8080" || df.Added[1].Detail != "http, Jenkins" ||
			df.Removed[0].Kind != "admin" || df.Changed[0].Key != "c:mail.acme.example" || df.Changed[0].From == df.Changed[0].To {
			t.Fatalf("diff items = %+v", df)
		}
	}
	_, err = e.svc.Diff(e.ctx(), d.ID, "2026-11-10", "2026-11-10")
	wantAPI(t, err, 400, "same_date")
	_, err = e.svc.Diff(e.ctx(), d.ID, "2026-11-09", "2026-01-01")
	wantAPI(t, err, 404, "not_found")
	_, err = e.svc.SnapshotOf(e.ctx(), d.ID, "2026-01-01")
	wantAPI(t, err, 404, "not_found")
	_, err = e.svc.Snapshots(e.ctx(), "xt-nope")
	wantAPI(t, err, 404, "not_found")
}

func TestContract_INV8_IPTargetCountsItsOwnAddress(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.SetRunner(&fakeRunner{content: Content{Ports: []PortRow{{ipA, 443, "https", ""}}}})
	ip := e.detect(ipA)[0]
	if _, err := e.svc.Commit(e.ctx(), "admin@acme.example", ip.ID, true); err != nil {
		t.Fatal(err)
	}
	s, err := e.svc.Scan(e.ctx(), "operator@acme.example", ip.ID)
	if err != nil || s.Counts.IPs != 1 || s.Counts.Subdomains != 0 || s.Hosts == nil {
		t.Fatalf("snapshot = %+v %v", s, err)
	}
}

// INV-10: what a scan hands over came from other hosts and is limited before it is stored.
func TestContract_INV10_ScanContentIsLimited(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	big := Content{}
	for i := range maxContentRows + 50 {
		big.Hosts = append(big.Hosts, HostRow{Name: "h" + strings.Repeat("x", i%3), IP: ipA})
	}
	big.Ports = []PortRow{{ipA, 0, "bad", ""}, {ipA, 65536, "bad", ""}, {ipA, 22, "ssh\x00\xff" + strings.Repeat("é", 2*maxContentText), "OpenSSH"}}
	big.AdminPanels = []AdminRow{{"https://x/", "p", ipA, 443, "<script>"}, {"https://y/", "p", ipA, 0, "danger"}}
	big.Certs = []CertRow{{"a.example", "R11", "not a date"}, certAt("b.example", day)}
	got := sanitize(big)
	if len(got.Hosts) != maxContentRows || len(got.Ports) != 1 || len(got.AdminPanels) != 1 || len(got.Certs) != 1 {
		t.Fatalf("rows: %d hosts, %d ports, %d admin, %d certs", len(got.Hosts), len(got.Ports), len(got.AdminPanels), len(got.Certs))
	}
	svc := got.Ports[0].Service
	if strings.ContainsRune(svc, 0) || len([]rune(svc)) != maxContentText || !strings.HasPrefix(svc, "ssh") {
		t.Fatalf("service text = %d runes", len([]rune(svc)))
	}
	if got.AdminPanels[0].Risk != "warn" || got.Certs[0].ExpiresAt != store.FormatTS(t0.Add(day)) {
		t.Fatalf("admin/cert = %+v %+v", got.AdminPanels, got.Certs)
	}
	// and what is stored is the limited content
	e.svc.SetRunner(&fakeRunner{content: big})
	d := e.committedDomain("acme.example")
	s, err := e.svc.Scan(e.ctx(), "operator@acme.example", d.ID)
	if err != nil || len(s.Hosts) != maxContentRows {
		t.Fatalf("stored %d hosts, %v", len(s.Hosts), err)
	}
}

func TestContract_POST2_NotFoundIsNotAnError(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	d, _ := e.svc.AddDomain(e.ctx(), "admin@acme.example", "acme.example")
	r, err := e.svc.Verify(e.ctx(), "operator@acme.example", d.ID)
	if err != nil || r.Verified || !strings.HasPrefix(r.Message, "The TXT record vedette-verify="+d.Token+" was not found on acme.example. DNS usually updates") {
		t.Fatalf("not found = %+v %v", r, err)
	}
	if r.Target.LastCheck == nil || r.Target.LastCheck.OK || r.Target.Status != "unverified" || r.Target.VerifiedAt != nil {
		t.Fatalf("target = %+v", r.Target)
	}
	// the record has a stray space or quotes around the value from the provider's form: only the exact value counts
	e.dns.put("acme.example", "vedette-verify="+d.Token+"x", "v=spf1 -all")
	if r, _ := e.svc.Verify(e.ctx(), "operator@acme.example", d.ID); r.Verified {
		t.Fatal("a different value verified the domain")
	}
	e.dns.err = errors.New("servfail")
	r, err = e.svc.Verify(e.ctx(), "operator@acme.example", d.ID)
	if err != nil || r.Verified || !strings.Contains(r.Message, "DNS lookup for acme.example failed") {
		t.Fatalf("lookup failure = %+v %v", r, err)
	}
	e.dns.err = nil
	e.dns.put("acme.example", " "+txtRecord(d.Token)+" ")
	r, err = e.svc.Verify(e.ctx(), "operator@acme.example", d.ID)
	if err != nil || !r.Verified || r.Message != "Found the TXT record vedette-verify="+d.Token+" on acme.example." || r.Target.VerifiedAt == nil {
		t.Fatalf("found = %+v %v", r, err)
	}
	first := *r.Target.VerifiedAt
	e.advance(time.Hour)
	r, _ = e.svc.Verify(e.ctx(), "operator@acme.example", d.ID)
	if *r.Target.VerifiedAt != first { // a domain keeps its first verification time
		t.Fatalf("verified_at moved: %s -> %s", first, *r.Target.VerifiedAt)
	}
	if !slices.Equal(e.pub.names(), []string{EventTargetVerified}) {
		t.Fatalf("events = %v", e.pub.names())
	}
	// an IP with the endpoint unreachable is also a normal answer
	e.prober.set(ipA)
	ip := e.detect(ipA)[0]
	e.prober.offline()
	r, err = e.svc.Verify(e.ctx(), "operator@acme.example", ip.ID)
	if err != nil || r.Verified || !strings.Contains(r.Message, "could not reach the public IP services") {
		t.Fatalf("offline verify = %+v %v", r, err)
	}
	_, err = e.svc.Verify(e.ctx(), "operator@acme.example", "xt-nope")
	wantAPI(t, err, 404, "not_found")
}

// SYS-3: every change is in the audit log, in the same transaction.
func TestSYS3_EveryMutationIsAudited(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.SetRunner(&fakeRunner{content: sampleContent()})
	d := e.committedDomain("acme.example")
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", d.ID); err != nil {
		t.Fatal(err)
	}
	e.detect(ipA)
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", false, 30); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Delete(e.ctx(), "admin@acme.example", d.ID); err != nil {
		t.Fatal(err)
	}
	want := []string{"exposure.target_add", "exposure.verify_ok", "exposure.commitment", "exposure.verify_ok", "exposure.scan", "exposure.verify_ok", "exposure.box_ip_settings", "exposure.target_delete"}
	if got := e.auditActions(); !slices.Equal(got, want) {
		t.Fatalf("audit actions = %v\nwant %v", got, want)
	}
	for _, a := range e.audits() {
		if a.User == "" || a.Target == "" {
			t.Fatalf("empty user or target: %+v", a)
		}
	}
}

// INV-9: the public IP services are asked only by a detection (a check, "Detect now", or the box's own job when it
// is due), never by a read, and with auto-detect off nothing is asked by itself.
func TestContract_INV9_OnlyDetectionsAskTheServices(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	d := e.addVerifiedDomain("acme.example")
	if _, err := e.svc.Targets(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Target(e.ctx(), d.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Settings(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if e.prober.count() != 0 {
		t.Fatalf("%d rounds asked by reads and domain verification", e.prober.count())
	}
	if _, err := e.svc.SaveSettings(e.ctx(), "admin@acme.example", false, 1); err != nil {
		t.Fatal(err)
	}
	e.advance(24 * time.Hour)
	if err := e.svc.RunAutoDetect(e.ctx()); err != nil || e.prober.count() != 0 {
		t.Fatalf("auto-detect off: %v, %d rounds", err, e.prober.count())
	}
}
