package exposure

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// addNode adds value with scope as a person does (no proof yet).
func (e *env) addNode(value string, scope ScopeMode) TargetView {
	e.t.Helper()
	v, err := e.svc.AddNode(e.ctx(), "admin@acme.example", NewNode{Value: value, Scope: scope})
	if err != nil {
		e.t.Fatalf("add %s: %v", value, err)
	}
	return v
}

// parents is each target's parent by value ("" at the top), as stored.
func (e *env) parents() map[string]string {
	e.t.Helper()
	rows, err := e.db.Reader().QueryContext(e.ctx(), `SELECT t.value, coalesce(p.value, '') FROM exp_target t LEFT JOIN exp_target p ON p.id = t.parent_id`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var v, p string
		if err := rows.Scan(&v, &p); err != nil {
			e.t.Fatal(err)
		}
		out[v] = p
	}
	return out
}

func (e *env) treeCounts() (pairs, twice int64) {
	e.t.Helper()
	var err error
	if pairs, err = unplacedPairs(e.ctx(), e.db.Reader()); err != nil {
		e.t.Fatal(err)
	}
	if twice, err = doubleScanned(e.ctx(), e.db.Reader()); err != nil {
		e.t.Fatal(err)
	}
	return pairs, twice
}

// A domain goes under the nearest domain target it is a name of, whichever was added first; a target removed hands its children to its
// own parent. Names that only end alike, other registered domains, names across a public suffix and IPs are never related.
func TestTree_PlacementAndReparenting(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.addNode("x.git.acme.example", "")
	e.addNode("git.acme.example", "") // above an existing one: takes it under it
	e.addNode("www.acme.example", "")
	e.addNode("notacme.example", "") // ends like acme.example, is not under it
	e.addNode("acme.example", "")    // the apex last: the subdomains move under it
	e.addNode("sub.other.example", "")
	e.addNode("foo.ddns.net", "")
	e.addNode("a.foo.ddns.net", "")
	e.addNode("bar.ddns.net", "") // ddns.net is a public suffix: no proof covers across it, so no parent either
	if _, err := e.svc.AddTarget(e.ctx(), "admin@acme.example", KindIP, ipA); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"acme.example": "", "git.acme.example": "acme.example", "x.git.acme.example": "git.acme.example", "www.acme.example": "acme.example",
		"notacme.example": "", "sub.other.example": "", "foo.ddns.net": "", "a.foo.ddns.net": "foo.ddns.net", "bar.ddns.net": "", ipA: "",
	}
	if got := e.parents(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("tree\n got %v\nwant %v", got, want)
	}
	if p, n := e.treeCounts(); p != 0 || n != 0 {
		t.Fatalf("counts %d %d", p, n)
	}
	// The middle one removed: its child moves up to its parent, keeping its own options
	git, _, err := loadTargetByValue(e.ctx(), e.db.Reader(), "git.acme.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Delete(e.ctx(), "admin@acme.example", git.ID); err != nil {
		t.Fatal(err)
	}
	if got := e.parents(); got["x.git.acme.example"] != "acme.example" {
		t.Fatalf("after removing the middle: %v", got)
	}
	// The apex removed: the rest go to the top
	apex, _, err := loadTargetByValue(e.ctx(), e.db.Reader(), "acme.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Delete(e.ctx(), "admin@acme.example", apex.ID); err != nil {
		t.Fatal(err)
	}
	if got := e.parents(); got["x.git.acme.example"] != "" || got["www.acme.example"] != "" {
		t.Fatalf("after removing the apex: %v", got)
	}
	// A tree stored wrong is counted: a subdomain unrelated to its parent
	e.addNode("acme.example", "")
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(e.ctx(), `UPDATE exp_target SET parent_id = NULL WHERE value = 'www.acme.example'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if p, _ := e.treeCounts(); p != 1 {
		t.Fatalf("a subdomain stored apart from its parent counts %d, want 1", p)
	}
}

// The owner of a name is the deepest enabled target that contains it and whose scope takes it; a target switched off scans nothing and
// gives its names back to its parent.
func TestTree_OwnerOfAName(t *testing.T) {
	t.Parallel()
	apex := scopeNode{id: "apex", value: "acme.example", mode: ScopeAll, enabled: true}
	git := scopeNode{id: "git", value: "git.acme.example", mode: ScopeAll, enabled: true}
	for _, c := range []struct {
		what  string
		nodes []scopeNode
		name  string
		want  string
	}{
		{"the apex's own name", []scopeNode{apex, git}, "acme.example", "apex"},
		{"a name under the apex", []scopeNode{apex, git}, "www.acme.example", "apex"},
		{"the child's own name", []scopeNode{apex, git}, "git.acme.example", "git"},
		{"a name under the child", []scopeNode{apex, git}, "x.git.acme.example", "git"},
		{"a name under a child that scans only itself: the parent's", []scopeNode{apex, {id: "git", value: "git.acme.example", mode: ScopeSelf, enabled: true}}, "x.git.acme.example", "apex"},
		{"its own name whatever the scope", []scopeNode{apex, {id: "git", value: "git.acme.example", mode: ScopeSelf, enabled: true}}, "git.acme.example", "git"},
		{"a chosen name", []scopeNode{{id: "apex", value: "acme.example", mode: ScopeSelected, enabled: true, chosen: map[string]bool{"www.acme.example": true}}}, "www.acme.example", "apex"},
		{"a name not chosen: nobody's", []scopeNode{{id: "apex", value: "acme.example", mode: ScopeSelected, enabled: true, chosen: map[string]bool{"www.acme.example": true}}}, "mail.acme.example", ""},
		{"scope self: nobody's", []scopeNode{{id: "apex", value: "acme.example", mode: ScopeSelf, enabled: true}}, "www.acme.example", ""},
		{"a child switched off: the parent's", []scopeNode{apex, {id: "git", value: "git.acme.example", mode: ScopeAll}}, "git.acme.example", "apex"},
		{"a name that only ends alike", []scopeNode{apex}, "notacme.example", ""},
		{"across a public suffix", []scopeNode{{id: "foo", value: "foo.ddns.net", mode: ScopeAll, enabled: true}}, "bar.ddns.net", ""},
	} {
		if got := ownerOf(c.name, c.nodes); got != c.want {
			t.Errorf("%s: owner of %s = %q, want %q", c.what, c.name, got, c.want)
		}
	}
	var nilPlan *NamePlan // an IP target, or a ScanTarget built by hand: every name it is handed
	if !nilPlan.Scans("anything.example") {
		t.Error("a nil plan refuses a name")
	}
}

// proveTree adds acme.example with its record on the apex, verified and committed, and git.acme.example, covered by that record with no
// record of its own (the box checks it by itself when it is added) and committed.
func (e *env) proveTree() (apex, git TargetView) {
	e.t.Helper()
	apex = e.addNode("acme.example", "")
	e.dns.put("acme.example", txtRecord(apex.Token))
	if r, err := e.svc.Verify(e.ctx(), "operator@acme.example", apex.ID); err != nil || !r.Verified {
		e.t.Fatalf("verify the apex: %+v %v", r, err)
	}
	git = e.addNode("git.acme.example", "")
	if git.Status != statusVerified || git.LastCheck == nil || !git.LastCheck.OK {
		e.t.Fatalf("a subdomain added under a proven apex is not covered: %+v", git)
	}
	for _, id := range []string{apex.ID, git.ID} {
		if _, err := e.commit(id); err != nil {
			e.t.Fatal(err)
		}
	}
	return apex, git
}

// The scan of a parent is handed the names it owns: not its child's name nor the names under the child, unless the child is switched off
// or scans only itself; a scope of self or of chosen names keeps the rest out. Each change applies from the next scan.
func TestTree_TheParentsScanSkipsItsChildsNames(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	run := &fakeRunner{content: Content{Hosts: []HostRow{{Name: "acme.example", IP: ipA, IPs: []HostIP{{IP: ipA, Family: "ipv4", Class: ClassPublic}}}}, Ports: []PortRow{}}}
	e.svc.SetRunner(run)
	apex, git := e.proveTree()
	scan := func(id string) ScanTarget {
		t.Helper()
		e.advance(ScanEvery)
		if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
			t.Fatal(err)
		}
		return run.last
	}
	scans := func(st ScanTarget, names ...string) string {
		var out []string
		for _, n := range names {
			if st.Names.Scans(n) {
				out = append(out, n)
			}
		}
		return strings.Join(out, " ")
	}
	names := []string{"acme.example", "www.acme.example", "git.acme.example", "x.git.acme.example"}
	if got := scans(scan(apex.ID), names...); got != "acme.example www.acme.example" {
		t.Fatalf("the apex scans %q", got)
	}
	if got := scans(scan(git.ID), names...); got != "git.acme.example x.git.acme.example" {
		t.Fatalf("the child scans %q", got)
	}
	edit := func(id string, ed NodeEdit) {
		t.Helper()
		if _, err := e.svc.EditNode(e.ctx(), "admin@acme.example", id, ed); err != nil {
			t.Fatal(err)
		}
	}
	self, all, selected, off, on := ScopeSelf, ScopeAll, ScopeSelected, false, true
	edit(git.ID, NodeEdit{Scope: &self})
	if got := scans(scan(apex.ID), names...); got != "acme.example www.acme.example x.git.acme.example" {
		t.Fatalf("with the child scanning only itself the apex scans %q", got)
	}
	edit(git.ID, NodeEdit{Scope: &all, Enabled: &off})
	if got := scans(scan(apex.ID), names...); got != strings.Join(names, " ") {
		t.Fatalf("with the child switched off the apex scans %q", got)
	}
	e.advance(ScanEvery)
	_, err := e.svc.Scan(e.ctx(), "admin@acme.example", git.ID)
	wantAPI(t, err, 409, "disabled")
	edit(git.ID, NodeEdit{Enabled: &on})
	edit(apex.ID, NodeEdit{Scope: &self})
	if got := scans(scan(apex.ID), names...); got != "acme.example" {
		t.Fatalf("scope self: the apex scans %q", got)
	}
	// Chosen names: listed by a scan first, then chosen by id
	run.content.Listed = []HostRow{{Name: "www.acme.example", Source: "ct"}, {Name: "mail.acme.example", Source: "mx"}}
	scan(apex.ID)
	hosts, err := e.svc.Hosts(e.ctx(), apex.ID)
	if err != nil {
		t.Fatal(err)
	}
	var www string
	for _, h := range hosts {
		if h.Name == "www.acme.example" {
			www = h.ID
		}
	}
	if www == "" {
		t.Fatalf("listed names were not stored: %+v", hosts)
	}
	edit(apex.ID, NodeEdit{Scope: &selected, Selected: &[]string{www}})
	if got := scans(scan(apex.ID), append(names, "mail.acme.example")...); got != "acme.example www.acme.example" {
		t.Fatalf("chosen names: the apex scans %q", got)
	}
}

// What a parent found on its child's name before the child was added is the child's from then on, in the same write: the parent keeps
// the name (linked to the child) without its address, the services on the address only that name pointed at are closed, and the issues
// about that name (a certificate, a web site) or on those services are gone. Removing the child gives the name back to the parent's
// next scan. No name is ever counted as scanned by two targets.
func TestTree_AChildAddedTakesItsNameFromTheParentsRows(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	apex := e.addNode("acme.example", "")
	e.dns.put("acme.example", txtRecord(apex.Token))
	if r, err := e.svc.Verify(e.ctx(), "operator@acme.example", apex.ID); err != nil || !r.Verified {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := e.commit(apex.ID); err != nil {
		t.Fatal(err)
	}
	soon := certAt("git.acme.example", 9*day)
	run := &fakeRunner{content: Content{
		Hosts: []HostRow{
			{Name: "acme.example", IP: ipA, IPs: []HostIP{{IP: ipA, Family: "ipv4", Class: ClassPublic}}},
			{Name: "git.acme.example", IP: ipB, IPs: []HostIP{{IP: ipB, Family: "ipv4", Class: ClassPublic}}},
		},
		Ports: []PortRow{{IP: ipA, Port: 443, Service: "https"}, {IP: ipB, Port: 443, Service: "https"}, {IP: ipB, Port: 22, Service: "ssh"}},
		Certs: []CertRow{soon},
	}}
	e.svc.SetRunner(run)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", apex.ID); err != nil {
		t.Fatal(err)
	}
	if n := e.count(`SELECT count(*) FROM exp_issue WHERE target_id = ? AND state = 'open' AND key = ?`, apex.ID, keyCertExpiry+"git.acme.example"); n != 1 {
		t.Fatalf("the certificate of git is not an issue of the apex: %d", n)
	}
	git := e.addNode("git.acme.example", "")
	for _, c := range []struct {
		what  string
		query string
		want  int
	}{
		{"the name stays, linked to the child", `SELECT count(*) FROM exp_host WHERE target_id = ? AND name = 'git.acme.example' AND child_target_id = '` + git.ID + `'`, 1},
		{"without its address", `SELECT count(*) FROM exp_address a JOIN exp_host h ON h.id = a.host_id WHERE a.target_id = ? AND h.name = 'git.acme.example'`, 0},
		{"the services on its address are closed", `SELECT count(*) FROM exp_service WHERE target_id = ? AND ip = '` + ipB + `' AND state = 'open'`, 0},
		{"the apex's own service stays", `SELECT count(*) FROM exp_service WHERE target_id = ? AND ip = '` + ipA + `' AND state = 'open'`, 1},
		{"the issue about the name is gone", `SELECT count(*) FROM exp_issue WHERE target_id = ? AND state = 'open' AND key LIKE 'cert_expiry:git.%'`, 0},
	} {
		if n := e.count(c.query, apex.ID); n != c.want {
			t.Errorf("%s: %d, want %d", c.what, n, c.want)
		}
	}
	if p, n := e.treeCounts(); p != 0 || n != 0 {
		t.Fatalf("counts %d %d", p, n)
	}
	// The child removed: the parent's next scan probes the name again and writes its address
	if err := e.svc.Delete(e.ctx(), "admin@acme.example", git.ID); err != nil {
		t.Fatal(err)
	}
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", apex.ID); err != nil {
		t.Fatal(err)
	}
	if !run.last.Names.Scans("git.acme.example") {
		t.Fatal("the name is not given back to the parent")
	}
	if n := e.count(`SELECT count(*) FROM exp_address a JOIN exp_host h ON h.id = a.host_id WHERE a.target_id = ? AND h.name = 'git.acme.example' AND h.child_target_id IS NULL`, apex.ID); n != 1 {
		t.Fatalf("the name's address after the child left: %d", n)
	}
}

// Ownership proof through the tree: a subdomain added under a proven apex needs no record of its own, and the proof it inherits is looked
// for again right before each scan, so the apex's record removed, or the apex removed with its token, refuses the child's next scan.
// A name is never covered by a target that only ends alike, by another registered domain, or across a public suffix.
func TestTree_ProofIsInheritedOnlyFromAProvenAncestor(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	run := &fakeRunner{content: Content{Hosts: []HostRow{}, Ports: []PortRow{}}}
	e.svc.SetRunner(run)
	apex, git := e.proveTree()
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", git.ID); err != nil {
		t.Fatalf("the covered child cannot be scanned: %v", err)
	}
	if run.last.Proof == nil || run.last.Proof.Domain != "acme.example" {
		t.Fatalf("the child's scan does not carry the apex's proof: %+v", run.last.Proof)
	}
	calls := run.calls
	// The apex's record removed: the child's next scan is refused at its start, nothing is sent
	e.dns.put("acme.example")
	e.advance(ScanEvery)
	_, err := e.svc.Scan(e.ctx(), "admin@acme.example", git.ID)
	wantAPI(t, err, 409, "txt_missing")
	// The record back, the apex removed with its token: refused again, and the child moves to the top
	e.dns.put("acme.example", txtRecord(apex.Token))
	if err := e.svc.Delete(e.ctx(), "admin@acme.example", apex.ID); err != nil {
		t.Fatal(err)
	}
	if p := e.parents()["git.acme.example"]; p != "" {
		t.Fatalf("the child still sits under %q", p)
	}
	e.advance(ScanEvery)
	_, err = e.svc.Scan(e.ctx(), "admin@acme.example", git.ID)
	wantAPI(t, err, 409, "txt_missing")
	if run.calls != calls {
		t.Fatalf("a refused scan reached the runner (%d calls, want %d)", run.calls, calls)
	}
	// Never covered: a name that only ends alike, another registered domain, a name across a public suffix
	for _, c := range []struct{ proven, other string }{
		{"acme.example", "notacme.example"},
		{"acme.example", "acme.other"},
		{"foo.ddns.net", "bar.ddns.net"},
	} {
		t.Run(c.other, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			p := e.addNode(c.proven, "")
			e.dns.put(c.proven, txtRecord(p.Token))
			if r, err := e.svc.Verify(e.ctx(), "operator@acme.example", p.ID); err != nil || !r.Verified {
				t.Fatalf("%+v %v", r, err)
			}
			o := e.addNode(c.other, "")
			if o.Status == statusVerified || e.parents()[c.other] != "" {
				t.Fatalf("%s is covered by %s: %+v", c.other, c.proven, o)
			}
			e.advance(DomainCheckEvery)
			if r, err := e.svc.Verify(e.ctx(), "operator@acme.example", o.ID); err != nil || r.Verified {
				t.Fatalf("%s verified by %s's record: %+v %v", c.other, c.proven, r, err)
			}
		})
	}
}

// A switched-off target is never scanned, not even through a domain's scan of the address (ScannableIP), and the deep gate refuses it.
func TestTree_ASwitchedOffTargetIsNeverScanned(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ips := e.detect(ipA)
	if _, err := e.commit(ips[0].ID); err != nil {
		t.Fatal(err)
	}
	off := false
	if _, err := e.svc.EditNode(e.ctx(), "admin@acme.example", ips[0].ID, NodeEdit{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	e.svc.SetRunner(&fakeRunner{content: sampleContent()})
	_, err := e.svc.Scan(e.ctx(), "admin@acme.example", ips[0].ID)
	wantAPI(t, err, 409, "disabled")
	if ok, err := e.svc.ScannableIP(e.ctx(), "admin@acme.example", netip.MustParseAddr(ipA)); err != nil || ok {
		t.Fatalf("a switched-off IP may be port-scanned through a domain: %v %v", ok, err)
	}
	if ok, reason, err := e.svc.CheckScannable(context.Background(), "scheduler", ScanIDPrefix+ips[0].ID); err != nil || ok || reason != BlockedDisabled {
		t.Fatalf("CheckScannable: %v %q %v", ok, reason, err)
	}
	if !slices.Contains(e.auditActions(), "exposure.target_edit") {
		t.Fatalf("the edit is not audited: %v", e.auditActions())
	}
}

// The refusals of an edit and of an add: a scope for an IP, a scope that is not one of the three, chosen names without the scope that
// reads them, an id that is not a name of this target, too many at once. Nothing is changed by a refused edit.
func TestTree_EditRefusals(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	apex := e.addNode("acme.example", "")
	other := e.addNode("other.example", "")
	if err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		_, err := writeHosts(e.ctx(), tx, other.ID, "2026-11-09T10:00:00.000Z", []HostRow{{Name: "www.other.example", Source: "ct"}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var foreign string
	if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT id FROM exp_host WHERE target_id = ?`, other.ID).Scan(&foreign); err != nil {
		t.Fatal(err)
	}
	ips := e.detect(ipA)
	bad, self, selected := ScopeMode("everything"), ScopeSelf, ScopeSelected
	many := make([]string, MaxSelected+1)
	for _, c := range []struct {
		what string
		id   string
		ed   NodeEdit
	}{
		{"a scope for an IP", ips[0].ID, NodeEdit{Scope: &self}},
		{"an unknown scope", apex.ID, NodeEdit{Scope: &bad}},
		{"names without the scope that reads them", apex.ID, NodeEdit{Selected: &[]string{}}},
		{"a name of another target", apex.ID, NodeEdit{Scope: &selected, Selected: &[]string{foreign}}},
		{"too many names", apex.ID, NodeEdit{Scope: &selected, Selected: &many}},
	} {
		_, err := e.svc.EditNode(e.ctx(), "admin@acme.example", c.id, c.ed)
		wantAPI(t, err, 400, "bad_value")
	}
	if got, err := loadTarget(e.ctx(), e.db.Reader(), apex.ID); err != nil || got.ScopeMode != ScopeAll {
		t.Fatalf("a refused edit changed the target: %+v %v", got, err)
	}
	_, err := e.svc.AddNode(e.ctx(), "admin@acme.example", NewNode{Value: ipB, Scope: ScopeSelf})
	wantAPI(t, err, 400, "bad_value")
	_, err = e.svc.AddNode(e.ctx(), "admin@acme.example", NewNode{Value: "new.example", Scope: bad})
	wantAPI(t, err, 400, "bad_value")
	v := e.addNode("only.example", ScopeSelf)
	if got, _ := loadTarget(e.ctx(), e.db.Reader(), v.ID); got.ScopeMode != ScopeSelf {
		t.Fatalf("scope at add: %q", got.ScopeMode)
	}
}
