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

// planRunner answers a domain's scan as the surface scanner does with its plan: the names it owns with their ports and certificates, the
// others listed without a probe.
type planRunner struct {
	content Content // every name the domain has, with the ports and certificates of their addresses
	last    ScanTarget
	during  func() // runs while the scan runs, after its plan was read
}

func (r *planRunner) Scan(_ context.Context, st ScanTarget) (Content, error) {
	r.last = st
	if r.during != nil {
		r.during()
		r.during = nil
	}
	out := Content{Hosts: []HostRow{}, Ports: []PortRow{}}
	reached := map[string]bool{}
	for _, h := range r.content.Hosts {
		if !strings.HasSuffix("."+h.Name, "."+st.Value) {
			continue
		}
		if !st.Names.Scans(h.Name) {
			out.Listed = append(out.Listed, HostRow{Name: h.Name, Source: h.Source})
			continue
		}
		out.Hosts = append(out.Hosts, h)
		reached[h.IP] = true
		for _, c := range r.content.Certs {
			if c.Host == h.Name {
				out.Certs = append(out.Certs, c)
			}
		}
	}
	for _, p := range r.content.Ports {
		if reached[p.IP] {
			out.Ports = append(out.Ports, p)
		}
	}
	return out, nil
}

// lastWritten is the newest exposure.scan.written of target id.
func (e *env) lastWritten(id string) ScanWrittenEvent {
	e.t.Helper()
	e.pub.mu.Lock()
	defer e.pub.mu.Unlock()
	for i := len(e.pub.got) - 1; i >= 0; i-- {
		if w, ok := e.pub.got[i].Data.(ScanWrittenEvent); ok && w.TargetID == id {
			return w
		}
	}
	e.t.Fatalf("no scan of %s was written", id)
	return ScanWrittenEvent{}
}

// The rows of a name live with the target that scans it, and moving them is never news: the apex scanned git.<apex> and x.git.<apex>;
// git.<apex> added takes their rows (open services, an issue about the name, first seen kept), the apex keeps the names without them;
// switched off, narrowed to its own name, or removed, the child hands them back and the apex's next scan opens no port and finds no new
// issue. Neither count of the tree is ever above 0.
func TestTree_OwnershipMovesWithoutANewPortOrANewIssue(t *testing.T) {
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
	host := func(name, ip string) HostRow {
		return HostRow{Name: name, IP: ip, Source: "ct", IPs: []HostIP{{IP: ip, Family: "ipv4", Class: ClassPublic}}}
	}
	run := &planRunner{content: Content{
		Hosts: []HostRow{host("acme.example", ipA), host("git.acme.example", ipB), host("x.git.acme.example", ipC)},
		Ports: []PortRow{{IP: ipA, Port: 443, Service: "https"}, {IP: ipB, Port: 22, Service: "ssh"}, {IP: ipB, Port: 443, Service: "https"}, {IP: ipC, Port: 80, Service: "http"}},
		Certs: []CertRow{certAt("git.acme.example", 9*day)},
	}}
	e.svc.SetRunner(run)
	scanApex := func(what string) {
		t.Helper()
		e.advance(ScanEvery)
		if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", apex.ID); err != nil {
			t.Fatal(err)
		}
		w := e.lastWritten(apex.ID)
		if !w.First && (len(w.Opened) != 0 || len(w.NewIssues) != 0) {
			t.Fatalf("%s: the apex's scan reports opened %+v and new issues %v", what, w.Opened, w.NewIssues)
		}
		if p, n := e.treeCounts(); p != 0 || n != 0 {
			t.Fatalf("%s: counts %d %d", what, p, n)
		}
	}
	held := func(target, ip string) int {
		return e.count(`SELECT count(*) FROM exp_service WHERE target_id = ? AND ip = ? AND state = 'open'`, target, ip)
	}
	scanApex("the first scan")
	scanApex("the second scan")

	git := e.addNode("git.acme.example", "")
	for _, c := range []struct {
		what string
		n    int
		want int
	}{
		{"the apex keeps git's name, linked to it", e.count(`SELECT count(*) FROM exp_host WHERE target_id = ? AND name = 'git.acme.example' AND child_target_id = ?`, apex.ID, git.ID), 1},
		{"a name under git is no target: no link", e.count(`SELECT count(*) FROM exp_host WHERE target_id = ? AND name = 'x.git.acme.example' AND child_target_id IS NULL`, apex.ID), 1},
		{"the apex holds nothing on git's addresses", held(apex.ID, ipB) + held(apex.ID, ipC), 0},
		{"git holds them, open", held(git.ID, ipB) + held(git.ID, ipC), 3},
		{"with their first seen", e.count(`SELECT count(*) FROM exp_service s WHERE s.target_id = ? AND s.first_seen = (SELECT min(first_seen) FROM exp_service WHERE target_id = ?)`, git.ID, git.ID), 3},
		{"and the issue about its name", e.count(`SELECT count(*) FROM exp_issue WHERE target_id = ? AND state = 'open' AND key = ?`, git.ID, keyCertExpiry+"git.acme.example"), 1},
		{"nothing was closed", e.count(`SELECT count(*) FROM exp_service WHERE state = 'closed'`), 0},
	} {
		if c.n != c.want {
			t.Errorf("%s: %d, want %d", c.what, c.n, c.want)
		}
	}
	scanApex("the scan after git was added")

	off, on, self := false, true, ScopeSelf
	if _, err := e.svc.EditNode(e.ctx(), "admin@acme.example", git.ID, NodeEdit{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	if held(apex.ID, ipB) != 2 || held(git.ID, ipB) != 0 {
		t.Fatalf("git switched off: the apex holds %d on its address, git %d", held(apex.ID, ipB), held(git.ID, ipB))
	}
	scanApex("git switched off")
	if _, err := e.svc.EditNode(e.ctx(), "admin@acme.example", git.ID, NodeEdit{Enabled: &on, Scope: &self}); err != nil {
		t.Fatal(err)
	}
	if held(git.ID, ipB) != 2 || held(apex.ID, ipC) != 1 || held(git.ID, ipC) != 0 { // git's own name is git's; x.git, out of its scope, the apex's
		t.Fatalf("git on, only its own name: git %d on its address, apex %d / git %d on x.git's", held(git.ID, ipB), held(apex.ID, ipC), held(git.ID, ipC))
	}
	scanApex("git narrowed to its own name")
	if err := e.svc.Delete(e.ctx(), "admin@acme.example", git.ID); err != nil {
		t.Fatal(err)
	}
	if held(apex.ID, ipB) != 2 || e.count(`SELECT count(*) FROM exp_issue WHERE target_id = ? AND state = 'open' AND key = ?`, apex.ID, keyCertExpiry+"git.acme.example") != 1 {
		t.Fatal("git removed: its rows did not come back to the apex")
	}
	scanApex("git removed")
	if n := e.count(`SELECT count(*) FROM exp_service WHERE state = 'closed'`); n != 0 {
		t.Fatalf("%d services were closed by moves", n)
	}
}

// A port that opens while the tree changes is reported once: the child is switched on while the apex's scan (planned with the child off)
// runs and finds RDP newly open on the child's address. The apex's write reports it opened and hands it to the child; the port the apex
// had already seen there, folded into the child's own row, is not reported again; the child's next scan reports nothing.
func TestTree_APortNewInAScanThatMovesIsReportedOnce(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	apex, git := e.proveTree()
	off, on := false, true
	if _, err := e.svc.EditNode(e.ctx(), "admin@acme.example", git.ID, NodeEdit{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	host := func(name, ip string) HostRow {
		return HostRow{Name: name, IP: ip, Source: "ct", IPs: []HostIP{{IP: ip, Family: "ipv4", Class: ClassPublic}}}
	}
	run := &planRunner{content: Content{Hosts: []HostRow{host("acme.example", ipA), host("git.acme.example", ipB)},
		Ports: []PortRow{{IP: ipA, Port: 443, Service: "https"}, {IP: ipB, Port: 22, Service: "ssh"}}}}
	e.svc.SetRunner(run)
	scan := func(id string) ScanWrittenEvent {
		t.Helper()
		e.advance(ScanEvery)
		if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", id); err != nil {
			t.Fatal(err)
		}
		return e.lastWritten(id)
	}
	scan(apex.ID) // the apex's baseline, git's name its own while git is off
	run.content.Ports = append(run.content.Ports, PortRow{IP: ipB, Port: 3389, Service: "ms-wbt-server"})
	run.during = func() {
		if _, err := e.svc.EditNode(e.ctx(), "admin@acme.example", git.ID, NodeEdit{Enabled: &on}); err != nil {
			t.Error(err)
		}
	}
	w := scan(apex.ID)
	if w.First || len(w.Opened) != 1 || w.Opened[0].Port != 3389 {
		t.Fatalf("the apex's scan reports opened %+v (first %v), want 3389 once", w.Opened, w.First)
	}
	if n := e.count(`SELECT count(*) FROM exp_service WHERE target_id = ? AND port = 3389 AND state = 'open'`, git.ID); n != 1 {
		t.Fatalf("the new port is not the child's: %d", n)
	}
	if g := scan(git.ID); len(g.Opened) != 0 {
		t.Fatalf("the child's scan reports it again: %+v", g.Opened)
	}
	alerts := 0
	e.pub.mu.Lock()
	for _, ev := range e.pub.got {
		if x, ok := ev.Data.(ScanWrittenEvent); ok {
			for _, p := range x.Opened {
				if p.Port == 3389 {
					alerts++
				}
			}
		}
	}
	e.pub.mu.Unlock()
	if alerts != 1 {
		t.Fatalf("3389 reported opened %d times, want 1", alerts)
	}
}

// The count of names scanned twice reads what the scans probed: with a runner that probes every name it is handed, the apex's scan of
// its child's name counts; with the plan obeyed it does not.
func TestTree_ANameScannedTwiceIsCounted(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	apex, git := e.proveTree()
	hosts := []HostRow{{Name: "acme.example", IP: ipA, IPs: []HostIP{{IP: ipA, Family: "ipv4", Class: ClassPublic}}},
		{Name: "git.acme.example", IP: ipB, IPs: []HostIP{{IP: ipB, Family: "ipv4", Class: ClassPublic}}}}
	for _, c := range []struct {
		id    string
		hosts []HostRow
	}{{git.ID, hosts[1:]}, {apex.ID, hosts}} { // the apex's runner probes every name, whatever the plan says
		e.svc.SetRunner(&fakeRunner{content: Content{Hosts: c.hosts, Ports: []PortRow{}}})
		e.advance(ScanEvery)
		if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", c.id); err != nil {
			t.Fatal(err)
		}
	}
	if _, n := e.treeCounts(); n != 1 {
		t.Fatalf("a name probed by the apex and its child counts %d, want 1", n)
	}
	e.svc.SetRunner(&planRunner{content: Content{Hosts: hosts, Ports: []PortRow{}}})
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", apex.ID); err != nil {
		t.Fatal(err)
	}
	if _, n := e.treeCounts(); n != 0 {
		t.Fatalf("with the plan obeyed the count is %d, want 0", n)
	}
	// A change of who scans the name is no double scan: git off, the apex scans git's name (its own then), git on, git scans it
	off, on := false, true
	if _, err := e.svc.EditNode(e.ctx(), "admin@acme.example", git.ID, NodeEdit{Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", apex.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.EditNode(e.ctx(), "admin@acme.example", git.ID, NodeEdit{Enabled: &on}); err != nil {
		t.Fatal(err)
	}
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", git.ID); err != nil {
		t.Fatal(err)
	}
	if _, n := e.treeCounts(); n != 0 {
		t.Fatalf("after git was switched off and on the count is %d, want 0", n)
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
	// The row says it: no method of its own, the ancestor's record at its last check
	if c, _ := loadTarget(e.ctx(), e.db.Reader(), git.ID); c.Method != "" || c.LastCheck == nil || c.LastCheck.Via != "acme.example" {
		t.Fatalf("the covered child's proof: method %q, check %+v", c.Method, c.LastCheck)
	}
	if a, _ := loadTarget(e.ctx(), e.db.Reader(), apex.ID); a.Method != methodDNS {
		t.Fatalf("the apex's own proof: method %q", a.Method)
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
	if run.calls != calls {
		t.Fatalf("a refused scan reached the runner")
	}
	// The record back, the apex removed with its token: refused again, and the child moves to the top
	e.dns.put("acme.example", txtRecord(apex.Token))
	e.advance(ScanEvery)
	if _, err := e.svc.Scan(e.ctx(), "admin@acme.example", git.ID); err != nil { // covered again
		t.Fatal(err)
	}
	calls = run.calls
	if err := e.svc.Delete(e.ctx(), "admin@acme.example", apex.ID); err != nil {
		t.Fatal(err)
	}
	if p := e.parents()["git.acme.example"]; p != "" {
		t.Fatalf("the child still sits under %q", p)
	}
	if c := e.target(git.ID); c.Scannable || c.LastCheck == nil || c.LastCheck.OK { // the page says it at once, not only at the next scan
		t.Fatalf("the child still reads as proven after its ancestor left: %+v", c.LastCheck)
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
