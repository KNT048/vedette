package exposure

import (
	"database/sql"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// D-79 (3), CONTRACT INV-14: the Ignored list. It only blocks: an ignored IP is never added by detection and never
// scanned, and restoring one only lets detection add it again.

func (e *env) ignoredValues() []string {
	e.t.Helper()
	l, err := e.svc.Ignored(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, x := range l {
		out = append(out, x.Value)
	}
	return out
}

func (e *env) idOfIP(ip string) string {
	e.t.Helper()
	for _, v := range e.ipTargets() {
		if v.Value == ip {
			return v.ID
		}
	}
	e.t.Fatalf("%s is not in the list: %v", ip, e.ipValues())
	return ""
}

func TestContract_INV14_IgnoredIPIsNeverAddedOrScanned(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.svc.SetRunner(&fakeRunner{content: sampleContent()})
	e.detect(ipA, ipB)
	b := e.idOfIP(ipB)
	if _, err := e.commit(b); err != nil {
		t.Fatal(err)
	}

	// removing with "don't add it again": the target and its data are gone, the IP is on the list, both audited as the person
	if err := e.svc.Remove(e.ctx(), "admin@acme.example", b, true); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.Ignored(e.ctx())
	if err != nil || len(got) != 1 || got[0].Value != ipB || got[0].IgnoredBy != "admin@acme.example" || got[0].IgnoredAt != "2026-11-09T10:00:00.000Z" {
		t.Fatalf("ignored = %+v %v", got, err)
	}
	var del, ign auditRow
	for _, a := range e.audits() {
		switch a.Action {
		case "exposure.target_delete":
			del = a
		case "exposure.ip_ignore":
			ign = a
		}
	}
	if del.User != "admin@acme.example" || del.Target != ipB || ign.User != "admin@acme.example" || ign.Target != ipB {
		t.Fatalf("audit: %+v %+v", del, ign)
	}
	if _, err := e.svc.Scan(e.ctx(), "operator@acme.example", b); err == nil {
		t.Fatal("an ignored IP was scanned")
	}

	// detection by a click, and by the job, sees B and does not add it
	e.prober.set(ipA, ipB)
	e.advance(time.Minute)
	r, err := e.svc.Detect(e.ctx(), "admin@acme.example", true)
	if err != nil || len(r.Items) != 1 || r.Items[0].Value != ipA || !strings.Contains(r.Message, "Not added, on your Ignored list: "+ipB+".") {
		t.Fatalf("detect = %+v %v", r, err)
	}
	e.advance(time.Hour)
	e.runJob()
	if slices.Contains(e.ipValues(), ipB) {
		t.Fatalf("the job added an ignored IP: %v", e.ipValues())
	}

	// the box uses only ignored addresses: a normal result, not a failure, and nothing is stored
	e.prober.set(ipB)
	e.advance(time.Minute)
	r, err = e.svc.Detect(e.ctx(), "admin@acme.example", true)
	if err != nil || len(r.Items) != 0 || r.Message != "The box reaches the Internet via "+ipB+", which is on your Ignored list, so nothing was added." {
		t.Fatalf("only ignored: %+v %v", r, err)
	}
	if b := e.settings(); b.LastRun == nil || !b.LastRun.OK {
		t.Fatalf("last run = %+v", b.LastRun)
	}

	// Restore only lets detection add it again: nothing is added by it, and the new target needs ownership proof and a commitment again
	if err := e.svc.Restore(e.ctx(), "admin@acme.example", ipB); err != nil {
		t.Fatal(err)
	}
	if len(e.ignoredValues()) != 0 || slices.Contains(e.ipValues(), ipB) {
		t.Fatalf("restore changed the list of targets: ignored %v, IPs %v", e.ignoredValues(), e.ipValues())
	}
	e.advance(time.Minute)
	e.detect(ipA, ipB)
	back := e.target(e.idOfIP(ipB))
	if back.Commitment != nil || back.Scannable || str((*string)(back.BlockedReason)) != "no_commitment" {
		t.Fatalf("restored IP = %+v", back)
	}
	var restore auditRow
	for _, a := range e.audits() {
		if a.Action == "exposure.ip_restore" {
			restore = a
		}
	}
	if restore.User != "admin@acme.example" || restore.Target != ipB {
		t.Fatalf("restore audit = %+v", restore)
	}
}

func TestContract_INV14_RefusalsChangeNothing(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	d := e.addVerifiedDomain()
	// only an IP can be ignored
	wantAPI(t, e.svc.Remove(e.ctx(), "admin@acme.example", d.ID, true), 400, "bad_value")
	if got := e.target(d.ID); got.Value != d.Value || len(e.ignoredValues()) != 0 {
		t.Fatal("a refused removal changed something")
	}
	// restore: not on the list, not an address
	wantAPI(t, e.svc.Restore(e.ctx(), "admin@acme.example", ipC), 404, "not_found")
	for _, bad := range []string{"", "not-an-ip", "8.8.8", "08.8.8.8", "8.8.8.8/32", "::1", "2001:db8::1", " 8.8.8.8", "8.8.8.8\n"} {
		wantAPI(t, e.svc.Restore(e.ctx(), "admin@acme.example", bad), 400, "bad_value")
	}
	// the list is bounded
	err := e.db.Write(e.ctx(), func(tx *sql.Tx) error {
		for i := range MaxIgnored {
			if _, err := tx.ExecContext(e.ctx(), `INSERT INTO exp_ignored (value, ignored_by, ignored_at) VALUES (?, 'admin@acme.example', '2026-11-09T10:00:00.000Z')`, "10.9."+strconv.Itoa(i/250)+"."+strconv.Itoa(i%250+1)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ip := e.detect(ipA)[0]
	wantAPI(t, e.svc.Remove(e.ctx(), "admin@acme.example", ip.ID, true), 400, "too_many")
	if got := e.target(ip.ID); got.Value != ipA {
		t.Fatal("the IP was removed although the list is full")
	}
	// without "ignore" there is no limit and nothing is listed
	if err := e.svc.Remove(e.ctx(), "admin@acme.example", ip.ID, false); err != nil {
		t.Fatal(err)
	}
}

// The database refuses what the contract forbids (DATA_MODEL section 6).
func TestMigrations_IgnoredConstraints(t *testing.T) {
	t.Parallel()
	db := newDB(t)
	exec := func(q string) error {
		return db.Write(t.Context(), func(tx *sql.Tx) error { _, err := tx.ExecContext(t.Context(), q); return err })
	}
	ok := `INSERT INTO exp_ignored (value, ignored_by, ignored_at) VALUES ('8.8.8.8', 'a@b.example', '2026-11-09T10:00:00.000Z')`
	if err := exec(ok); err != nil {
		t.Fatal(err)
	}
	for name, q := range map[string]string{
		"duplicate":   ok,
		"not an IPv4": `INSERT INTO exp_ignored (value, ignored_by, ignored_at) VALUES ('not-an-ip', 'a@b.example', '2026-11-09T10:00:00.000Z')`,
		"no actor":    `INSERT INTO exp_ignored (value, ignored_by, ignored_at) VALUES ('9.9.9.9', '', '2026-11-09T10:00:00.000Z')`,
		"bad time":    `INSERT INTO exp_ignored (value, ignored_by, ignored_at) VALUES ('9.9.9.9', 'a@b.example', 'yesterday')`,
	} {
		if err := exec(q); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestHandlers_IgnoredList(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	e.detect(ipA, ipB)
	id := e.idOfIP(ipB)

	// the list comes with GET /exposure/targets, newest first, empty (not null) at the start
	code, b := e.call("GET", "/exposure/targets", "viewer", "")
	if code != 200 || b["ignored"] == nil || len(list(b, "ignored")) != 0 {
		t.Fatalf("start: %d %v", code, b["ignored"])
	}
	// ?ignore=true needs an admin; the operator is refused before anything changes
	if code, _ := e.call("DELETE", "/exposure/targets/"+id+"?ignore=true", "operator", ""); code != 403 {
		t.Fatalf("operator: %d", code)
	}
	if code, _ := e.call("DELETE", "/exposure/targets/"+id+"?ignore=maybe", "admin", ""); code != 400 {
		t.Fatalf("a value that is not true or false: %d", code)
	}
	if code, _ := e.call("DELETE", "/exposure/targets/"+id+"?ignore=true", "admin", ""); code != 204 {
		t.Fatalf("remove and ignore: %d", code)
	}
	_, b = e.call("GET", "/exposure/targets", "viewer", "")
	got := list(b, "ignored")
	if len(got) != 1 {
		t.Fatalf("ignored = %v", got)
	}
	row, _ := got[0].(map[string]any)
	if row["value"] != ipB || row["ignored_by"] == "" || row["ignored_at"] != "2026-11-09T10:00:00Z" /* the API drops zero milliseconds */ {
		t.Fatalf("row = %v", row)
	}
	// restore: admin only, 404 when not on the list, 400 for something that is not an address
	for _, role := range []string{"viewer", "operator"} {
		if code, _ := e.call("DELETE", "/exposure/box-ip/ignored/"+ipB, role, ""); code != 403 {
			t.Errorf("%s: %d", role, code)
		}
	}
	if code, b := e.call("DELETE", "/exposure/box-ip/ignored/"+ipC, "admin", ""); code != 404 || errCode(b) != "not_found" {
		t.Fatalf("not on the list: %d %v", code, b)
	}
	if code, b := e.call("DELETE", "/exposure/box-ip/ignored/not-an-ip", "admin", ""); code != 400 || errCode(b) != "bad_value" {
		t.Fatalf("not an address: %d %v", code, b)
	}
	if code, _ := e.call("DELETE", "/exposure/box-ip/ignored/"+ipB, "admin", ""); code != 204 {
		t.Fatalf("restore: %d", code)
	}
	if _, b = e.call("GET", "/exposure/targets", "viewer", ""); len(list(b, "ignored")) != 0 {
		t.Fatal("still ignored after restore")
	}
	// the module is off: no routes
	e.gate.Set(ModuleID, false)
	if code, _ := e.call("DELETE", "/exposure/box-ip/ignored/"+ipB, "admin", ""); code != 404 {
		t.Fatalf("module off: %d", code)
	}
}
