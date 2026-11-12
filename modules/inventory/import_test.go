package inventory_test

import (
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/modules/inventory"
)

func (e *env) importCSV(text string) inventory.ImportResult {
	e.t.Helper()
	r, err := e.svc.Import(e.ctx(), "it@acme.example", "devices.csv", text)
	if err != nil {
		e.t.Fatalf("Import: %v", err)
	}
	return r
}

func TestContract_INV13_CSVImportAndExport(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	good := "name,ip,product,version,kind\r\nBranch firewall,192.168.30.1,FortiGate,7.2.5,firewall\r\nCompany website,,WordPress,6.5.2,web\r\n"
	r := e.importCSV(good)
	if r.Created != 2 || r.Skipped != 0 || len(r.Errors) != 0 {
		t.Fatalf("result = %+v", r)
	}
	l, _ := e.svc.Devices(e.ctx())
	if l.Counts.Manual != 2 {
		t.Fatalf("counts = %+v", l.Counts)
	}

	t.Run("bad rows are reported by row number, good rows are still added", func(t *testing.T) {
		text := strings.Join([]string{
			"name,ip,product,version,kind",
			"ok device,192.168.40.1,Synology,7.2,nas", // line 2: ok
			"x,192.168.40.2,NoSuchProductAtAll,,",     // line 3: product
			"y,999.1.1.1,Synology,,",                  // line 4: ip
			"z,192.168.40.3,Synology,7/2,",            // line 5: version
			"w,192.168.40.4,Synology,,toaster",        // line 6: kind
			"dup,192.168.30.1,Synology,,",             // line 7: IP in the list
			"a,192.168.40.9,Synology,,",               // line 8: ok
			"b,192.168.40.9,Synology,,",               // line 9: IP twice in the file
			",,,,",                                    // blank: ignored
			"a<b,,Synology,,",                         // line 11: name
			",192.168.40.20,,,",                       // line 12: neither name nor product
		}, "\n")
		r := e.importCSV(text)
		if r.Created != 2 || r.Skipped != 8 {
			t.Fatalf("result = %+v", r)
		}
		lines := map[int]string{}
		for _, er := range r.Errors {
			lines[er.Line] = er.Message
		}
		for _, line := range []int{3, 4, 5, 6, 7, 9, 11, 12} {
			if lines[line] == "" {
				t.Errorf("no error for line %d: %v", line, lines)
			}
		}
		if lines[2] != "" || lines[8] != "" {
			t.Errorf("errors on good lines: %v", lines)
		}
	})

	t.Run("a file just exported can be imported again without doubling devices", func(t *testing.T) {
		rd, err := e.svc.ExportCSV(e.ctx(), "it@acme.example")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rd)
		before, _ := e.svc.Devices(e.ctx())
		r := e.importCSV(string(b))
		after, _ := e.svc.Devices(e.ctx())
		if r.Created != 0 || after.Counts.All != before.Counts.All {
			t.Fatalf("created %d, devices %d -> %d, errors %+v", r.Created, before.Counts.All, after.Counts.All, r.Errors)
		}
	})

	t.Run("export is UTF-8 with a BOM, CRLF, and formulas are defused", func(t *testing.T) {
		e := newEnv(t)
		e.addDevice(inventory.AddInput{CatalogID: "fortigate", Name: "=HYPERLINK(\"http://evil\")", IP: "192.168.30.1"})
		e.addDevice(inventory.AddInput{CatalogID: "synology-nas-dsm", Name: "nas, \"main\""})
		rd, err := e.svc.ExportCSV(e.ctx(), "it@acme.example")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rd)
		s := string(b)
		if !strings.HasPrefix(s, "\xef\xbb\xbfname,ip,mac,kind,vendor,model,os,software,approved,fragile,origin,source,confidence,last_seen\r\n") {
			t.Fatalf("header = %q", s[:80])
		}
		if !strings.Contains(s, `'=HYPERLINK("http://evil")`) && !strings.Contains(s, `"'=HYPERLINK(""http://evil"")"`) {
			t.Fatalf("formula not defused: %s", s)
		}
		if !strings.Contains(s, `"nas, ""main"""`) || !strings.HasSuffix(s, "\r\n") {
			t.Fatalf("quoting wrong: %s", s)
		}
		if !has(e.auditActions(), "inventory.export") {
			t.Fatal("export not audited")
		}
	})

	t.Run("the other delimiters of Excel and a BOM are accepted", func(t *testing.T) {
		e := newEnv(t)
		r := e.importCSV("\ufeffname;ip;product\r\nA;192.168.50.1;FortiGate\r\n")
		if r.Created != 1 {
			t.Fatalf("semicolon: %+v", r)
		}
		r = e.importCSV("Device Name\tIP Address\tSoftware\nB\t192.168.50.2\tSynology\n")
		if r.Created != 1 {
			t.Fatalf("tab and aliases: %+v", r)
		}
	})

	t.Run("limits", func(t *testing.T) {
		e := newEnv(t)
		for name, tc := range map[string]struct {
			text, code string
		}{
			"empty":         {"  \n ", "empty_file"},
			"no header":     {"foo,bar\n1,2\n", "bad_header"},
			"too large":     {"name\n" + strings.Repeat("a", inventory.MaxImportBytes), "too_large"},
			"too many rows": {"name\n" + strings.Repeat("x\n", inventory.MaxImportRows+1), "too_many_rows"},
		} {
			_, err := e.svc.Import(e.ctx(), "it@acme.example", "f.csv", tc.text)
			t.Run(name, func(t *testing.T) { wantAPIError(t, err, 400, tc.code) })
		}
		// exactly 500 rows is fine
		var b strings.Builder
		b.WriteString("name,ip\n")
		for i := range inventory.MaxImportRows {
			fmt.Fprintf(&b, "dev%d,10.1.%d.%d\n", i, i/250, i%250+1)
		}
		if r := e.importCSV(b.String()); r.Created != 500 {
			t.Fatalf("500 rows: %+v", r)
		}
	})
}

func TestImportTemplateIsImportable(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	b, _ := io.ReadAll(inventory.ImportTemplate())
	if !strings.HasPrefix(string(b), "\xef\xbb\xbfname,ip,product,version,kind") {
		t.Fatalf("template = %q", b)
	}
	if r := e.importCSV(string(b)); r.Created != 2 {
		t.Fatalf("template import = %+v", r)
	}
}

func TestContract_POST1_RecordObservationCreatesPendingDevices(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	ip := netip.MustParseAddr("192.168.10.50")
	e.tick(-time.Hour)
	first := e.now
	if err := e.svc.RecordObservation(e.ctx(), obs(ip, macA, observe.Vendor, "Acme", observe.Passive, 0.6)); err != nil {
		t.Fatal(err)
	}
	e.tick(time.Hour)
	if err := e.svc.RecordObservation(e.ctx(), obs(ip, macA, observe.Hostname, "cam01", observe.Passive, 0.6)); err != nil {
		t.Fatal(err)
	}
	l, _ := e.svc.Devices(e.ctx())
	if len(l.Items) != 1 {
		t.Fatalf("%d devices, want one (same MAC)", len(l.Items))
	}
	d := l.Items[0]
	if d.Approved || d.IP != "192.168.10.50" || d.MAC == nil || *d.MAC != macA || d.Hostname == nil || *d.Hostname != "cam01" || d.Vendor == nil || d.Vendor.Value != "Acme" {
		t.Fatalf("device = %+v", d)
	}
	if d.FirstSeen != first.Format("2006-01-02T15:04:05.000Z") || d.LastSeen != e.now.Format("2006-01-02T15:04:05.000Z") {
		t.Fatalf("first/last seen = %s / %s", d.FirstSeen, d.LastSeen)
	}
	// found by IP when the MAC is unknown; a device with no MAC yet takes it
	e.record(obs(netip.MustParseAddr("192.168.10.60"), "", observe.Hostname, "printer", observe.Passive, 0.5))
	e.record(obs(netip.MustParseAddr("192.168.10.60"), macB, observe.Vendor, "HP", observe.Passive, 0.5))
	l, _ = e.svc.Devices(e.ctx())
	if len(l.Items) != 2 {
		t.Fatalf("%d devices, want 2", len(l.Items))
	}
	// the IP moves to another device (DHCP): the old one gives it up, nothing is merged
	e.record(obs(netip.MustParseAddr("192.168.10.60"), "aa:bb:cc:00:00:03", observe.Hostname, "newcomer", observe.Passive, 0.5))
	l, _ = e.svc.Devices(e.ctx())
	if len(l.Items) != 3 {
		t.Fatalf("%d devices, want 3", len(l.Items))
	}
	owners := 0
	for _, d := range l.Items {
		if d.IP == "192.168.10.60" {
			owners++
			if d.Hostname == nil || *d.Hostname != "newcomer" {
				t.Fatalf("the IP is held by %+v", d)
			}
		}
	}
	if owners != 1 {
		t.Fatalf("%d devices hold the IP", owners)
	}
	// a declared device keeps its IP; the newcomer gets none
	e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "192.168.10.99"})
	e.record(obs(netip.MustParseAddr("192.168.10.99"), "aa:bb:cc:00:00:04", observe.Hostname, "intruder", observe.Passive, 0.5))
	for _, d := range func() []inventory.Device { l, _ := e.svc.Devices(e.ctx()); return l.Items }() {
		if d.IP == "192.168.10.99" && d.Origin != "manual" {
			t.Fatalf("a discovered device took a declared device's IP: %+v", d)
		}
	}
}

func TestSinkRefusesUntrustedInput(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	good := obsv(macA, observe.Hostname, "ok", observe.Passive, 0.5)
	long := strings.Repeat("a", 201)
	bad := map[string]observe.Observation{
		"manual source":     obsv(macA, observe.Hostname, "x", observe.Manual, 1),
		"unknown source":    obsv(macA, observe.Hostname, "x", "telepathy", 1),
		"unknown field":     obsv(macA, "colour", "x", observe.Passive, 1),
		"confidence 1.5":    obsv(macA, observe.Hostname, "x", observe.Passive, 1.5),
		"confidence -0.1":   obsv(macA, observe.Hostname, "x", observe.Passive, -0.1),
		"empty value":       obsv(macA, observe.Hostname, "", observe.Passive, 1),
		"control character": obsv(macA, observe.Hostname, "a\x00b", observe.Passive, 1),
		"newline":           obsv(macA, observe.OS, "a\nb", observe.Passive, 1),
		"value too long":    obsv(macA, observe.Vendor, long, observe.Passive, 1),
		"bad kind":          obsv(macA, observe.Kind, "toaster", observe.Passive, 1),
		"bad mac value":     obsv(macA, observe.MAC, "zz", observe.Passive, 1),
		"bad mac hint":      obsv("nope", observe.Hostname, "x", observe.Passive, 1),
		"no hint":           {Field: observe.Hostname, Value: "x", Source: observe.Passive, Confidence: 1},
		"IPv6 hint":         {AssetHint: observe.AssetHint{IP: netip.MustParseAddr("fd00::1")}, Field: observe.Hostname, Value: "x", Source: observe.Passive, Confidence: 1},
		"invalid UTF-8":     obsv(macA, observe.Hostname, "a\xffb", observe.Passive, 1),
	}
	for name, o := range bad {
		t.Run(name, func(t *testing.T) {
			err := e.svc.Record(e.ctx(), []observe.Observation{good, o})
			if err == nil || !strings.Contains(err.Error(), "invalid input") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	// the batch is all or none: the good observation of every failed batch was not stored
	if n := e.count(`SELECT count(*) FROM inv_asset`); n != 0 {
		t.Fatalf("%d devices after only failed batches", n)
	}
	// a clock far in the future is replaced by ours
	e.record(observe.Observation{AssetHint: observe.AssetHint{MAC: macA}, Field: observe.Hostname, Value: "x", Source: observe.Passive, Confidence: 0.5, SeenAt: e.now.Add(24 * 365 * time.Hour)})
	l, _ := e.svc.Devices(e.ctx())
	if l.Items[0].LastSeen != "2026-11-09T10:00:00.000Z" {
		t.Fatalf("last_seen = %s", l.Items[0].LastSeen)
	}
	// MAC notations are normalised, so one device is not split in two
	e.record(obsv("AA-BB-CC-00-00-01", observe.Vendor, "Acme", observe.Passive, 0.5))
	if n := e.count(`SELECT count(*) FROM inv_asset`); n != 1 {
		t.Fatalf("%d devices", n)
	}
	if err := e.svc.Record(e.ctx(), nil); err != nil {
		t.Fatal(err)
	}
	big := make([]observe.Observation, 5001)
	for i := range big {
		big[i] = good
	}
	if err := e.svc.Record(e.ctx(), big); err == nil {
		t.Fatal("a batch of 5001 was accepted")
	}
}

func TestContract_POST2_UpsertSoftwareReplacesBySource(t *testing.T) {
	t.Parallel()
	kev := fakeKEV{cves: map[string][]string{"mozilla|firefox": {"CVE-2024-1111"}, "apache|http server": {"CVE-2024-2222"}}}
	e := newEnv(t, withKEV(kev))
	id := e.addDevice(inventory.AddInput{CatalogID: "windows-11", IP: "192.168.1.5"})
	up := func(items ...inventory.SoftwareItem) {
		t.Helper()
		if err := e.svc.UpsertSoftware(e.ctx(), id, items, "agent"); err != nil {
			t.Fatal(err)
		}
	}
	ff := inventory.SoftwareItem{Vendor: "Mozilla", Product: "Firefox", Version: "120", Confidence: 0.9}
	httpd := inventory.SoftwareItem{Vendor: "Apache", Product: "HTTP Server", Version: "2.4.58", Confidence: 0.9, KevKeys: []string{"Apache|HTTP Server"}}
	e.ev.reset()
	up(ff, httpd)
	if n := len(e.detail(id).Asset.Software); n != 3 { // the manual Windows row stays
		t.Fatalf("%d software rows", n)
	}
	if n := len(e.ev.named(inventory.EventSoftwareChanged)); n != 1 {
		t.Fatalf("%d software.changed", n)
	}
	got := map[string]bool{}
	for _, ev := range e.ev.named(inventory.EventMatchChanged) {
		got[ev.Data.(inventory.MatchEvent).CVE] = true
	}
	if !got["CVE-2024-1111"] || !got["CVE-2024-2222"] || len(got) != 2 {
		t.Fatalf("match events = %v", got)
	}
	// the same list again changes nothing and announces nothing
	e.ev.reset()
	up(ff, httpd)
	if len(e.ev.events) != 0 {
		t.Fatalf("events for an identical list: %+v", e.ev.events)
	}
	// a shorter list removes what the source no longer reports, and only that source's rows
	up(ff)
	var names []string
	for _, s := range e.detail(id).Asset.Software {
		names = append(names, s.Display+"/"+s.Source)
	}
	if strings.Join(names, ",") != "Mozilla Firefox/agent,Windows 11/manual" {
		t.Fatalf("software = %v", names)
	}
	// a new version replaces the old row of the same source? No: versions are distinct rows until the agent drops the old one
	up(inventory.SoftwareItem{Vendor: "Mozilla", Product: "Firefox", Version: "121", Confidence: 0.9})
	if n := len(e.detail(id).Asset.Software); n != 2 {
		t.Fatalf("%d rows after an upgrade", n)
	}
	// manual is refused, an unknown device is ErrNotFound, bad items are refused
	if err := e.svc.UpsertSoftware(e.ctx(), id, nil, "manual"); err == nil {
		t.Fatal("manual accepted")
	}
	if err := e.svc.UpsertSoftware(e.ctx(), "a-nope", nil, "agent"); err == nil {
		t.Fatal("unknown device accepted")
	}
	if err := e.svc.UpsertSoftware(e.ctx(), id, []inventory.SoftwareItem{{Vendor: "", Product: "x"}}, "agent"); err == nil {
		t.Fatal("empty vendor accepted")
	}
	if err := e.svc.UpsertSoftware(e.ctx(), id, []inventory.SoftwareItem{{Vendor: "a", Product: "b", Confidence: 2}}, "agent"); err == nil {
		t.Fatal("confidence 2 accepted")
	}
	// the agent path through core/observe finds or creates the device by hint
	if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{MAC: macB, IP: netip.MustParseAddr("192.168.1.77")}, observe.Agent, []observe.Software{{Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6", Confidence: 0.9}}); err != nil {
		t.Fatal(err)
	}
	if got := e.idByMAC(macB); len(e.detail(got).Asset.Software) != 1 {
		t.Fatal("software not stored for the new device")
	}
	if err := e.svc.ReplaceSoftware(e.ctx(), observe.AssetHint{MAC: macB}, observe.Manual, nil); err == nil {
		t.Fatal("manual accepted by the sink")
	}
}

func TestContract_POST4_PatchAddsAManualObservationAndKeepsTheOldValues(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.record(obs(netip.MustParseAddr("192.168.1.9"), macA, observe.Kind, "pc", observe.Agent, 0.9))
	id := e.idByMAC(macA)
	before := e.count(`SELECT count(*) FROM inv_observation WHERE asset_id = ? AND field = 'kind'`, id)
	k := "printer"
	notes := "second floor"
	if err := e.svc.PatchDevice(e.ctx(), "it@acme.example", id, inventory.Patch{Kind: &k, Notes: &notes}); err != nil {
		t.Fatal(err)
	}
	d := e.detail(id)
	if d.Asset.Kind != "printer" || !d.Asset.Fragile || d.Asset.Notes == nil || *d.Asset.Notes != notes {
		t.Fatalf("device = %+v", d.Asset)
	}
	if after := e.count(`SELECT count(*) FROM inv_observation WHERE asset_id = ? AND field = 'kind'`, id); after != before+1 {
		t.Fatalf("kind observations %d -> %d", before, after)
	}
	cur, _ := currentOf(d, "kind")
	if cur.Source != "manual" || cur.Confidence != 1 || cur.Value != "printer" {
		t.Fatalf("current kind = %+v", cur)
	}
	var oldKept bool
	for _, o := range d.Observations {
		oldKept = oldKept || (o.Field == "kind" && o.Value == "pc" && o.Source == "agent" && !o.Current)
	}
	if !oldKept {
		t.Fatalf("the agent's value is gone: %+v", d.Observations)
	}
	// errors
	bad := "toaster"
	wantAPIError(t, e.svc.PatchDevice(e.ctx(), "it@acme.example", id, inventory.Patch{Kind: &bad}), 400, "bad_kind")
	wantAPIError(t, e.svc.PatchDevice(e.ctx(), "it@acme.example", id, inventory.Patch{RegularScan: &bad}), 400, "bad_regular_scan")
	long := strings.Repeat("n", 2001)
	wantAPIError(t, e.svc.PatchDevice(e.ctx(), "it@acme.example", id, inventory.Patch{Notes: &long}), 400, "bad_notes")
	wantAPIError(t, e.svc.PatchDevice(e.ctx(), "it@acme.example", "a-nope", inventory.Patch{}), 404, "not_found")
	if !has(e.auditActions(), "inventory.set_kind") || !has(e.auditActions(), "inventory.set_notes") {
		t.Fatalf("audit = %v", e.auditActions())
	}
}

func TestEveryMutationIsAudited(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	id := e.addDevice(inventory.AddInput{CatalogID: "fortigate", IP: "192.168.1.1"})
	_, err := e.svc.AddSoftware(e.ctx(), "it@acme.example", id, inventory.AddInput{CatalogID: "openvpn-access-server"})
	must(err)
	for _, s := range e.detail(id).Asset.Software {
		if s.Product == "Access Server" {
			must(e.svc.RemoveSoftware(e.ctx(), "it@acme.example", id, s.ID))
		}
	}
	kind, rs, notes, fragile := "router", "never", "rack 2", true
	must(e.svc.PatchDevice(e.ctx(), "it@acme.example", id, inventory.Patch{Kind: &kind, RegularScan: &rs, Notes: &notes, Fragile: &fragile}))
	must(e.svc.SetSuspicious(e.ctx(), "it@acme.example", id, true))
	must(e.svc.SetSuspicious(e.ctx(), "it@acme.example", id, false))
	must(e.svc.Approve(e.ctx(), "it@acme.example", id))
	must(e.svc.SetNotifyNew(e.ctx(), "it@acme.example", true))
	e.importCSV("name\nx\n")
	_, err = e.svc.ExportCSV(e.ctx(), "it@acme.example")
	must(err)
	_, err = e.svc.SaveSettings(e.ctx(), "admin@acme.example", okSettings())
	must(err)
	must(e.svc.DeleteDevice(e.ctx(), "it@acme.example", id))
	got := e.auditActions()
	for _, want := range []string{
		"inventory.add_manual", "inventory.add_software", "inventory.remove_software", "inventory.set_kind", "inventory.set_regular_scan", "inventory.set_fragile",
		"inventory.set_notes", "inventory.mark_suspicious", "inventory.unmark_suspicious", "inventory.approve", "inventory.notify_new", "inventory.import",
		"inventory.export", "inventory.settings", "inventory.delete",
	} {
		if !has(got, want) {
			t.Errorf("no audit row %s in %v", want, got)
		}
	}
	// a failed mutation leaves no audit row and no data (one transaction)
	n := e.count(`SELECT count(*) FROM core_audit`)
	_, err = e.svc.AddDevice(e.ctx(), "it@acme.example", inventory.AddInput{CatalogID: "fortigate", IP: "bad"})
	if err == nil || e.count(`SELECT count(*) FROM core_audit`) != n {
		t.Fatal("a failed add changed the audit log")
	}
	if e.count(`SELECT count(*) FROM core_audit WHERE user = 'it@acme.example'`) == 0 {
		t.Fatal("the actor is not recorded")
	}
}

func TestImportDoesNotBurnCPUOnHostileCells(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	// one 180 KB product cell of many short words (it used to hold the single writer for ten seconds)
	big := "name,product\r\nx," + strings.Repeat("ab ", 60_000) + "\r\n"
	start := time.Now()
	r := e.importCSV(big)
	// Wall-clock guards only catch the old cost (10.9 s here, ~5x that under -race): a busy CI or dev machine
	// must not fail them, so they sit far above the normal 0.3 s.
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("a 180 KB cell took %v", d)
	}
	if r.Created != 0 || len(r.Errors) != 1 || !strings.Contains(r.Errors[0].Message, "too long") || r.Errors[0].Line != 2 {
		t.Fatalf("result = %+v", r)
	}
	// 500 rows of unknown products of 64 characters (the longest accepted): about 0.3 s normally, 10.6 s before the fix
	var b strings.Builder
	b.WriteString("name,product\n")
	for range inventory.MaxImportRows {
		b.WriteString("x," + strings.Repeat("zq ", 21) + "x\n")
	}
	start = time.Now()
	r = e.importCSV(b.String())
	if d := time.Since(start); d > 30*time.Second {
		t.Fatalf("500 unknown products took %v", d)
	}
	if r.Created != 0 || len(r.Errors) != inventory.MaxImportRows || !strings.Contains(r.Errors[0].Message, "not recognised") {
		t.Fatalf("created %d, %d errors, first %+v", r.Created, len(r.Errors), r.Errors[0])
	}
}

func TestNotFoundComesBeforeBadInput(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	_, err := e.svc.AddSoftware(e.ctx(), "it@acme.example", "a-nope", inventory.AddInput{Vendor: "only a vendor"})
	wantAPIError(t, err, 404, "not_found")
	_, err = e.svc.AddSoftware(e.ctx(), "it@acme.example", "a-nope", inventory.AddInput{CatalogID: "fortigate", Version: "7/2"})
	wantAPIError(t, err, 404, "not_found")
	bad := "toaster"
	wantAPIError(t, e.svc.PatchDevice(e.ctx(), "it@acme.example", "a-nope", inventory.Patch{Kind: &bad}), 404, "not_found")
	// the same device that exists: the body is then judged
	id := e.addDevice(inventory.AddInput{CatalogID: "fortigate"})
	_, err = e.svc.AddSoftware(e.ctx(), "it@acme.example", id, inventory.AddInput{Vendor: "only a vendor"})
	wantAPIError(t, err, 400, "incomplete_product")
}
