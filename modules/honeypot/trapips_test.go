package honeypot_test

// D-466 Trap IPs: the upgrade from the secondary IP and decoys, what the host is asked to build, what the list shows about
// where each Trap IP lives, which Trap IP a hit names, and W1-13: a source touching two Trap IPs within a minute is a scan.

import (
	"context"
	"fmt"
	"io/fs"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/core/store/storetest"
	"github.com/knt048/vedette/modules/core"
	"github.com/knt048/vedette/modules/honeypot"
)

// migratedBefore is a database at the honeypot migrations before 0003 (a box before D-466).
func migratedBefore(t *testing.T) *store.DB {
	t.Helper()
	before := fstest.MapFS{}
	entries, err := fs.ReadDir(honeypot.Migrations, ".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() >= "0003" {
			continue
		}
		b, err := fs.ReadFile(honeypot.Migrations, e.Name())
		if err != nil {
			t.Fatal(err)
		}
		before[e.Name()] = &fstest.MapFile{Data: b}
	}
	return storetest.Migrated(t, storetest.Migration{Module: "core", FS: core.Migrations}, storetest.Migration{Module: "honeypot", FS: before})
}

type tipRow struct {
	ID, Name, IP, Preset, Services, Created string
	Vendor                                  *string
	Enabled                                 bool
}

func migrateRows(t *testing.T, db *store.DB, setup ...string) []tipRow {
	t.Helper()
	ctx := t.Context()
	if err := db.Write(ctx, func(tx *sqlTx) error {
		for _, q := range setup {
			if _, err := tx.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx, db, "honeypot", honeypot.Migrations); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Reader().QueryContext(ctx, `SELECT id, name, ip, preset, vendor, services, enabled, created_at FROM hp_trap_ips ORDER BY created_at, id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []tipRow
	for rows.Next() {
		var r tipRow
		if err := rows.Scan(&r.ID, &r.Name, &r.IP, &r.Preset, &r.Vendor, &r.Services, &r.Enabled, &r.Created); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE name IN ('hp_trap', 'hp_decoys')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("old tables left: %d %v", n, err)
	}
	if err := db.Reader().QueryRowContext(ctx, `SELECT count(*) FROM hp_config WHERE key = 'config'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("the old config row is left: %d %v", n, err)
	}
	return out
}

const oldConfig = `INSERT INTO hp_config (key, value, updated_at, updated_by) VALUES ('config', '{"secondary_ip":"192.168.10.240","hostname":"FILESRV-OLD"}', '2026-11-01T09:00:00.000Z', 'a')`

// oldApplied is the record of what the old core handed to the host.
func oldApplied(ips string) string {
	return `INSERT INTO hp_config (key, value, updated_at, updated_by) VALUES ('applied', '` + ips + `', '2026-11-01T09:00:00.000Z', 'system')`
}

// D-466 (8): the secondary IP becomes the first Trap IP with the traps that were on; each decoy a Trap IP of its preset with
// the preset's services that were on (none on: the preset's, switched off); no address answers a port it did not answer before.
func TestMigration0003TurnsTheSecondaryIPAndDecoysIntoTrapIPs(t *testing.T) {
	t.Parallel()
	got := migrateRows(t, migratedBefore(t), oldConfig, oldApplied(`["192.168.10.240","192.168.10.241","192.168.10.242","192.168.10.243"]`),
		`UPDATE hp_trap SET enabled = 1, since = '2026-11-01T09:00:00.000Z' WHERE service IN ('ssh', 'smb')`,
		`INSERT INTO hp_decoys (id, personality, name, ip, enabled, created_at) VALUES
			('dec-nas', 'nas', 'NAS-OLD', '192.168.10.241', 1, '2026-11-01T08:00:00.000Z'),
			('dec-lnx', 'linux', 'LNX-OLD', '192.168.10.242', 1, '2026-11-02T08:00:00.000Z'),
			('dec-prn', 'printer', 'PRN-OLD', '192.168.10.243', 1, '2026-11-03T08:00:00.000Z'),
			('dec-off', 'windows_fs', 'FS-OFF', '192.168.10.244', 0, '2026-11-04T08:00:00.000Z')`)
	want := []tipRow{
		{ID: "tip-secondary", Name: "FILESRV-OLD", IP: "192.168.10.240", Preset: "custom", Services: `["smb","ssh"]`, Enabled: true},
		{ID: "dec-nas", Name: "NAS-OLD", IP: "192.168.10.241", Preset: "nas", Services: `["smb"]`, Enabled: true},
		{ID: "dec-lnx", Name: "LNX-OLD", IP: "192.168.10.242", Preset: "linux", Services: `["ssh"]`, Enabled: true},
		{ID: "dec-prn", Name: "PRN-OLD", IP: "192.168.10.243", Preset: "printer", Services: `["http"]`, Enabled: false},
		{ID: "dec-off", Name: "FS-OFF", IP: "192.168.10.244", Preset: "file_server", Services: `["smb"]`, Enabled: false},
	}
	if len(got) != len(want) {
		t.Fatalf("%d rows: %+v", len(got), got)
	}
	for i, w := range want {
		g := got[i]
		if g.ID != w.ID || g.Name != w.Name || g.IP != w.IP || g.Preset != w.Preset || g.Services != w.Services || g.Enabled != w.Enabled || g.Vendor != nil {
			t.Errorf("row %d: %+v, want %+v", i, g, w)
		}
	}
	if got[0].Created >= got[1].Created {
		t.Fatalf("the secondary IP is not the first Trap IP: %s vs %s", got[0].Created, got[1].Created)
	}
}

// With every trap off the secondary IP becomes a File server that is off; a decoy without a secondary IP never listened and is off.
func TestMigration0003WithNothingOn(t *testing.T) {
	t.Parallel()
	got := migrateRows(t, migratedBefore(t), oldConfig,
		`INSERT INTO hp_decoys (id, personality, name, ip, enabled, created_at) VALUES ('dec-lnx', 'linux', 'LNX-OLD', '192.168.10.242', 1, '2026-11-02T08:00:00.000Z')`)
	if len(got) != 2 || got[0].Preset != "file_server" || got[0].Services != `["smb","rdp"]` || got[0].Enabled || got[1].Services != `["ssh"]` || got[1].Enabled {
		t.Fatalf("%+v", got)
	}
	got = migrateRows(t, migratedBefore(t),
		`UPDATE hp_trap SET enabled = 1 WHERE service = 'ssh'`,
		`INSERT INTO hp_decoys (id, personality, name, ip, enabled, created_at) VALUES ('dec-lnx', 'linux', 'LNX-OLD', '192.168.10.242', 1, '2026-11-02T08:00:00.000Z')`)
	if len(got) != 1 || got[0].ID != "dec-lnx" || got[0].Services != `["ssh"]` || got[0].Enabled {
		t.Fatalf("a decoy without a secondary IP: %+v", got)
	}
}

// B2 review: a decoy listened only when the old core handed the secondary IP and its own address to the host. When the secondary
// IP clashed (a device, the box, outside the LAN) nothing was handed over, so after the upgrade the decoys are off, not newly
// answering; a decoy whose own address the host never took is off too. The migration reads the "applied" record for this.
func TestMigration0003LeavesOffWhatNeverListened(t *testing.T) {
	t.Parallel()
	decoys := `INSERT INTO hp_decoys (id, personality, name, ip, enabled, created_at) VALUES
		('dec-nas', 'nas', 'NAS-OLD', '192.168.10.241', 1, '2026-11-01T08:00:00.000Z'),
		('dec-lnx', 'linux', 'LNX-OLD', '192.168.10.242', 1, '2026-11-02T08:00:00.000Z')`
	on := `UPDATE hp_trap SET enabled = 1 WHERE service IN ('ssh', 'smb')`
	enabled := func(rows []tipRow) map[string]bool {
		m := map[string]bool{}
		for _, r := range rows {
			m[r.ID] = r.Enabled
		}
		return m
	}
	// The secondary IP was in conflict: the old core handed nothing over.
	if got := enabled(migrateRows(t, migratedBefore(t), oldConfig, oldApplied(`[]`), on, decoys)); got["dec-nas"] || got["dec-lnx"] {
		t.Fatalf("decoys of a secondary IP in conflict were switched on: %v", got)
	}
	// No record at all (an install that never applied): off.
	if got := enabled(migrateRows(t, migratedBefore(t), oldConfig, on, decoys)); got["dec-nas"] || got["dec-lnx"] {
		t.Fatalf("decoys without an applied record were switched on: %v", got)
	}
	// The secondary IP and one decoy were held; the other decoy the host refused.
	got := enabled(migrateRows(t, migratedBefore(t), oldConfig, oldApplied(`["192.168.10.240","192.168.10.242"]`), on, decoys))
	if !got["dec-lnx"] || got["dec-nas"] || !got["tip-secondary"] {
		t.Fatalf("only what the host held stays on: %v", got)
	}
}

// W1-14: the host is asked to build a File server with the vendor's MAC prefix and only its own ports.
func TestTheHostGetsTheVendorPrefixAndOnlyTheTrapIPsPorts(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	if _, err := e.svc.AddTrapIP(e.ctx(), "a", honeypot.TrapIPInput{Name: "FILESRV-OLD", IP: "192.168.10.240", Preset: honeypot.FileServer, Vendor: ptr("dell"),
		Services: []honeypot.ServiceName{honeypot.RDP, honeypot.SMB}}); err != nil {
		t.Fatal(err)
	}
	e.addTrapIP("BUILD-01", "192.168.10.241", honeypot.Linux, honeypot.SSH)
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	fs := e.host.specs[addr("192.168.10.240")]
	if fs.OUI != "f8bc12" || !slices.Equal(fs.Ports, []honeypot.Port{{Proto: "tcp", Port: 445}, {Proto: "tcp", Port: 3389}}) {
		t.Fatalf("file server spec %+v", fs)
	}
	if l := e.host.specs[addr("192.168.10.241")]; l.OUI != "" || !slices.Equal(l.Ports, []honeypot.Port{{Proto: "tcp", Port: 22}}) {
		t.Fatalf("linux spec %+v", l)
	}
}

// viewHost says how it holds the addresses and whether it keeps each to its own ports.
type viewHost struct {
	*fakeHost
	keeps bool
}

func (h viewHost) DecoyLinks(context.Context) map[netip.Addr]honeypot.DecoyLink {
	return map[netip.Addr]honeypot.DecoyLink{addr("192.168.10.240"): {MAC: "f8:bc:12:4f:54:67", Link: "vdhc0a80af0", Parent: "eno1"}}
}
func (h viewHost) KeepsPorts(context.Context) bool { return h.keeps }

// The Trap IPs tab shows where each Trap IP lives: MAC and the vendor its prefix shows, the link and card, the services
// that answer now, the last hit.
func TestTrapIPShowsWhereItLives(t *testing.T) {
	t.Parallel()
	for _, keeps := range []bool{true, false} {
		e := newEnv(t)
		e.cfg.Host = viewHost{fakeHost: e.host, keeps: keeps}
		svc, err := honeypot.New(e.cfg)
		if err != nil {
			t.Fatal(err)
		}
		e.svc = svc
		fsrv, err := e.svc.AddTrapIP(e.ctx(), "a", honeypot.TrapIPInput{Name: "FILESRV-OLD", IP: "192.168.10.240", Preset: honeypot.FileServer, Vendor: ptr("dell"),
			Services: []honeypot.ServiceName{honeypot.SMB, honeypot.RDP}})
		if err != nil {
			t.Fatal(err)
		}
		e.addTrapIP("BUILD-01", "192.168.10.241", honeypot.Linux, honeypot.SSH)
		if d := e.trapIP(fsrv.ID); d.MAC != nil || d.Attachment != nil || len(d.OpenServices) != 0 || d.LastHitAt != nil {
			t.Fatalf("before the host holds it: %+v", d)
		}
		if err := e.svc.Apply(e.ctx()); err != nil {
			t.Fatal(err)
		}
		d := e.trapIP(fsrv.ID)
		if d.MAC == nil || *d.MAC != "f8:bc:12:4f:54:67" || d.MACVendor == nil || !strings.Contains(strings.ToLower(*d.MACVendor), "dell") {
			t.Fatalf("keeps=%v: mac %v vendor %v", keeps, d.MAC, d.MACVendor)
		}
		if d.Attachment == nil || *d.Attachment != (honeypot.Attachment{Kind: "macvlan", Link: "vdhc0a80af0", Parent: "eno1"}) {
			t.Fatalf("attachment %+v", d.Attachment)
		}
		want := []honeypot.ServiceName{honeypot.SMB, honeypot.RDP}
		if !keeps { // an older host: the address answers every service the container runs
			want = []honeypot.ServiceName{honeypot.SMB, honeypot.RDP, honeypot.SSH}
			if d.Reason == nil || !strings.Contains(*d.Reason, "older") {
				t.Fatalf("no note on an older host: %v", d.Reason)
			}
		}
		if !slices.Equal(d.OpenServices, want) || d.DeviceID != nil {
			t.Fatalf("keeps=%v: open %v, device %v", keeps, d.OpenServices, d.DeviceID)
		}
		e.appendLog(ln{LogType: 14001, Src: "192.168.10.157", SrcPort: 7, Dst: "192.168.10.240", DstPort: 3389, At: t0, Data: map[string]any{"USERNAME": "admin"}}.json())
		e.poll()
		if d := e.trapIP(fsrv.ID); d.LastHitAt == nil || *d.LastHitAt != "2026-11-09T10:00:00.000Z" {
			t.Fatalf("last hit %v", d.LastHitAt)
		}
	}
}

func httpGet(src string, sport int, dst string, at time.Time) ln {
	return ln{LogType: 3000, Src: src, SrcPort: sport, Dst: dst, DstPort: 80, At: at, Data: map[string]any{"PATH": "/", "USERAGENT": "curl/8"}}
}

// sweepEnv has three Trap IPs: FILESRV-OLD .240 (SSH, SMB), NAS-ARCHIVE .241 and PRN-FLOOR2 .242 (HTTP), applied.
func sweepEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.setup()
	e.addTrapIP("NAS-ARCHIVE", "192.168.10.241", honeypot.NAS, honeypot.HTTP, honeypot.SMB)
	e.addTrapIP("PRN-FLOOR2", "192.168.10.242", honeypot.Printer, honeypot.HTTP)
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	return e
}

func hitsOfKind(t *testing.T, e *env, k honeypot.HitKind) []honeypot.Hit {
	t.Helper()
	l, err := e.svc.Hits(e.ctx(), honeypot.HitFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var out []honeypot.Hit
	for _, h := range l {
		if h.Kind == k {
			out = append(out, h)
		}
	}
	return out
}

// D-466 (5), W1-13: each hit names the Trap IP that was hit, in the list, the detail and the event.
func TestHitNamesTheTrapIPThatWasHit(t *testing.T) {
	t.Parallel()
	e := sweepEnv(t)
	e.appendLog(httpGet("192.168.10.157", 1, "192.168.10.241", t0).json(), sshNew("192.168.10.158", 2, t0).json())
	e.poll()
	got := map[string]string{}
	for _, h := range hitsOfKind(t, e, honeypot.KindService) {
		got[h.TrapIP] = h.TrapHostname
		d, err := e.svc.HitDetail(e.ctx(), h.ID)
		if err != nil || d.TrapIP != h.TrapIP || d.TrapHostname != h.TrapHostname {
			t.Fatalf("detail %+v %v", d, err)
		}
	}
	if len(got) != 2 || got["192.168.10.241"] != "NAS-ARCHIVE" || got["192.168.10.240"] != "FILESRV-OLD" {
		t.Fatalf("trap IPs of the hits: %v", got)
	}
	decoys := map[string]bool{}
	for _, ev := range e.pub.all() {
		decoys[ev.Data.(honeypot.HitEventData).Decoy] = true
	}
	if len(decoys) != 2 || !decoys["NAS-ARCHIVE"] || !decoys["FILESRV-OLD"] {
		t.Fatalf("event decoys %v", decoys)
	}
}

// W1-13: one source touching two Trap IPs within a minute raises one scan hit (one event); a third Trap IP in the same
// window joins it.
func TestTouchingTwoTrapIPsWithinAMinuteIsOneScan(t *testing.T) {
	t.Parallel()
	e := sweepEnv(t)
	src := "192.168.10.107"
	e.appendLog(httpGet(src, 1, "192.168.10.241", t0).json(), sshNew(src, 2, t0.Add(20*time.Second)).json())
	e.poll()
	scans := hitsOfKind(t, e, honeypot.KindScan)
	if len(scans) != 1 || len(hitsOfKind(t, e, honeypot.KindService)) != 2 {
		t.Fatalf("scans %+v", scans)
	}
	sc := scans[0]
	if sc.Label != "Scan across the Trap IPs" || sc.SrcIP != src || sc.IsTest || sc.TrapHostname != "FILESRV-OLD, NAS-ARCHIVE" ||
		!strings.Contains(sc.Excerpt, "FILESRV-OLD (192.168.10.240)") || !strings.Contains(sc.Excerpt, "NAS-ARCHIVE (192.168.10.241)") {
		t.Fatalf("%+v", sc)
	}
	var scanEvents []honeypot.HitEventData
	for _, ev := range e.pub.all() {
		if d := ev.Data.(honeypot.HitEventData); d.Kind == honeypot.KindScan {
			scanEvents = append(scanEvents, d)
		}
	}
	if len(scanEvents) != 1 || scanEvents[0].SrcAssetID != "a-pc07" || scanEvents[0].SrcName != "PC-HR-01" || scanEvents[0].Decoy != "FILESRV-OLD, NAS-ARCHIVE" {
		t.Fatalf("scan events %+v", scanEvents)
	}
	// a third Trap IP in the same window: the same scan hit, no new event
	e.appendLog(httpGet(src, 3, "192.168.10.242", t0.Add(40*time.Second)).json())
	e.poll()
	if scans = hitsOfKind(t, e, honeypot.KindScan); len(scans) != 1 || !strings.Contains(scans[0].Excerpt, "PRN-FLOOR2 (192.168.10.242)") ||
		scans[0].TrapHostname != "FILESRV-OLD, NAS-ARCHIVE, PRN-FLOOR2" || scans[0].TrapIP != "192.168.10.240, 192.168.10.241, 192.168.10.242" {
		t.Fatalf("after a third Trap IP (the Trap IP column names all three): %+v", scans)
	}
	n := 0
	for _, ev := range e.pub.all() {
		if ev.Data.(honeypot.HitEventData).Kind == honeypot.KindScan {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d scan events", n)
	}
}

// Touches two minutes apart, the same Trap IP twice, or a test hit and a touch are no scan.
func TestNoScanWithoutTwoTrapIPsInAMinute(t *testing.T) {
	t.Parallel()
	e := sweepEnv(t)
	e.appendLog(httpGet("192.168.10.157", 1, "192.168.10.241", t0).json(), sshNew("192.168.10.157", 2, t0.Add(2*time.Minute)).json())
	e.appendLog(httpGet("192.168.10.158", 1, "192.168.10.241", t0).json(), httpGet("192.168.10.158", 2, "192.168.10.241", t0.Add(10*time.Second)).json())
	e.poll()
	if _, err := e.svc.TestHit(e.ctx(), "op", honeypot.HTTP); err != nil {
		t.Fatal(err)
	}
	e.appendLog(sshNew("192.168.10.2", 9, t0.Add(3*time.Minute)).json()) // the box itself (INV-3)
	e.poll()
	if scans := hitsOfKind(t, e, honeypot.KindScan); len(scans) != 0 {
		t.Fatalf("scans %+v", scans)
	}
}

// gatewayHost knows the box's default gateway.
type gatewayHost struct{ *fakeHost }

func (gatewayHost) Gateway(context.Context) netip.Addr { return addr("192.168.10.1") }

// B2 review: the router's address is refused when the Trap IP is added, changed or switched on (ip_is_gateway), not a minute
// later as a conflict after the host refused it.
func TestTheGatewayIsNoTrapIP(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(e *env) { e.cfg.Host = gatewayHost{e.host} })
	in := honeypot.TrapIPInput{Name: "ROUTER-2", IP: "192.168.10.1", Preset: honeypot.Linux, Services: []honeypot.ServiceName{honeypot.SSH}}
	if _, err := e.svc.AddTrapIP(e.ctx(), "a", in); apiCode(t, err) != "ip_is_gateway" {
		t.Fatalf("add: %v", err)
	}
	tip := e.addTrapIP("LNX-01", "192.168.10.241", honeypot.Linux, honeypot.SSH)
	if _, err := e.svc.EditTrapIP(e.ctx(), "a", tip.ID, in); apiCode(t, err) != "ip_is_gateway" {
		t.Fatalf("edit: %v", err)
	}
	if n := e.count(`SELECT count(*) FROM hp_trap_ips WHERE ip = '192.168.10.1'`); n != 0 {
		t.Fatalf("%d rows on the gateway", n)
	}
}

// B2 lab: a device row the inventory made from a Trap IP's own frames carries the decoy's MAC. It is no machine on the address:
// the Trap IP keeps listening, no device is named, and the MAC is remembered, so even after the address leaves the host the ghost
// does not hold the Trap IP in conflict. A row with another MAC is a real conflict.
func TestADeviceWithTheDecoysOwnMACIsNoConflict(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(e *env) { e.cfg.Host = viewHost{fakeHost: e.host, keeps: true} })
	tip, err := e.svc.AddTrapIP(e.ctx(), "a", honeypot.TrapIPInput{Name: "FILESRV-OLD", IP: "192.168.10.240", Preset: honeypot.FileServer, Vendor: ptr("dell"),
		Services: []honeypot.ServiceName{honeypot.SMB, honeypot.RDP}})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	ghost := dev("a-ghost", "192.168.10.240", "", "unknown")
	ghost.MAC = "f8:bc:12:4f:54:67" // viewHost's MAC for .240
	e.inv.add(ghost)
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	v, err := e.svc.TrapIPs(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if got := v.Items[0]; got.State != honeypot.StateListening || got.DeviceID != nil {
		t.Fatalf("a ghost of the decoy's own MAC: %+v", got)
	}
	// The address leaves the host (switched off and on again): the remembered MAC still marks the ghost.
	e.cfg.Host = e.host
	svc, err := honeypot.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetTrapIPEnabled(e.ctx(), "a", tip.ID, true); err != nil {
		t.Fatalf("switching on beside a ghost: %v", err)
	}
	// Another MAC at the address is a machine there.
	other := dev("a-real", "192.168.10.240", "REAL-PC", "pc")
	other.MAC = "aa:bb:cc:00:02:40"
	e.inv.add(other)
	if _, err := svc.SetTrapIPEnabled(e.ctx(), "a", tip.ID, true); apiCode(t, err) != "ip_in_use" {
		t.Fatalf("a real device on the address: %v", err)
	}
}

// touchHost records new connection attempts to the decoys, as vedette-host's set touched (B2 review M2).
type touchHost struct {
	*fakeHost
	list *[]honeypot.Touch
}

func (h touchHost) Touches(context.Context) ([]honeypot.Touch, error) {
	return slices.Clone(*h.list), nil
}

// B2 review M2 (lab: nmap -sS across the Trap IPs made no hit): the attempts the host records feed the sweep detection. Two Trap
// IPs within a minute are one scan hit and one event; one Trap IP alone, the box, a Trap IP as the source, or the same attempts
// read again make nothing new; a third Trap IP joins the same hit. No per-touch service hit comes from an attempt.
func TestHostRecordedAttemptsAreASweep(t *testing.T) {
	t.Parallel()
	var list []honeypot.Touch
	e := newEnv(t, func(e *env) { e.cfg.Host = touchHost{fakeHost: e.host, list: &list} })
	e.now = t0.Add(5 * time.Minute) // inside one 10-minute hit window (a sweep across a window edge is two hits, one incident)
	e.setup()
	e.addTrapIP("NAS-ARCHIVE", "192.168.10.241", honeypot.NAS, honeypot.HTTP, honeypot.SMB)
	e.addTrapIP("PRN-FLOOR2", "192.168.10.242", honeypot.Printer, honeypot.HTTP)
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	src := addr("192.168.10.145")
	touch := func(s, d string, ago time.Duration) honeypot.Touch {
		return honeypot.Touch{Src: addr(s), Dst: addr(d), At: e.now.Add(-ago)}
	}
	poll := func() {
		t.Helper()
		if err := e.svc.PollTouches(e.ctx()); err != nil {
			t.Fatal(err)
		}
	}
	scanEvents := func() int {
		n := 0
		for _, ev := range e.pub.all() {
			if ev.Data.(honeypot.HitEventData).Kind == honeypot.KindScan {
				n++
			}
		}
		return n
	}
	// One Trap IP, the box itself, a Trap IP as the source: nothing.
	list = []honeypot.Touch{touch("192.168.10.145", "192.168.10.240", 30*time.Second), touch("192.168.10.2", "192.168.10.240", 20*time.Second),
		touch("192.168.10.2", "192.168.10.241", 20*time.Second), touch("192.168.10.241", "192.168.10.240", 10*time.Second)}
	poll()
	if n := len(hitsOfKind(t, e, honeypot.KindScan)); n != 0 || len(e.pub.all()) != 0 {
		t.Fatalf("%d scan hits, %d events from one Trap IP, the box and a Trap IP", n, len(e.pub.all()))
	}
	// A second Trap IP within the minute: one scan hit, one event, no service hit.
	list = append(list, touch("192.168.10.145", "192.168.10.241", 5*time.Second))
	poll()
	poll() // the same attempts read again
	scans := hitsOfKind(t, e, honeypot.KindScan)
	if len(scans) != 1 || scans[0].SrcIP != src.String() || scans[0].TrapHostname != "FILESRV-OLD, NAS-ARCHIVE" || scanEvents() != 1 {
		t.Fatalf("scan hits %+v, %d scan events", scans, scanEvents())
	}
	if n := len(hitsOfKind(t, e, honeypot.KindService)); n != 0 {
		t.Fatalf("%d service hits from attempts", n)
	}
	// A third Trap IP: the same hit names it, no new event.
	list = append(list, touch("192.168.10.145", "192.168.10.242", 0))
	poll()
	if scans = hitsOfKind(t, e, honeypot.KindScan); len(scans) != 1 || scans[0].TrapHostname != "FILESRV-OLD, NAS-ARCHIVE, PRN-FLOOR2" || scanEvents() != 1 {
		t.Fatalf("after a third Trap IP: %+v, %d events", scans, scanEvents())
	}
	// Module off: the host is not even asked.
	e.gate.turnOff()
	list = append(list, touch("192.168.10.146", "192.168.10.240", 0), touch("192.168.10.146", "192.168.10.241", 0))
	poll()
	if n := len(hitsOfKind(t, e, honeypot.KindScan)); n != 1 {
		t.Fatalf("%d scan hits while the module is off", n)
	}
}

// B2 review M2: a scan hit made from attempts that completed no handshake says the source may be forged, and such hits have a
// budget of their own (20 an hour): a flood of forged sources stops there and never uses up the listener hits' cap.
func TestAttemptScansHaveTheirOwnBudget(t *testing.T) {
	t.Parallel()
	var list []honeypot.Touch
	e := newEnv(t, func(e *env) { e.cfg.Host = touchHost{fakeHost: e.host, list: &list} })
	e.now = t0.Add(5 * time.Minute)
	e.setup()
	e.addTrapIP("NAS-ARCHIVE", "192.168.10.241", honeypot.NAS, honeypot.HTTP, honeypot.SMB)
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	for i := range 25 {
		src := fmt.Sprintf("192.168.10.%d", 150+i)
		list = append(list, honeypot.Touch{Src: addr(src), Dst: addr("192.168.10.240"), At: e.now.Add(-20 * time.Second)},
			honeypot.Touch{Src: addr(src), Dst: addr("192.168.10.241"), At: e.now.Add(-10 * time.Second)})
	}
	if err := e.svc.PollTouches(e.ctx()); err != nil {
		t.Fatal(err)
	}
	scans := hitsOfKind(t, e, honeypot.KindScan)
	if len(scans) != 20 || e.svc.Stats().Suppressed != 5 || !strings.Contains(scans[0].Excerpt, "may be forged") {
		t.Fatalf("%d scan hits, %d suppressed, excerpt %q", len(scans), e.svc.Stats().Suppressed, scans[0].Excerpt)
	}
	// A real connection still makes its hit.
	e.appendLog(sshNew("192.168.10.107", 50001, e.now).json())
	e.poll()
	if n := len(hitsOfKind(t, e, honeypot.KindService)); n != 1 {
		t.Fatalf("%d listener hits after the attempt budget ran out", n)
	}
}

// B2 review round 2 (H1, M1): while an address is being handed to the host its MAC is not known, and ExpectedMACs says "" for it
// (any frame there is the box for that moment); once the host gave it a MAC, that MAC; a Trap IP that is off is absent; TrapIPSince
// is when each was switched on.
func TestExpectedMACsAndSince(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(e *env) { e.cfg.Host = viewHost{fakeHost: e.host, keeps: true} })
	var during map[netip.Addr]string
	e.host.onAdd = func() { during = e.svc.ExpectedMACs(e.ctx()) }
	if _, err := e.svc.AddTrapIP(e.ctx(), "a", honeypot.TrapIPInput{Name: "FILESRV-OLD", IP: "192.168.10.240", Preset: honeypot.FileServer, Vendor: ptr("dell"),
		Services: []honeypot.ServiceName{honeypot.SMB}}); err != nil {
		t.Fatal(err)
	}
	off := e.addTrapIP("LNX-01", "192.168.10.241", honeypot.Linux, honeypot.SSH)
	if _, err := e.svc.SetTrapIPEnabled(e.ctx(), "a", off.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if m, ok := during[addr("192.168.10.240")]; !ok || m != "" {
		t.Fatalf("during the add: %v", during)
	}
	after := e.svc.ExpectedMACs(e.ctx())
	if after[addr("192.168.10.240")] != "f8:bc:12:4f:54:67" || len(after) != 1 {
		t.Fatalf("after the add: %v", after)
	}
	since := e.svc.TrapIPSince(e.ctx())
	if at := since[addr("192.168.10.240")]; at.IsZero() || at.After(e.now) || len(since) != 1 {
		t.Fatalf("since %v (now %v)", since, e.now)
	}
}

// W6-4: a scan hit the host's attempts made first says the source may be forged; once the same source completes a real
// connection to a Trap IP in that window, the note goes (its address answered a handshake, so it is not forged).
func TestARealConnectionDropsTheForgedNote(t *testing.T) {
	t.Parallel()
	var list []honeypot.Touch
	e := newEnv(t, func(e *env) { e.cfg.Host = touchHost{fakeHost: e.host, list: &list} })
	e.now = t0.Add(5 * time.Minute)
	e.setup()
	e.addTrapIP("NAS-ARCHIVE", "192.168.10.241", honeypot.NAS, honeypot.HTTP, honeypot.SMB)
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	list = []honeypot.Touch{{Src: addr("192.168.10.107"), Dst: addr("192.168.10.240"), At: e.now.Add(-20 * time.Second)},
		{Src: addr("192.168.10.107"), Dst: addr("192.168.10.241"), At: e.now.Add(-10 * time.Second)}}
	if err := e.svc.PollTouches(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if scans := hitsOfKind(t, e, honeypot.KindScan); len(scans) != 1 || !strings.Contains(scans[0].Excerpt, "may be forged") {
		t.Fatalf("scan hits from attempts: %+v", scans)
	}
	e.appendLog(sshNew("192.168.10.107", 50001, e.now.Add(-5*time.Second)).json())
	e.poll()
	scans := hitsOfKind(t, e, honeypot.KindScan)
	if len(scans) != 1 || strings.Contains(scans[0].Excerpt, "forged") || !strings.Contains(scans[0].Excerpt, "Touched FILESRV-OLD") {
		t.Fatalf("after a real connection: %+v", scans)
	}
}

// W6-4 (n24 walk): the real connection came first, to one Trap IP; the sweep was made later by the host's attempts. The address is
// proven by that connection, so the scan hit must not call it forged.
func TestAConnectionBeforeTheSweepKeepsTheForgedNoteOff(t *testing.T) {
	t.Parallel()
	var list []honeypot.Touch
	e := newEnv(t, func(e *env) { e.cfg.Host = touchHost{fakeHost: e.host, list: &list} })
	e.now = t0.Add(5 * time.Minute)
	e.setup()
	e.addTrapIP("NAS-ARCHIVE", "192.168.10.241", honeypot.NAS, honeypot.HTTP, honeypot.SMB)
	if err := e.svc.Apply(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.appendLog(sshNew("192.168.10.107", 50001, e.now.Add(-30*time.Second)).json())
	e.poll()
	if scans := hitsOfKind(t, e, honeypot.KindScan); len(scans) != 0 {
		t.Fatalf("one Trap IP is no sweep: %+v", scans)
	}
	list = []honeypot.Touch{{Src: addr("192.168.10.107"), Dst: addr("192.168.10.240"), At: e.now.Add(-20 * time.Second)},
		{Src: addr("192.168.10.107"), Dst: addr("192.168.10.241"), At: e.now.Add(-10 * time.Second)}}
	if err := e.svc.PollTouches(e.ctx()); err != nil {
		t.Fatal(err)
	}
	scans := hitsOfKind(t, e, honeypot.KindScan)
	if len(scans) != 1 || strings.Contains(scans[0].Excerpt, "forged") {
		t.Fatalf("a sweep after a real connection: %+v", scans)
	}
}
