package sensoractive_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/core/secrets"
	sa "github.com/knt048/vedette/modules/sensor-active"
)

// SNMP set up per device. A secret goes only to its device's read address; Copy from copies on the box; a device that moves
// away from a read address left to its IP is not followed; the settings go with a deleted device and move with a merged one; the
// old credentials are moved to the devices they covered, once.

// secretOf opens the saved secret of a device (column secret_id or priv_secret_id).
func (w *snmpWorld) secretOf(asset, column string) (id, plain string) {
	w.t.Helper()
	ctx := w.t.Context()
	if err := w.db.Reader().QueryRowContext(ctx, `SELECT `+column+` FROM sa_snmp_device WHERE asset_id = ?`, asset).Scan(&id); err != nil {
		w.t.Fatal(err)
	}
	purpose := "sa_snmp.secret"
	if column == "priv_secret_id" {
		purpose = "sa_snmp.priv"
	}
	b, err := w.sec.Open(ctx, w.db.Reader(), id, purpose)
	if err != nil {
		w.t.Fatal(err)
	}
	return id, string(b)
}

// loseSecret seals the saved secret of device asset again under another master key, as a restore without the key leaves it.
func (w *snmpWorld) loseSecret(asset, column string) {
	w.t.Helper()
	other, err := secrets.New(bytes.Repeat([]byte{7}, secrets.KeySize))
	if err != nil {
		w.t.Fatal(err)
	}
	ctx := w.t.Context()
	err = w.db.Write(ctx, func(tx *sql.Tx) error {
		var sid, purpose string
		if err := tx.QueryRowContext(ctx, `SELECT s.id, s.purpose FROM sa_snmp_device d JOIN core_secret s ON s.id = d.`+column+` WHERE d.asset_id = ?`, asset).Scan(&sid, &purpose); err != nil {
			return err
		}
		_, err := other.Replace(ctx, tx, sid, purpose, []byte("sealed-elsewhere"), true)
		return err
	})
	if err != nil {
		w.t.Fatal(err)
	}
}

// a secret is only ever sent to its device's read address. The job builder refuses a target at any other address, before a
// secret is opened, even when every other check passed; the target at the read address is built.
func TestSNMPTheJobRefusesAnyAddressButTheDevicesReadAddress(t *testing.T) {
	t.Parallel()
	w := newSNMPWorld(t, &fakeReader{})
	in := v2c("s3cret-community")
	in.ReadFrom = "192.168.10.40"
	w.set("a-sw", in)
	for _, at := range []string{"192.168.10.20", "192.168.10.24", "192.168.10.41"} { // its own IP, another device, a stranger
		job, err := sa.SNMPJobAt(t.Context(), w.svc, "a-sw", netip.MustParseAddr(at))
		if !errors.Is(err, sa.ErrSNMPNotReadAddress) || len(job.Targets) != 0 {
			t.Errorf("%s: %v, %d targets; want refused with nothing built", at, err, len(job.Targets))
		}
	}
	job, err := sa.SNMPJobAt(t.Context(), w.svc, "a-sw", netip.MustParseAddr("192.168.10.40"))
	if err != nil || len(job.Targets) != 1 || job.Targets[0].IP != "192.168.10.40" || job.Targets[0].Credential.Community != "s3cret-community" {
		t.Fatalf("the read address: %v %+v", err, job.Targets)
	}
}

// Copy from copies another device's settings and secrets on the box. Nothing returned holds the secret; the copy is the
// device's own (another secret row: editing one never changes the other); the audit row says where it was copied from, never the
// secret; a source whose secret this box cannot open is refused.
func TestSNMPCopyFromNeverReturnsTheSecret(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	ctx := t.Context()
	w.set("a-sw", sa.SNMPInput{Version: "v3", Username: "ro", Auth: "sha256", AuthPassword: secrets.NewValue("auth-pass-1"), Priv: "aes128",
		PrivPassword: secrets.NewValue("priv-pass-1"), Port: 1161})
	d, err := w.svc.SetSNMP(ctx, "admin@example.com", "a-printer", sa.SNMPInput{CopyFrom: "a-sw"})
	if err != nil || d.Version != "v3" || d.Username != "ro" || d.Auth != "sha256" || d.Priv != "aes128" || d.Port != 1161 || d.SecretLast4 != "ss-1" ||
		d.ReadFrom != netip.MustParseAddr("192.168.10.24") {
		t.Fatalf("copy: %v %+v", err, d)
	}
	b, _ := json.Marshal(d)
	list, _ := w.svc.SNMPDevices(ctx)
	lb, _ := json.Marshal(list)
	for _, s := range []string{string(b), string(lb)} {
		if strings.Contains(s, "auth-pass-1") || strings.Contains(s, "priv-pass-1") {
			t.Fatalf("a secret is in what the service returns: %s", s)
		}
	}
	srcID, srcPlain := w.secretOf("a-sw", "secret_id")
	cpID, cpPlain := w.secretOf("a-printer", "secret_id")
	if _, pp := w.secretOf("a-printer", "priv_secret_id"); srcID == cpID || srcPlain != "auth-pass-1" || cpPlain != "auth-pass-1" || pp != "priv-pass-1" {
		t.Fatalf("the copy is not the device's own: %s/%s %q %q %q", srcID, cpID, srcPlain, cpPlain, pp)
	}
	if n := w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.snmp_set' AND detail LIKE '%copied from device a-sw' AND detail NOT LIKE '%pass%'`); n != 1 {
		t.Errorf("%d audit rows of the copy", n)
	}
	w.set("a-sw", sa.SNMPInput{Version: "v3", Username: "ro", Auth: "sha256", AuthPassword: secrets.NewValue("auth-pass-2"), Priv: "aes128",
		PrivPassword: secrets.NewValue("priv-pass-2")})
	if _, plain := w.secretOf("a-printer", "secret_id"); plain != "auth-pass-1" {
		t.Fatal("editing the source changed the copy")
	}
	// The copied device is read with its own settings at its own address.
	if res, err := w.svc.CheckSNMP(ctx, "a", "a-printer"); err != nil || !res.OK {
		t.Fatalf("check the copy: %v %+v", err, res)
	}
	if j := r.sent(); len(j) != 1 || j[0].Targets[0].IP != "192.168.10.24" || j[0].Targets[0].Credential.AuthPass != "auth-pass-1" || j[0].Targets[0].Credential.Port != 1161 {
		t.Fatalf("job %+v", j)
	}
	w.loseSecret("a-sw", "secret_id")
	if _, err := w.svc.SetSNMP(ctx, "a", "a-printer", sa.SNMPInput{CopyFrom: "a-sw"}); apiCode(err) != "secret_lost" {
		t.Fatalf("copy of a lost secret: %v", err)
	}
}

// #868, a device whose saved secret is sealed under another master key is sent nothing: Check now answers 409 secret_lost,
// the round skips it and reads the others, the device says so; an edit that types it again fixes it.
func TestSNMPADeviceWhoseSecretWasNotRestoredSendsNothing(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	ctx := t.Context()
	w.set("a-sw", v2c("s3cret-community"))
	w.set("a-printer", v2c("community-2"))
	w.loseSecret("a-sw", "secret_id")
	_, err := w.svc.CheckSNMP(ctx, "a", "a-sw")
	var e *apierr.Error
	if !errors.As(err, &e) || e.Status != 409 || e.Code != "secret_lost" || !strings.Contains(e.Message, "not restored") {
		t.Fatalf("check: %v", err)
	}
	if d, _ := w.svc.SNMPDeviceOf(ctx, "a-sw"); !d.SecretLost || d.Blocked == nil || d.Blocked.Reason != "secret_lost" {
		t.Fatalf("the device does not say it: %+v", d)
	}
	if _, err := w.svc.SetSNMP(ctx, "a", "a-sw", v2c("")); apiCode(err) != "secret_lost" {
		t.Fatalf("an edit keeping the lost secret: %v", err)
	}
	if err := w.svc.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if jobs := r.sent(); len(jobs) != 1 || !slices.Equal(ipsOf(jobs[0]), []string{"192.168.10.24"}) {
		t.Fatalf("the round read %+v", jobs)
	}
	if d := w.set("a-sw", v2c("community-new")); d.SecretLost || d.Blocked != nil {
		t.Fatalf("typed again: %+v", d)
	}
}

// #829 C4, a device whose read address was left to its IP and that then moves is not followed (a copied network card looks
// the same): nothing is sent, the device and the check say where it is and what to do. A read address the person typed stays as it
// is when the device's IP changes.
func TestSNMPADeviceThatMovedIsNotFollowed(t *testing.T) {
	t.Parallel()
	r := &fakeReader{}
	w := newSNMPWorld(t, r)
	ctx := t.Context()
	w.set("a-sw", v2c("s3cret-community"))
	mgmt := v2c("community-2")
	mgmt.ReadFrom = "192.168.10.50"
	w.set("a-printer", mgmt)
	w.inv.moveTo("a-sw", "192.168.10.33")
	w.inv.moveTo("a-printer", "192.168.10.34")
	res, err := w.svc.CheckSNMP(ctx, "a", "a-sw")
	if err != nil || res.Reason != "moved" || !strings.Contains(res.Message, "is now at 192.168.10.33") || !strings.Contains(res.Message, "set Read from to 192.168.10.33") {
		t.Fatalf("moved: %v %+v", err, res)
	}
	if d, _ := w.svc.SNMPDeviceOf(ctx, "a-sw"); d.Blocked == nil || d.Blocked.Reason != "moved" {
		t.Fatalf("the device does not say it moved: %+v", d)
	}
	if res, err := w.svc.CheckSNMP(ctx, "a", "a-printer"); err != nil || !res.OK {
		t.Fatalf("a typed read address after a move: %v %+v", err, res)
	}
	if jobs := r.sent(); len(jobs) != 1 || jobs[0].Targets[0].IP != "192.168.10.50" {
		t.Fatalf("jobs %+v", jobs)
	}
	// Set again at the new address (the secret typed again): read there.
	at := v2c("s3cret-community")
	at.ReadFrom = "192.168.10.33"
	if d := w.set("a-sw", at); d.Blocked != nil || !d.ReadFromDefault {
		t.Fatalf("set again: %+v", d)
	}
}

// a device's SNMP goes with the device (lifecycle DeviceDeleted) and moves with a merge (lifecycle DeviceMerged) when the
// device kept has none; otherwise, neither having answered, the kept device's own stays and the other's goes, secrets included.
func TestSNMPSettingsFollowDeletedAndMergedDevices(t *testing.T) {
	t.Parallel()
	w := newSNMPWorld(t, &fakeReader{})
	w.set("a-sw", v2c("community-1"))
	w.set("a-printer", v2c("community-2"))
	w.set("a-never", v2c("community-3"))
	mergeDevices(t, w.db, w.svc, lifecycle.Merge{From: "a-sw", Into: "a-new"}) // a-new has none: a-sw's become a-new's
	if w.count(`SELECT count(*) FROM sa_snmp_device WHERE asset_id = 'a-new' AND read_from = '192.168.10.20'`) != 1 || w.count(`SELECT count(*) FROM sa_snmp_device WHERE asset_id = 'a-sw'`) != 0 {
		t.Fatal("the settings did not move with the merge")
	}
	mergeDevices(t, w.db, w.svc, lifecycle.Merge{From: "a-printer", Into: "a-never"}) // both have some, none answered: a-never keeps its own
	if _, plain := w.secretOf("a-never", "secret_id"); plain != "community-3" || w.count(`SELECT count(*) FROM sa_snmp_device WHERE asset_id = 'a-printer'`) != 0 {
		t.Fatal("the kept device lost its own settings, or the other's stayed")
	}
	deleteDevice(t, w.db, w.svc, "a-never")
	if w.count(`SELECT count(*) FROM sa_snmp_device`) != 1 || w.count(`SELECT count(*) FROM core_secret`) != 1 {
		t.Fatalf("after the delete: %d settings, %d secrets", w.count(`SELECT count(*) FROM sa_snmp_device`), w.count(`SELECT count(*) FROM core_secret`))
	}
}

// legacy writes a credential of the old kind (sa_snmp, its secret sealed as it was) and returns its id.
func (w *snmpWorld) legacy(id, name, community, scope, lastAnswer string) {
	w.t.Helper()
	ctx := w.t.Context()
	err := w.db.Write(ctx, func(tx *sql.Tx) error {
		sid, last4, err := w.sec.Seal(ctx, tx, "sa_snmp.secret", []byte(community), true)
		if err != nil {
			return err
		}
		var la any
		if lastAnswer != "" {
			la = lastAnswer
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO sa_snmp (id, name, version, secret_id, secret_last4, scope, created_at, updated_at, last_answer_at)
			VALUES (?, ?, 'v2c', ?, ?, ?, ?, ?, ?)`, id, name, sid, last4, scope, "2026-11-0"+id[len(id)-1:]+"T00:00:00.000Z", "2026-11-01T00:00:00.000Z", la)
		return err
	})
	if err != nil {
		w.t.Fatal(err)
	}
}

func (w *snmpWorld) legacyAnswer(cred, asset, ip, at string) {
	w.t.Helper()
	ctx := w.t.Context()
	if err := w.db.Write(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO sa_snmp_answer (credential_id, asset_id, ip, answered_at, sys_descr) VALUES (?, ?, ?, ?, 'Juniper EX4200')`, cred, asset, ip, at)
		return err
	}); err != nil {
		w.t.Fatal(err)
	}
}

// The migration: each device covered by a credential's scope that has SNMP readings (an answer kept, or an SNMP observation) or its
// SNMP switch stored on gets its own copy, read at its IP; several credentials: the one it answered last, else the one that answered
// last, else the first tried. A credential that covers no such device is deleted. Every credential is then gone with its secrets
// and answers; a notice and an audit row per credential say what happened; it runs once.
func TestSNMPCredentialsMoveToTheDevicesTheyCovered(t *testing.T) {
	t.Parallel()
	w := newSNMPWorld(t, &fakeReader{})
	ctx := t.Context()
	w.legacy("snmp-1", "all", "community-1", `["192.168.10.0/26"]`, "2026-11-10T00:00:00.000Z")
	w.legacy("snmp-2", "switch", "community-2", `["192.168.10.20"]`, "2026-11-09T00:00:00.000Z")
	w.legacy("snmp-3", "printers", "community-3", `["192.168.10.24","192.168.10.30"]`, "2026-11-12T00:00:00.000Z")
	w.legacy("snmp-4", "nobody", "community-4", `["192.168.10.50"]`, "")
	w.legacy("snmp-5", "far", "community-5", `["10.9.9.0/24"]`, "")
	w.legacy("snmp-6", "box", "community-6", `["192.168.10.2"]`, "2026-11-12T00:00:00.000Z")
	// a-sw answered "all" and later "switch": several credentials on one device, the one it answered last wins.
	w.legacyAnswer("snmp-1", "a-sw", "192.168.10.20", "2026-11-10T00:00:00.000Z")
	w.legacyAnswer("snmp-2", "a-sw", "192.168.10.20", "2026-11-11T00:00:00.000Z")
	w.inv.mu.Lock()
	w.inv.snmpRead = []string{"a-printer", "a-box"} // an SNMP observation, no answer row: "printers" answered last of all
	w.inv.snmpOn = []string{"a-far"}                // SNMP switched on by a person: "far" holds it
	w.inv.mu.Unlock()
	// a-new and a-never are covered by "all" but never answered nor were switched on: no copy.
	list, err := w.svc.SNMPDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range list {
		_, plain := w.secretOf(d.DeviceID, "secret_id")
		got[d.DeviceID] = plain + " @" + d.ReadFrom.String()
		if !d.ReadFromDefault {
			t.Errorf("%s: read address not the default", d.DeviceID)
		}
	}
	want := map[string]string{"a-sw": "community-2 @192.168.10.20", "a-printer": "community-3 @192.168.10.24", "a-far": "community-5 @10.9.9.9"}
	if len(got) != len(want) {
		t.Fatalf("copies %v, want %v", got, want)
	}
	for id, v := range want {
		if got[id] != v {
			t.Errorf("%s: %q, want %q", id, got[id], v)
		}
	}
	if d, _ := w.svc.SNMPDeviceOf(ctx, "a-sw"); d.State != sa.SNMPWorking || d.Answer == nil || d.Answer.SysDescr != "Juniper EX4200" {
		t.Errorf("a-sw keeps the answer it gave: %+v", d)
	}
	if n := w.count(`SELECT count(*) FROM sa_snmp`) + w.count(`SELECT count(*) FROM sa_snmp_answer`); n != 0 {
		t.Fatalf("%d rows of credentials or answers left", n)
	}
	if n := w.count(`SELECT count(*) FROM core_secret`); n != 3 {
		t.Fatalf("%d secrets, want the 3 copies (every credential's own gone)", n)
	}
	notices, err := w.svc.SNMPNotices(ctx)
	if err != nil || len(notices) != 6 {
		t.Fatalf("notices %v %+v", err, notices)
	}
	text := ""
	for _, n := range notices {
		text += n.Text + "\n"
	}
	for _, s := range []string{`"nobody" (v2c, scope 192.168.10.50) was removed: it covered no device`, `"switch" (v2c, scope 192.168.10.20) was copied to device a-sw (192.168.10.20)`,
		`"all" (v2c, scope 192.168.10.0/26) was removed`, `"box" (v2c, scope 192.168.10.2) was removed`} {
		if !strings.Contains(text, s) {
			t.Errorf("no notice says %q:\n%s", s, text)
		}
	}
	if strings.Contains(text, "community-") {
		t.Fatal("a notice holds a community")
	}
	if n := w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.snmp_move' AND detail NOT LIKE '%community-%'`); n != 6 {
		t.Errorf("%d audit rows of the move, want 6", n)
	}
	if err := w.svc.DismissSNMPNotices(ctx); err != nil {
		t.Fatal(err)
	}
	// Once: a credential written after the move (as an old export restored) is not moved again in this process; nothing else changes.
	if _, err := w.svc.SNMPDevices(ctx); err != nil || w.count(`SELECT count(*) FROM sa_snmp_notice`) != 0 {
		t.Fatalf("again: %v", err)
	}
}

// The migration: a credential whose secret this box cannot open gives no copy; its devices are named in the notice, and it is
// deleted like the others.
func TestSNMPACredentialWithALostSecretIsNotCopied(t *testing.T) {
	t.Parallel()
	w := newSNMPWorld(t, &fakeReader{})
	ctx := t.Context()
	w.legacy("snmp-1", "all", "community-1", `["192.168.10.0/26"]`, "")
	w.legacyAnswer("snmp-1", "a-sw", "192.168.10.20", "2026-11-10T00:00:00.000Z")
	other, err := secrets.New(bytes.Repeat([]byte{7}, secrets.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.db.Write(ctx, func(tx *sql.Tx) error {
		var sid string
		if err := tx.QueryRowContext(ctx, `SELECT secret_id FROM sa_snmp`).Scan(&sid); err != nil {
			return err
		}
		_, err := other.Replace(ctx, tx, sid, "sa_snmp.secret", []byte("sealed-elsewhere"), true)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if list, err := w.svc.SNMPDevices(ctx); err != nil || len(list) != 0 {
		t.Fatalf("%v %+v", err, list)
	}
	notices, _ := w.svc.SNMPNotices(ctx)
	if len(notices) != 1 || !strings.Contains(notices[0].Text, "could not be opened on this box") || !strings.Contains(notices[0].Text, "device a-sw (192.168.10.20)") {
		t.Fatalf("notices %+v", notices)
	}
	if w.count(`SELECT count(*) FROM sa_snmp`)+w.count(`SELECT count(*) FROM core_secret`) != 0 {
		t.Fatal("the credential or its secret stayed")
	}
}

// Copy from sends a saved secret only to the device's own address: with a Read from a person types, the secret must be typed
// (400 secret_required), as for an edit that changes the read address. Copied to the device's own IP, it is saved.
func TestSNMPCopyFromToAnotherAddressNeedsTheSecretTyped(t *testing.T) {
	t.Parallel()
	w := newSNMPWorld(t, &fakeReader{})
	ctx := t.Context()
	w.set("a-sw", v2c("s3cret-community"))
	if _, err := w.svc.SetSNMP(ctx, "a", "a-printer", sa.SNMPInput{CopyFrom: "a-sw", ReadFrom: "192.168.10.41"}); apiCode(err) != "secret_required" {
		t.Fatalf("copy to a typed address: %v, want secret_required", err)
	}
	if w.count(`SELECT count(*) FROM sa_snmp_device WHERE asset_id = 'a-printer'`) != 0 {
		t.Fatal("the refused copy was saved")
	}
	if d, err := w.svc.SetSNMP(ctx, "a", "a-printer", sa.SNMPInput{CopyFrom: "a-sw", ReadFrom: "192.168.10.24"}); err != nil || d.ReadFrom != netip.MustParseAddr("192.168.10.24") {
		t.Fatalf("copy to the device's own address: %v %+v", err, d)
	}
}

// One read address is one device's: a second device given it is refused with 409 read_from_taken, naming the first.
func TestSNMPAReadAddressBelongsToOneDevice(t *testing.T) {
	t.Parallel()
	w := newSNMPWorld(t, &fakeReader{})
	in := v2c("community-1")
	in.ReadFrom = "192.168.10.40"
	w.set("a-sw", in)
	_, err := w.svc.SetSNMP(t.Context(), "a", "a-printer", in)
	var e *apierr.Error
	if !errors.As(err, &e) || e.Status != 409 || e.Code != "read_from_taken" || !strings.Contains(e.Message, "device a-sw") {
		t.Fatalf("a second device on one read address: %v", err)
	}
	if _, err := w.svc.SetSNMP(t.Context(), "a", "a-printer", v2c("community-2")); err != nil {
		t.Fatalf("its own address: %v", err)
	}
}

// A save that is refused changes nothing: the device's SNMP switch is turned on only for a form that passes.
func TestSNMPARefusedSaveLeavesTheSwitchAlone(t *testing.T) {
	t.Parallel()
	w := newSNMPWorld(t, &fakeReader{})
	for _, in := range []sa.SNMPInput{v2c(""), {Version: "v2c", Community: secrets.NewValue("pub\nlic")}, {Version: "v1"}} {
		if _, err := w.svc.SetSNMP(t.Context(), "a", "a-sw", in); err == nil {
			t.Fatalf("%+v saved", in)
		}
	}
	w.inv.mu.Lock()
	on := slices.Clone(w.inv.turnedOn)
	w.inv.mu.Unlock()
	if len(on) != 0 {
		t.Fatalf("the switch was turned on for %v by refused saves", on)
	}
}

// The move never stops on one damaged credential: a secret row that is missing, one that cannot be opened for another reason, or a
// scope that cannot be read gives no copy and a notice; the move ends, and the SNMP calls answer after it.
func TestSNMPTheMoveFinishesWithDamagedCredentials(t *testing.T) {
	t.Parallel()
	w := newSNMPWorld(t, &fakeReader{})
	ctx := t.Context()
	w.legacy("snmp-1", "missing", "community-1", `["192.168.10.20"]`, "")
	w.legacy("snmp-2", "other purpose", "community-2", `["192.168.10.24"]`, "")
	w.legacy("snmp-3", "bad scope", "community-3", `[1, 2]`, "")
	w.legacy("snmp-4", "good", "community-4", `["192.168.10.23"]`, "")
	w.inv.mu.Lock()
	w.inv.snmpOn = []string{"a-sw", "a-printer", "a-never"}
	w.inv.mu.Unlock()
	if err := w.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM core_secret WHERE id = (SELECT secret_id FROM sa_snmp WHERE id = 'snmp-1')`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE core_secret SET purpose = 'something.else' WHERE id = (SELECT secret_id FROM sa_snmp WHERE id = 'snmp-2')`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	list, err := w.svc.SNMPDevices(ctx)
	if err != nil || len(list) != 1 || list[0].DeviceID != "a-never" {
		t.Fatalf("after the move: %v %+v", err, list)
	}
	if w.count(`SELECT count(*) FROM sa_snmp`) != 0 {
		t.Fatal("old credentials stayed")
	}
	notices, _ := w.svc.SNMPNotices(ctx)
	text := ""
	for _, n := range notices {
		text += n.Text + "\n"
	}
	for _, want := range []string{`"missing"`, `"other purpose"`, `"bad scope" (v2c, scope none readable) was removed`} {
		if !strings.Contains(text, want) {
			t.Errorf("no notice for %s:\n%s", want, text)
		}
	}
	if strings.Count(text, "could not be opened") != 2 {
		t.Errorf("want two could-not-be-opened notices:\n%s", text)
	}
	if _, err := w.svc.SNMPDeviceOf(ctx, "a-sw"); err != nil {
		t.Fatalf("a device's SNMP after the move: %v", err)
	}
	if err := w.svc.Tick(ctx); err != nil {
		t.Fatalf("a tick after the move: %v", err)
	}
}

// Logs matches an address to a device by the read address a person typed: a default read address (the device's IP at save time) is
// not one, and a device that moved does not keep its old address.
func TestSNMPReadAddressesAreOnlyWhatAPersonTyped(t *testing.T) {
	t.Parallel()
	w := newSNMPWorld(t, &fakeReader{})
	ctx := t.Context()
	w.set("a-sw", v2c("s3cret-community")) // read from its own IP
	typed := v2c("community-2")
	typed.ReadFrom = "192.168.10.50"
	w.set("a-printer", typed)
	w.inv.moveTo("a-sw", "192.168.10.33")
	got, err := w.svc.ReadAddresses(ctx)
	if err != nil || len(got) != 1 || got["a-printer"] != netip.MustParseAddr("192.168.10.50") {
		t.Fatalf("read addresses %v %v, want only a-printer at 192.168.10.50", got, err)
	}
}
