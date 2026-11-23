package inventory_test

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/core/lifecycle"
	"github.com/knt048/vedette/modules/inventory"
)

// A split tells the lifecycle participants, inside its write, where each software line of the device that stays went on the device split
// off when its readings took a line of a new id: a module that keeps rows by line (findings) moves them with the software. A folded
// line whose person's entry goes back is mapped, with Gone false: the kept device still reads the software by its scan.
func TestSplit_TellsTheLifecycleWhereTheSoftwareWent(t *testing.T) {
	t.Parallel()
	hooks := &lifecycle.Hooks{}
	var got []lifecycle.Split
	hooks.Register(lifecycle.Participant{Name: "test", DeviceSplit: func(ctx context.Context, tx *sql.Tx, s lifecycle.Split) error {
		var n int // inside the split's own write: the device split off is there
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM inv_asset WHERE id = ?`, s.Into).Scan(&n); err != nil || n != 1 {
			t.Errorf("the device split off in the hook's transaction: %d, %v", n, err)
		}
		got = append(got, s)
		return nil
	}})
	e := newEnv(t, func(c *inventory.Config) { c.Lifecycle = hooks })
	hand := e.addDevice(inventory.AddInput{Vendor: "VMware", Product: "ESXi", Version: "8.0.3 build 24022510", Name: "esxi-01", IP: "192.0.2.90"})
	e.tick(time.Minute)
	host := esxiHost(e)
	if err := e.svc.Merge(e.ctx(), admin, host, hand); err != nil {
		t.Fatal(err)
	}
	var folded string
	for _, s := range matchRows(t, e, host) {
		if s.Product == "esxi" || s.Product == "ESXi" {
			folded = s.ID
		}
	}
	back, err := e.svc.Split(e.ctx(), admin, host, "192.0.2.90")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].From != host || got[0].Into != back || got[0].Actor != admin {
		t.Fatalf("split hooks %+v, want one from %s into %s", got, host, back)
	}
	line, ok := got[0].Software[folded]
	if !ok || line.Gone || line.Into == "" || line.Into == folded {
		t.Fatalf("the folded ESXi line %s: %+v (all %+v)", folded, line, got[0].Software)
	}
	if !slices.ContainsFunc(matchRows(t, e, back), func(s inventory.MatchSoftware) bool { return s.ID == line.Into }) {
		t.Errorf("line %s is not the device split off's", line.Into)
	}
}

// MatchSoftware names the person who entered a version, and nobody for a source's reading.
func TestMatchInput_SetByIsThePersonsEntry(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	host := esxiHost(e)
	for _, s := range matchRows(t, e, host) {
		if s.SetBy != "" {
			t.Fatalf("a scan's reading set by %q", s.SetBy)
		}
	}
	id := matchRows(t, e, host)[0].ID
	e.tick(time.Minute)
	v := "8.0 U3e"
	if err := e.svc.EditSoftware(e.ctx(), "op@example.com", host, id, inventory.SoftwareEdit{Version: &v}); err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(matchRows(t, e, host), func(s inventory.MatchSoftware) bool { return s.ID == id && s.Source == "manual" })
	if i < 0 || matchRows(t, e, host)[i].SetBy != "op@example.com" {
		t.Fatalf("the person's entry: %+v", matchRows(t, e, host))
	}
}

// A line the merged device brought whole goes back whole with its id: the split names it too, mapped to itself on the device split off
// and gone from the device that stays, so a module that keeps rows by device and line moves them with it.
func TestSplit_TellsTheLifecycleOfALineThatGoesBackWhole(t *testing.T) {
	t.Parallel()
	hooks := &lifecycle.Hooks{}
	var got []lifecycle.Split
	hooks.Register(lifecycle.Participant{Name: "test", DeviceSplit: func(_ context.Context, _ *sql.Tx, s lifecycle.Split) error {
		got = append(got, s)
		return nil
	}})
	e := newEnv(t, func(c *inventory.Config) { c.Lifecycle = hooks })
	hand := e.addDevice(inventory.AddInput{Vendor: "VMware", Product: "ESXi", Version: "8.0.3 build 24022510", Name: "esxi-01", IP: "192.0.2.90"})
	esxiLine := func(dev string) string {
		var id string
		if err := e.db.Reader().QueryRowContext(e.ctx(), `SELECT id FROM inv_software WHERE asset_id = ? AND lower(product) = 'esxi' AND state = 'present'`, dev).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	line := esxiLine(hand)
	e.tick(time.Minute)
	e.record(vmCard(vmCard1, "192.0.2.131", "")...)
	vm := e.idOf("192.0.2.131")
	if err := e.svc.Merge(e.ctx(), admin, vm, hand); err != nil {
		t.Fatal(err)
	}
	back, err := e.svc.Split(e.ctx(), admin, vm, "192.0.2.90")
	if err != nil {
		t.Fatal(err)
	}
	if got := esxiLine(back); got != line {
		t.Fatalf("the test needs the ESXi line to go back whole: %q, want %q", got, line)
	}
	if len(got) != 1 {
		t.Fatalf("split hooks %+v, want one", got)
	}
	if l, ok := got[0].Software[line]; !ok || l.Into != line || !l.Gone {
		t.Errorf("the ESXi line that went back whole: %+v, %v (all %+v); want mapped to itself and gone from the device that stays", l, ok, got[0].Software)
	}
}

// A participant's error rolls the whole split back: no device split off, the readings where they were.
func TestSplit_AHookErrorRollsTheSplitBack(t *testing.T) {
	t.Parallel()
	hooks := &lifecycle.Hooks{}
	hooks.Register(lifecycle.Participant{Name: "test", DeviceSplit: func(context.Context, *sql.Tx, lifecycle.Split) error {
		return errors.New("refused")
	}})
	e := newEnv(t, func(c *inventory.Config) { c.Lifecycle = hooks })
	hand := e.addDevice(inventory.AddInput{Vendor: "VMware", Product: "ESXi", Version: "8.0.3 build 24022510", Name: "esxi-01", IP: "192.0.2.90"})
	e.tick(time.Minute)
	host := esxiHost(e)
	if err := e.svc.Merge(e.ctx(), admin, host, hand); err != nil {
		t.Fatal(err)
	}
	devices, readings := e.count(`SELECT count(*) FROM inv_asset`), e.count(`SELECT count(*) FROM inv_software_reading`)
	if _, err := e.svc.Split(e.ctx(), admin, host, "192.0.2.90"); err == nil {
		t.Fatal("the split went through a participant's error")
	}
	if n := e.count(`SELECT count(*) FROM inv_asset`); n != devices {
		t.Errorf("devices %d after a refused split, want %d", n, devices)
	}
	if n := e.count(`SELECT count(*) FROM inv_software_reading`); n != readings {
		t.Errorf("readings %d after a refused split, want %d", n, readings)
	}
}
