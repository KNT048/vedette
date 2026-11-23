package inventory_test

import (
	"slices"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/inventory"
)

// The box's own agent is a source like any agent: its device page has an agent row that reports, says when it read the box last
// and when it reads it next (its hourly read), and offers Check now, which reads the packages at once (a new package shows without
// waiting for the hour) and leaves one audit row. A container-only install has no packages of its own: no button, and the check is
// refused.
func TestBoxAgent_RowWithLastAndNextReadAndCheckNow(t *testing.T) {
	t.Parallel()
	items := []inventory.SoftwareItem{{Display: "OpenSSH", Vendor: "OpenBSD", Product: "OpenSSH", Version: "9.6p1", Packaged: true}}
	e := newEnv(t, withBox(swapBox{&items}))
	id, err := e.svc.EnsureBox(e.ctx(), inventory.BoxInfo{Hostname: "vedette-hq", IP: "192.168.10.2"})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RefreshBoxPackages(e.ctx()); err != nil { // the hourly job's read
		t.Fatal(err)
	}
	read := e.now
	v, err := e.svc.DeviceSources(e.ctx(), id)
	if err != nil {
		t.Fatal(err)
	}
	agent := v.Rows[2]
	if agent.Source != inventory.RowAgent || agent.State != inventory.StateReporting || agent.Agent == nil || *agent.Agent != inventory.AgentBox ||
		agent.Action == nil || *agent.Action != inventory.ActionBoxCheck || agent.LastAt == nil || agent.NextAt == nil {
		t.Fatalf("the box's agent row: %+v", agent)
	}
	if next, _ := time.Parse(time.RFC3339, *agent.NextAt); !next.Equal(read.Add(inventory.BoxEvery).Truncate(time.Millisecond)) {
		t.Errorf("next read = %s, want an hour after %s", *agent.NextAt, read)
	}

	e.tick(10 * time.Minute)
	items = append(items, inventory.SoftwareItem{Display: "curl", Vendor: "curl", Product: "curl", Version: "8.5.0", Packaged: true})
	v, err = e.svc.CheckBox(e.ctx(), admin)
	if err != nil {
		t.Fatal(err)
	}
	if sw := e.detail(id).Asset.Software; !slices.ContainsFunc(sw, func(s inventory.SoftwareLine) bool { return s.Product == "curl" }) {
		t.Errorf("Check now did not read the new package: %+v", sw)
	}
	if next, _ := time.Parse(time.RFC3339, *v.Rows[2].NextAt); !next.Equal(e.now.Add(inventory.BoxEvery).Truncate(time.Millisecond)) {
		t.Errorf("next read after Check now = %s", *v.Rows[2].NextAt)
	}
	if got := e.auditBy("inventory.box_check"); len(got) != 1 {
		t.Errorf("audit rows of the check: %v", got)
	}

	c := newEnv(t) // a container-only install: no packages of its own
	cid, err := c.svc.EnsureBox(c.ctx(), inventory.BoxInfo{Hostname: "vedette-ct", ContainerOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	cv, err := c.svc.DeviceSources(c.ctx(), cid)
	if err != nil {
		t.Fatal(err)
	}
	if cv.Rows[2].Action != nil {
		t.Errorf("container-only box offers %v", *cv.Rows[2].Action)
	}
	_, err = c.svc.CheckBox(c.ctx(), admin)
	wantAPIError(t, err, 409, "not_appliance")
}
