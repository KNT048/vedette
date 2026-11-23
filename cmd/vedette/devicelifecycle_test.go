package main

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"testing"

	"github.com/knt048/vedette/core/lifecycle"
)

// Every module that keeps rows about a device takes part in a merge and a delete, inside the inventory's write.
func TestEveryModuleWithDeviceRowsTakesPartInTheLifecycle(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	got := s.d.Lifecycle.Names()
	for _, want := range []string{"findings", "mitigation", "notify", "response", "connections", "feeds", "sensor-active"} {
		if !slices.Contains(got, want) {
			t.Errorf("%s does not take part: %v", want, got)
		}
	}
}

// Two rows of one machine that both hold a finding, a software row and an SNMP setting are merged in one transaction and nothing is
// lost: each CVE has one finding with the history of both copies and the person's decisions, each software row is one row whose
// times cover both readings and that the findings name, one SNMP setting stays and a notice names the other. A participant that
// fails rolls the whole merge back: every table is as it was, the two rows included.
func TestMergeOfTwoRowsIsOneTransactionThatLosesNothing(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	from, into, _ := s.twoRowsOfOneMachine(t)

	fail := errors.New("a module could not move its rows")
	failing := false
	s.d.Lifecycle.Register(lifecycle.Participant{Name: "test: fails on demand", DeviceMerged: func(context.Context, *sql.Tx, lifecycle.Merge) error {
		if failing {
			return fail
		}
		return nil
	}})
	failing = true
	before := s.dumpDB()
	if err := s.d.Inventory.Merge(t.Context(), "person@example.com", into, from); !errors.Is(err, fail) {
		t.Fatalf("merge with a failing part: %v", err)
	}
	if s.dumpDB() != before {
		t.Fatal("a failed merge changed the database: it must roll back as one transaction")
	}

	failing = false
	if err := s.d.Inventory.Merge(t.Context(), "person@example.com", into, from); err != nil {
		t.Fatal(err)
	}
	if n := s.count(`SELECT count(*) FROM inv_asset WHERE id = ?`, from); n != 0 {
		t.Fatal("the merged row is still there")
	}
	if n := s.count(`SELECT count(*) FROM (SELECT cve FROM fnd_finding WHERE asset_id = ? GROUP BY cve, ifnull(software_id, '') HAVING count(*) > 1)`, into); n != 0 {
		t.Fatal("a CVE has two findings on one software line of the device")
	}
	if n := s.count(`SELECT count(*) FROM fnd_finding_event e JOIN fnd_finding f ON f.id = e.finding_id WHERE f.asset_id = ? AND e.actor IN ('person@example.com', 'other@example.com')`, into); n != 3 {
		t.Errorf("%d of the 3 people's decisions are on the device", n)
	}
	if n := s.count(`SELECT count(*) FROM fnd_finding f WHERE f.asset_id = ? AND f.software_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM inv_software s WHERE s.id = f.software_id AND s.asset_id = f.asset_id)`, into); n != 0 {
		t.Errorf("%d findings name a software row the device does not have", n)
	}
	if n := s.count(`SELECT count(*) FROM inv_software WHERE asset_id = ? AND seen_at = '2026-11-20T09:03:21.501Z'`, into); n != 50 {
		t.Errorf("%d of the 50 software rows carry the later reading", n)
	}
	if n := s.count(`SELECT count(*) FROM sa_snmp_device WHERE asset_id = ?`, into); n != 1 {
		t.Errorf("%d SNMP settings on the device, want 1", n)
	}
	if n := s.count(`SELECT count(*) FROM sa_snmp_notice WHERE text LIKE '%Removed: SNMP v2c%'`); n != 1 {
		t.Error("no notice names the SNMP settings the merge removed")
	}
	if n := s.count(`SELECT count(*) FROM core_audit WHERE action = 'findings.merged_with_asset' AND target = ? AND detail LIKE '%decided on both%'`, into); n != 1 {
		t.Error("the audit row does not name the CVE decided on both rows")
	}
}

// A participant that fails rolls a delete back too: the device and every module's rows stay.
func TestFailedDeleteRollsBack(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	from, _, _ := s.twoRowsOfOneMachine(t)
	fail := errors.New("a module could not delete its rows")
	s.d.Lifecycle.Register(lifecycle.Participant{Name: "test: fails", DeviceDeleted: func(context.Context, *sql.Tx, lifecycle.Delete) error { return fail }})
	before := s.dumpDB()
	if err := s.d.Inventory.DeleteDevice(t.Context(), "person@example.com", from); !errors.Is(err, fail) {
		t.Fatalf("delete with a failing part: %v", err)
	}
	if s.dumpDB() != before {
		t.Fatal("a failed delete changed the database")
	}
}

// A deleted device leaves a linked connection and an "I have this" answer in place, naming no device.
func TestDeleteUnlinksConnectionsAndAnswers(t *testing.T) {
	t.Parallel()
	s := newStack(t)
	from, _, _ := s.twoRowsOfOneMachine(t)
	if err := s.d.Inventory.DeleteDevice(t.Context(), "person@example.com", from); err != nil {
		t.Fatal(err)
	}
	if n := s.count(`SELECT count(*) FROM core_connection WHERE id = 'cn-merge-1' AND asset_id IS NULL`); n != 1 {
		t.Error("the connection still names the deleted device, or is gone")
	}
	if n := s.count(`SELECT count(*) FROM feeds_weekly_answer WHERE key = 'linux|kernel' AND device_id IS NULL`); n != 1 {
		t.Error("the answer still names the deleted device, or is gone")
	}
}
