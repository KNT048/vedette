package ops_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knt048/vedette/host/api"
	"github.com/knt048/vedette/host/ops"
	"github.com/knt048/vedette/host/ops/opstest"
)

func unitText(t *testing.T, m *opstest.Machine, svc, digest string) []byte {
	t.Helper()
	cfg := m.Config()
	b, err := ops.RenderUnit(svc, digest, true, cfg.CoreUID, cfg.CoreGID, cfg.SensorUID, cfg.SensorGID)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestWriteUnitWritesAtomically0644AndKeepsThePreviousBytes(t *testing.T) {
	t.Parallel()
	m := opstest.NewMachine(t)
	m.MakeUnitsDir()
	o := m.Ops(nil)
	a, b := unitText(t, m, "honeypot", opstest.Digest('a')), unitText(t, m, "honeypot", opstest.Digest('b'))
	if err := o.WriteUnit("honeypot", a, true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Prev("honeypot"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a first write has no previous bytes: %v", err)
	}
	if err := o.WriteUnit("honeypot", b, true); err != nil {
		t.Fatal(err)
	}
	got, _ := m.Unit("honeypot")
	prev, err := m.Prev("honeypot")
	if got != string(b) || err != nil || prev != string(a) {
		t.Fatalf("unit %q prev %q %v", got, prev, err)
	}
	st, err := os.Stat(filepath.Join(m.UnitsDir(), "vedette-honeypot.container"))
	if err != nil || st.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v %v", st.Mode(), err)
	}
	pst, err := os.Stat(filepath.Join(m.State, "containers", "units", "honeypot.prev"))
	if err != nil || pst.Mode().Perm() != 0o600 {
		t.Fatalf("prev mode %v %v", pst, err)
	}
	// Writing the same bytes again changes nothing and does not replace .prev by them.
	if err := o.WriteUnit("honeypot", b, true); err != nil {
		t.Fatal(err)
	}
	if prev2, _ := m.Prev("honeypot"); prev2 != string(a) {
		t.Fatal("the same bytes replaced .prev")
	}
	// A write that must not touch .prev (putting an old unit back) leaves it.
	if err := o.WriteUnit("honeypot", a, false); err != nil {
		t.Fatal(err)
	}
	if prev3, _ := m.Prev("honeypot"); prev3 != string(a) {
		t.Fatal("a revert write replaced .prev")
	}
	left, _ := filepath.Glob(filepath.Join(m.UnitsDir(), ".tmp-*"))
	if len(left) != 0 {
		t.Fatalf("temp files left: %v", left)
	}
}

func TestWriteUnitRefusesALinkAtTheUnitName(t *testing.T) {
	t.Parallel()
	m := opstest.NewMachine(t)
	m.MakeUnitsDir()
	victim := filepath.Join(m.Root, "victim")
	if err := os.WriteFile(victim, []byte("do not touch"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(m.UnitsDir(), "vedette-honeypot.container")); err != nil {
		t.Fatal(err)
	}
	o := m.Ops(nil)
	err := o.WriteUnit("honeypot", unitText(t, m, "honeypot", opstest.Digest('a')), true)
	if !errors.Is(err, ops.ErrUnitUnsafe) {
		t.Fatalf("a link at the unit name: %v", err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "do not touch" { //nolint:gosec // test: a path under the fake root
		t.Fatalf("the link target was written: %q", b)
	}
	// A directory or a FIFO at the name is refused too.
	_ = os.Remove(filepath.Join(m.UnitsDir(), "vedette-honeypot.container"))
	if err := os.Mkdir(filepath.Join(m.UnitsDir(), "vedette-honeypot.container"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := o.WriteUnit("honeypot", unitText(t, m, "honeypot", opstest.Digest('a')), true); !errors.Is(err, ops.ErrUnitUnsafe) {
		t.Fatalf("a directory at the unit name: %v", err)
	}
}

func TestWriteUnitRefusesALinkAtTheDirectoryAndAnUnsafeChain(t *testing.T) {
	t.Parallel()
	text := func(m *opstest.Machine) []byte { return unitText(t, m, "honeypot", opstest.Digest('a')) }

	// The Quadlet directory is a link to another directory.
	m := opstest.NewMachine(t)
	other := filepath.Join(m.Root, "elsewhere")
	if err := os.MkdirAll(other, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(m.Root, "etc/containers"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, m.UnitsDir()); err != nil {
		t.Fatal(err)
	}
	if err := m.Ops(nil).WriteUnit("honeypot", text(m), true); !errors.Is(err, ops.ErrUnitUnsafe) {
		t.Fatalf("a link at the directory: %v", err)
	}
	if left, _ := os.ReadDir(other); len(left) != 0 {
		t.Fatalf("something was written through the link: %v", left)
	}

	// A parent is a link: /etc/containers -> elsewhere.
	m2 := opstest.NewMachine(t)
	elsewhere := filepath.Join(m2.Root, "real-containers")
	if err := os.MkdirAll(filepath.Join(elsewhere, "systemd"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(m2.Root, "etc"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(m2.Root, "etc/containers")); err != nil {
		t.Fatal(err)
	}
	if err := m2.Ops(nil).WriteUnit("honeypot", text(m2), true); !errors.Is(err, ops.ErrUnitUnsafe) {
		t.Fatalf("a link at a parent: %v", err)
	}

	// Group- or world-writable: the directory itself and each parent.
	for _, rel := range []string{"etc/containers/systemd", "etc/containers", "etc"} {
		for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
			m3 := opstest.NewMachine(t)
			m3.MakeUnitsDir()
			if err := os.Chmod(filepath.Join(m3.Root, rel), mode); err != nil {
				t.Fatal(err)
			}
			if err := m3.Ops(nil).WriteUnit("honeypot", text(m3), true); !errors.Is(err, ops.ErrUnitUnsafe) {
				t.Errorf("%s mode %o: %v", rel, mode, err)
			}
			if _, err := m3.Unit("honeypot"); err == nil {
				t.Errorf("%s mode %o: the unit was written", rel, mode)
			}
		}
	}
	// A sticky bit is no excuse (sshd StrictModes has none).
	m4 := opstest.NewMachine(t)
	m4.MakeUnitsDir()
	if err := os.Chmod(filepath.Join(m4.Root, "etc"), os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if err := m4.Ops(nil).WriteUnit("honeypot", text(m4), true); !errors.Is(err, ops.ErrUnitUnsafe) {
		t.Fatalf("sticky world-writable parent: %v", err)
	}
	// A missing directory is not made: the installer builds the tree.
	m5 := opstest.NewMachine(t)
	if err := m5.Ops(nil).WriteUnit("honeypot", text(m5), true); !errors.Is(err, ops.ErrUnitUnsafe) {
		t.Fatalf("a missing directory: %v", err)
	}
	if _, err := os.Stat(m5.UnitsDir()); err == nil {
		t.Fatal("the host made the Quadlet directory")
	}
}

func TestWriteUnitStopsWhenThePreviousBytesCannotBeKept(t *testing.T) {
	t.Parallel()
	m := opstest.NewMachine(t)
	m.MakeUnitsDir()
	o := m.Ops(nil)
	a, b := unitText(t, m, "honeypot", opstest.Digest('a')), unitText(t, m, "honeypot", opstest.Digest('b'))
	if err := o.WriteUnit("honeypot", a, true); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(m.State, "containers", "units")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(m.State, "containers", "units"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := o.WriteUnit("honeypot", b, true); err == nil {
		t.Fatal("the unit changed although its old bytes could not be kept")
	}
	if got, _ := m.Unit("honeypot"); got != string(a) || strings.Contains(got, opstest.Digest('b')) {
		t.Fatalf("the unit changed: %q", got)
	}
}

func TestEveryServiceUnitIsWrittenFromItsTemplateForTheMachinesIds(t *testing.T) {
	t.Parallel()
	m := opstest.NewMachine(t)
	for _, svc := range []string{api.ServiceCore, api.ServiceSensor, api.ServiceHoneypot, api.ServiceScan} {
		m.InstallUnit(svc, opstest.Digest('d'), true)
		got, err := m.Unit(svc)
		if err != nil || got != string(unitText(t, m, svc, opstest.Digest('d'))) {
			t.Errorf("%s: %v", svc, err)
		}
	}
}
