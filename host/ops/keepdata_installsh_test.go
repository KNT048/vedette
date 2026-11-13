package ops

import (
	"os"
	"os/exec" //nolint:depguard // the test runs install.sh's own sh functions with a fixed argv; SYS-1 is about the product
	"path/filepath"
	"strings"
	"testing"
)

// W2-9, D-418: after an --uninstall --keep-data the host's records of the containers are still there and their units are not.
// install.sh reads the release core last ran from the file the Go code writes (kept_release_ok), and clears exactly the records
// the Go code keeps for the containers (forget_containers), so that the bootstrap installs again over the kept data. A rename of
// those files, or a change of the JSON of versions-<service>.json, turns this red.
func TestInstallSh_KeepDataReinstallReadsAndClearsTheHostsRecords(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, "\nHOST_STATE="+suState+"\n") {
		t.Fatalf("install.sh does not set HOST_STATE=%s", suState)
	}
	script := "set -eu\nsay() { printf '%s\\n' \"$*\"; }\nwarn() { printf 'WARNING: %s\\n' \"$*\" >&2; }\n" +
		"die() { printf 'ERROR: %s\\n' \"$*\" >&2; exit 1; }\n"
	for _, name := range []string{"host_version_ok", "vedette_units", "kept_records", "kept_release_ok", "forget_containers"} {
		i := strings.Index(s, "\n"+name+"() {\n")
		if i < 0 {
			t.Fatalf("no %s in install.sh", name)
		}
		j := strings.Index(s[i+1:], "\n}\n")
		if j < 0 {
			t.Fatalf("%s has no end", name)
		}
		script += s[i+1:i+1+j+2] + "\n"
	}
	host, units := t.TempDir(), t.TempDir()
	run := func(call string) (string, error) {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "sh", "-c", script+call) //nolint:gosec // the sh functions of install.sh under test
		cmd.Env = append(os.Environ(), "HOST_STATE="+host, "UNIT_DIR="+units)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	o := &Ops{cfg: Config{StateDir: host}}
	for _, d := range []string{"containers/units", "releases", "backups", suDirName} {
		if err := os.MkdirAll(filepath.Join(host, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rec := func(v string) *versionRecord {
		return &versionRecord{pulledRecord: pulledRecord{Service: "core", Version: v, Digest: "sha256:" + strings.Repeat("a", 64), Manifest: "e30="}}
	}
	// previous is newer than current on purpose: the release that last ran is current's
	if err := writeJSONAtomic(o.stateFile("containers", versionsName("core")), versionState{Service: "core", Current: rec("0.0.1-test.3"), Previous: rec("0.0.1-test.9")}); err != nil {
		t.Fatal(err)
	}
	cleared := []string{
		o.stateFile("containers", versionsName("core")),
		o.stateFile("containers", pulledName("core")),
		o.stateFile("containers", pulledName("scan")),
		o.stateFile("containers", journalName("sensor")),
		o.stateFile("containers", "units", o.prevName("core")),
	}
	kept := []string{
		o.stateFile("releases", indexStateFile),
		o.stateFile("backups", "b1"),
		filepath.Join(host, suDirName, "versions.json"),
	}
	for _, f := range append(cleared[1:], kept...) {
		if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// a unit of Vedette is there: nothing is kept data, and no release is compared
	if err := os.WriteFile(filepath.Join(units, "vedette-sensor.container"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := run("kept_records"); err == nil {
		t.Fatalf("kept_records with a unit there: %q", out)
	}
	if out, err := run("kept_release_ok 0.0.1-test.1"); err != nil {
		t.Fatalf("kept_release_ok with a unit there: %v %q", err, out)
	}
	if err := os.Remove(filepath.Join(units, "vedette-sensor.container")); err != nil {
		t.Fatal(err)
	}
	if out, err := run("kept_records"); err != nil {
		t.Fatalf("kept_records with the records and no unit: %v %q", err, out)
	}

	if _, err := exec.LookPath("dpkg"); err == nil { // the comparison is dpkg's (every supported box has it); macOS has none
		for v, ok := range map[string]bool{"0.0.1-test.2": false, "0.0.1-test.3": true, "0.0.1-test.10": true, "0.0.1": true, "0.1.0-beta.1": true} {
			out, err := run("kept_release_ok " + v)
			if ok && (err != nil || !strings.Contains(out, "last ran with release 0.0.1-test.3")) {
				t.Errorf("kept_release_ok %s refused or did not name the kept release: %v %q", v, err, out)
			}
			if !ok && (err == nil || !strings.Contains(out, "keeps the data of Vedette 0.0.1-test.3")) {
				t.Errorf("kept_release_ok %s, older than the kept data, was not refused: %q", v, out)
			}
		}
	}

	// a link in place of the old unit texts is removed, not followed
	outside := filepath.Join(t.TempDir(), "keep")
	if err := os.WriteFile(outside, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := run("forget_containers"); err != nil {
		t.Fatalf("forget_containers: %v %q", err, out)
	}
	if err := os.Symlink(filepath.Dir(outside), o.stateFile("containers", "units")); err != nil {
		t.Fatal(err)
	}
	if out, err := run("forget_containers"); err != nil {
		t.Fatalf("forget_containers with a link: %v %q", err, out)
	}
	for _, f := range cleared {
		if _, err := os.Lstat(f); !os.IsNotExist(err) {
			t.Errorf("%s is still there after forget_containers", f)
		}
	}
	if _, err := os.Lstat(o.stateFile("containers", "units")); !os.IsNotExist(err) {
		t.Error("the link in place of containers/units is still there")
	}
	for _, f := range append(kept, outside) {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%s was removed by forget_containers: %v", f, err)
		}
	}
	if o.loadVersions("core").Current != nil {
		t.Error("the host still reads a running version of core")
	}
	if out, err := run("kept_records"); err == nil {
		t.Fatalf("kept_records after forget_containers: %q", out)
	}
}
