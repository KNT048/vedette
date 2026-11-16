package worker_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

// #830: the worker reports how far a running job is from what the tool prints anyway. The fake tools print their progress lines,
// then wait for a file the test writes once the report has arrived, so nothing here depends on the speed of the machine.

func fastProgress(c *worker.Config) { c.ProgressEvery = 20 * time.Millisecond }

// waitProgress returns the first report of job id1 (the one job of these tests) that ok accepts.
func (c *fakeCore) waitProgress(t *testing.T, ok func(sensorlink.JobProgress) bool) sensorlink.JobProgress {
	t.Helper()
	deadline := time.After(30 * time.Second)
	for {
		select {
		case r := <-c.progress:
			if r.id == id1 && ok(r.p) {
				return r.p
			}
		case <-deadline:
			t.Fatal("no such progress report from the worker")
			return sensorlink.JobProgress{}
		}
	}
}

// gate makes the fake tool wait until the test writes $DIR/go (polling, so the script ends on its own once released).
const gate = `while [ ! -f "$DIR/go" ]; do sleep 0.02; done
`

func release(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "go"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNmapProgressIsReportedFromItsXML(t *testing.T) {
	t.Parallel()
	nm := writeNmap(t, `cat <<'EOF'
<?xml version="1.0"?>
<nmaprun>
<taskprogress task="Unknown Task" time="1700000000" percent="50.00" remaining="10"/>
<taskprogress task="SYN Stealth Scan" time="1700000000" percent="999.00" remaining="10"/>
<taskprogress task="SYN Stealth Scan" time="1700000000" percent="42.50" remaining="60" etc="1700000060"/>
EOF
`+gate+`cat <<'EOF'
<host><status state="up"/><address addr="192.168.10.20" addrtype="ipv4"/></host></nmaprun>
EOF
`)
	r := start(t, nm, fastProgress)
	r.core.push(job(id1))
	if p := r.core.waitProgress(t, func(sensorlink.JobProgress) bool { return true }); p != (sensorlink.JobProgress{Phase: "discovery", Percent: -1}) {
		t.Fatalf("first report = %+v, want the phase nmap starts with", p)
	}
	p := r.core.waitProgress(t, func(p sensorlink.JobProgress) bool { return p.Percent >= 0 })
	if want := (sensorlink.JobProgress{Phase: "ports", Percent: 42.5, RemainingS: 60}); p != want {
		t.Fatalf("progress = %+v, want %+v (an unknown task and a percent over 100 are not reported)", p, want)
	}
	release(t, nm.dir)
	if got := r.core.next(t); got.res.Status != "done" {
		t.Fatalf("result = %+v", got.res)
	}
}

// #830 FAIL 1, fix B: where nmap prints no <taskprogress> (it found no terminal), the worker still names the phase: the one its
// command line starts with as soon as nmap starts, then the port scan once nmap's XML says discovery found the host.
func TestNmapPhaseMovesWithoutItsProgressLines(t *testing.T) {
	t.Parallel()
	nm := writeNmap(t, `cat <<'EOF'
<?xml version="1.0"?>
<nmaprun>
<hosthint><status state="up" reason="arp-response" reason_ttl="0"/>
<address addr="192.168.10.20" addrtype="ipv4"/>
<hostnames>
</hostnames>
</hosthint>
EOF
`+gate+`cat <<'EOF'
<host><status state="up"/><address addr="192.168.10.20" addrtype="ipv4"/></host></nmaprun>
EOF
`)
	r := start(t, nm, fastProgress)
	r.core.push(job(id1))
	if p := r.core.waitProgress(t, func(sensorlink.JobProgress) bool { return true }); p != (sensorlink.JobProgress{Phase: "discovery", Percent: -1}) {
		t.Fatalf("first report = %+v, want discovery", p)
	}
	if p := r.core.waitProgress(t, func(p sensorlink.JobProgress) bool { return p.Phase != "discovery" }); p != (sensorlink.JobProgress{Phase: "ports", Percent: -1}) {
		t.Fatalf("next report = %+v, want ports (no percent)", p)
	}
	release(t, nm.dir)
	if got := r.core.next(t); got.res.Status != "done" {
		t.Fatalf("result = %+v", got.res)
	}
}

// #830 FAIL 1, fix A: the worker's nmap runs on a terminal of its own (core/exec Binary.TTY), the only way nmap 7.95 prints its
// --stats-every lines. The fake nmap records whether its stdin is a terminal.
func TestNmapRunsOnATerminal(t *testing.T) {
	t.Parallel()
	if f, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0); err != nil {
		t.Skipf("no pseudo-terminal here: %v", err)
	} else {
		_ = f.Close()
	}
	nm := writeNmap(t, `if [ -t 0 ]; then echo yes > "$DIR/tty"; else echo no > "$DIR/tty"; fi
`+printXML)
	r := start(t, nm)
	r.core.push(job(id1))
	if got := r.core.next(t); got.res.Status != "done" {
		t.Fatalf("result = %+v", got.res)
	}
	if b, err := os.ReadFile(filepath.Join(nm.dir, "tty")); err != nil || string(b) != "yes\n" {
		t.Fatalf("nmap's stdin a terminal: %q, %v; want yes", b, err)
	}
}

func TestNucleiProgressCountsItsChecks(t *testing.T) {
	t.Parallel()
	// two lines of the job (one repeated), one of a template the job did not ask for, then the wait
	r := startNuclei(t, `cat <<'EOF'
{"template-id":"CVE-2024-1","host":"192.168.10.20","port":"8080","matcher-status":false}
{"template-id":"CVE-2024-1","host":"192.168.10.20","port":"8080","matcher-status":false}
{"template-id":"CVE-2099-9","host":"192.168.10.20","port":"8080","matcher-status":false}
{"template-id":"CVE-2024-2","host":"10.0.0.7","port":"22","matcher-status":false}
EOF
`+gate, fastProgress)
	r.core.push(r.job(id1))
	p := r.core.waitProgress(t, func(p sensorlink.JobProgress) bool { return p.Done == 2 })
	if want := (sensorlink.JobProgress{Phase: "vulns", Percent: -1, Done: 2, Total: 4}); p != want {
		t.Fatalf("progress = %+v, want %+v", p, want)
	}
	release(t, r.nu.Dir)
	if got := r.core.next(t); got.res.Status != "done" {
		t.Fatalf("result = %+v", got.res)
	}
}
