package worker_test

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/sensor-active/worker"
	"github.com/knt048/vedette/modules/sensor-active/worker/workertest"
)

// The nuclei job of the worker (D-125, D-136). The nuclei here is a shell script run through the real core/exec; nothing
// reaches a network.

const jsonlLine = `{"template-id":"CVE-2024-1","host":"192.168.10.20:8080","matcher-status":false,"error":"timeout"}` + "\n"

var (
	printJSONL = "cat <<'EOF'\n" + jsonlLine + "EOF\n"
	tIDs       = []string{"CVE-2024-1", "CVE-2024-2"}
)

type nrig struct {
	*rig
	nu   *workertest.Nuclei
	pack *workertest.Pack
	home string
}

// startNuclei runs a worker with the fake nuclei and a pack of the ids.
func startNuclei(t *testing.T, body string, mut ...func(*worker.Config)) *nrig {
	t.Helper()
	nu := workertest.NewNuclei(t, body)
	pk := workertest.NewPack(t, tIDs...)
	home := filepath.Join(t.TempDir(), "tmpfs-home")
	cfg := func(c *worker.Config) {
		c.NucleiPath, c.NucleiIndex, c.NucleiHome, c.TemplatesDir = nu.Path, pk.Index, home, pk.Dir
	}
	return &nrig{rig: start(t, writeNmap(t, printXML), append([]func(*worker.Config){cfg}, mut...)...), nu: nu, pack: pk, home: home}
}

func (r *nrig) job(id string) sensorlink.Job {
	return sensorlink.Job{ID: id, Kind: sensorlink.KindNuclei, TimeoutS: 60, Nuclei: &sensorlink.NucleiJob{
		Pack:      sensorlink.JobPack{Version: r.pack.Version, SHA256: r.pack.SHA256},
		Templates: slices.Clone(tIDs),
		Targets:   []sensorlink.NucleiTarget{{Host: "192.168.10.20", Port: 8080, Scheme: "http"}, {Host: "10.0.0.7", Port: 22}},
		Rate:      5, MaxHostErrors: 3,
	}}
}

// A job runs with the argv the worker built from its fields and the pack index: one -t per template, never the directory
// (D-136 (6)), the targets as -u (M3), and the result carries the JSONL and the exit code.
func TestNucleiRunsAJobWithTheFixedGrammar(t *testing.T) {
	t.Parallel()
	r := startNuclei(t, printJSONL)
	r.core.push(r.job(id1))
	got := r.core.next(t)
	if got.id != id1 || got.res.Status != "done" || got.res.ExitCode != 0 || got.res.Truncated || string(got.res.JSONL()) != jsonlLine || got.res.XMLB64 != "" {
		t.Fatalf("result = %+v jsonl %q", got.res, got.res.JSONL())
	}
	args := strings.Split(strings.TrimSpace(r.nu.Argv()), "\n")
	d := nucleiargv.TemplatesDir
	tail := []string{"-rl", "5", "-mhe", "3", "-t", d + "/" + r.pack.Paths["CVE-2024-1"], "-t", d + "/" + r.pack.Paths["CVE-2024-2"], "-u", "http://192.168.10.20:8080", "-u", "10.0.0.7:22"}
	if len(args) < len(tail) || !slices.Equal(args[len(args)-len(tail):], tail) {
		t.Fatalf("argv: %q", args)
	}
	if err := nucleiargv.Validate(args); err != nil {
		t.Fatalf("what ran is not what nucleiargv allows: %v", err)
	}
	for _, a := range args {
		if a == d || a == d+"/" {
			t.Fatalf("the whole template directory was named: %q", args)
		}
	}
}

// D-136 (5), scan INV-4: nuclei runs with the environment of core/exec and a HOME on the tmpfs that is empty at the start. A
// proxy, a cloud upload switch or a key in the parent's environment does not reach it. (Not parallel: it sets variables.)
func TestNucleiEnvironmentIsClean(t *testing.T) {
	for k, v := range map[string]string{
		"HTTP_PROXY": "http://evil:3128", "HTTPS_PROXY": "http://evil:3128", "ALL_PROXY": "socks5://evil", "http_proxy": "http://evil:3128",
		"NO_PROXY": "x", "ENABLE_CLOUD_UPLOAD": "true", "PDCP_API_KEY": "k-secret", "HOME": "/root", "XDG_CONFIG_HOME": "/root/.config",
		"NUCLEI_CONFIG": "/root/c.yaml", "LD_PRELOAD": "/tmp/evil.so",
	} {
		t.Setenv(k, v)
	}
	r := startNuclei(t, printJSONL)
	// something an earlier run, or the image, left in the home must not be there at the start
	if err := os.MkdirAll(filepath.Join(r.home, "run", ".config", "nuclei"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.home, "run", ".config", "nuclei", "config.yaml"), []byte("proxy: evil"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.core.push(r.job(id1))
	if got := r.core.next(t); got.res.Status != "done" {
		t.Fatalf("result = %+v", got.res)
	}
	env := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(r.nu.Env()), "\n") {
		k, v, _ := strings.Cut(l, "=")
		env[k] = v
	}
	for k := range env {
		switch k {
		case "PATH", "LANG", "HOME", "PWD", "SHLVL", "_", "OLDPWD": // the first three are core/exec's; sh adds the others
		default:
			t.Errorf("unexpected variable %s=%s in nuclei's environment", k, env[k])
		}
	}
	if want := filepath.Join(r.home, "run"); env["HOME"] != want {
		t.Errorf("HOME = %q, want %q", env["HOME"], want)
	}
	if l := strings.TrimSpace(r.nu.HomeListing()); l != "" {
		t.Errorf("HOME was not empty at the start: %q", l)
	}
}

// The worker refuses what the grammar forbids, with the reason, and nuclei never starts (D-136 (4)).
func TestNucleiRefusesWhatTheGrammarForbids(t *testing.T) {
	t.Parallel()
	r := startNuclei(t, printJSONL)
	target := func(host string, port int, scheme string) sensorlink.NucleiTarget {
		return sensorlink.NucleiTarget{Host: host, Port: port, Scheme: scheme}
	}
	many := func(n int) []sensorlink.NucleiTarget {
		var ts []sensorlink.NucleiTarget
		for i := range n {
			ts = append(ts, target(fmt.Sprintf("10.0.%d.%d", i/200, i%200+1), 80, "http"))
		}
		return ts
	}
	manyIDs := make([]string, 33)
	for i := range manyIDs {
		manyIDs[i] = fmt.Sprintf("CVE-2024-%d", i+1)
	}
	cases := map[string]func(*sensorlink.Job){
		"a domain": func(j *sensorlink.Job) {
			j.Nuclei.Targets = []sensorlink.NucleiTarget{target("printer.lan", 80, "http")}
		},
		"a public address":  func(j *sensorlink.Job) { j.Nuclei.Targets = []sensorlink.NucleiTarget{target("8.8.8.8", 80, "http")} },
		"one public of two": func(j *sensorlink.Job) { j.Nuclei.Targets = append(j.Nuclei.Targets, target("1.1.1.1", 80, "")) },
		"loopback":          func(j *sensorlink.Job) { j.Nuclei.Targets = []sensorlink.NucleiTarget{target("127.0.0.1", 80, "http")} },
		"link-local metadata": func(j *sensorlink.Job) {
			j.Nuclei.Targets = []sensorlink.NucleiTarget{target("169.254.169.254", 80, "http")}
		},
		"100/8 outside RFC 6598 (D-461)": func(j *sensorlink.Job) {
			j.Nuclei.Targets = []sensorlink.NucleiTarget{target("100.128.0.1", 80, "http")}
		},
		"benchmark": func(j *sensorlink.Job) {
			j.Nuclei.Targets = []sensorlink.NucleiTarget{target("198.18.0.1", 80, "http")}
		},
		"240/4":            func(j *sensorlink.Job) { j.Nuclei.Targets = []sensorlink.NucleiTarget{target("240.0.0.1", 80, "http")} },
		"multicast":        func(j *sensorlink.Job) { j.Nuclei.Targets = []sensorlink.NucleiTarget{target("224.0.0.1", 80, "http")} },
		"an IPv6 literal":  func(j *sensorlink.Job) { j.Nuclei.Targets = []sensorlink.NucleiTarget{target("fe80::1", 80, "http")} },
		"a flag as a host": func(j *sensorlink.Job) { j.Nuclei.Targets = []sensorlink.NucleiTarget{target("-u", 80, "")} },
		"a flag with a space": func(j *sensorlink.Job) {
			j.Nuclei.Targets = []sensorlink.NucleiTarget{target("192.168.10.20 -ud", 80, "")}
		},
		"a URL as a host": func(j *sensorlink.Job) {
			j.Nuclei.Targets = []sensorlink.NucleiTarget{target("http://192.168.10.20", 80, "")}
		},
		"a non-canonical address": func(j *sensorlink.Job) {
			j.Nuclei.Targets = []sensorlink.NucleiTarget{target("192.168.010.20", 80, "http")}
		},
		"a network address": func(j *sensorlink.Job) {
			j.Nuclei.Targets = []sensorlink.NucleiTarget{target("192.168.10.0", 80, "http")}
		},
		"a scheme of file": func(j *sensorlink.Job) {
			j.Nuclei.Targets = []sensorlink.NucleiTarget{target("192.168.10.20", 80, "file")}
		},
		"port 0": func(j *sensorlink.Job) {
			j.Nuclei.Targets = []sensorlink.NucleiTarget{target("192.168.10.20", 0, "http")}
		},
		"port 70000": func(j *sensorlink.Job) {
			j.Nuclei.Targets = []sensorlink.NucleiTarget{target("192.168.10.20", 70000, "http")}
		},
		"17 targets":   func(j *sensorlink.Job) { j.Nuclei.Targets = many(17) },
		"no target":    func(j *sensorlink.Job) { j.Nuclei.Targets = nil },
		"33 templates": func(j *sensorlink.Job) { j.Nuclei.Templates = manyIDs },
		"no template":  func(j *sensorlink.Job) { j.Nuclei.Templates = nil },
		"a template not in the pack": func(j *sensorlink.Job) {
			j.Nuclei.Templates = []string{"CVE-2024-1", "CVE-2099-9"}
		},
		"a template that is a path": func(j *sensorlink.Job) { j.Nuclei.Templates = []string{"../../etc/passwd"} },
		"a template that is a flag": func(j *sensorlink.Job) { j.Nuclei.Templates = []string{"-code"} },
		"a repeated template":       func(j *sensorlink.Job) { j.Nuclei.Templates = []string{"CVE-2024-1", "CVE-2024-1"} },
		"rate 0":                    func(j *sensorlink.Job) { j.Nuclei.Rate = 0 },
		"rate 21":                   func(j *sensorlink.Job) { j.Nuclei.Rate = 21 },
		"rate -5":                   func(j *sensorlink.Job) { j.Nuclei.Rate = -5 },
		"max host errors 1":         func(j *sensorlink.Job) { j.Nuclei.MaxHostErrors = 1 },
		"max host errors 21":        func(j *sensorlink.Job) { j.Nuclei.MaxHostErrors = 21 },
		"timeout 0":                 func(j *sensorlink.Job) { j.TimeoutS = 0 },
		"timeout over an hour":      func(j *sensorlink.Job) { j.TimeoutS = 3601 },
	}
	n := 0
	for name, mut := range cases {
		n++
		id := fmt.Sprintf("%032x", n)
		j := r.job(id)
		mut(&j)
		r.core.push(j)
		got := r.core.next(t)
		if got.id != id || got.res.Status != "refused" || got.res.Reason != "invalid_job" || got.res.ExitCode != -1 || got.res.JSONLB64 != "" {
			t.Errorf("%s: result = %+v", name, got.res)
		}
	}
	if a := r.nu.Argv(); a != "" {
		t.Fatalf("nuclei ran for a refused job: %s", a)
	}
}

// A kind this worker does not know is refused (invalid_job), also when it carries fields of another kind; nothing runs.
func TestUnknownKindIsRefused(t *testing.T) {
	t.Parallel()
	r := startNuclei(t, printJSONL)
	for i, kind := range []string{"shell", "NUCLEI", "nmap2", "nuclei ", strings.Repeat("k", 100)} {
		id := fmt.Sprintf("%032x", i+1)
		r.core.push(sensorlink.Job{ID: id, Kind: kind})
		got := r.core.next(t)
		if got.id != id || got.res.Status != "refused" || got.res.Reason != "invalid_job" {
			t.Errorf("kind %q: result = %+v", kind, got.res)
		}
	}
	if r.nu.Argv() != "" || r.nmap.argvLog() != "" {
		t.Fatal("something ran for an unknown kind")
	}
}

// The pack the job was planned against must be the pack in the image: version and hash of the index (pack_mismatch).
func TestNucleiRefusesAnotherPack(t *testing.T) {
	t.Parallel()
	r := startNuclei(t, printJSONL)
	for name, mut := range map[string]func(*sensorlink.JobPack){
		"another hash":       func(p *sensorlink.JobPack) { p.SHA256 = strings.Repeat("0", 64) },
		"another version":    func(p *sensorlink.JobPack) { p.Version = "2026.11.9" },
		"an upper-case hash": func(p *sensorlink.JobPack) { p.SHA256 = strings.ToUpper(p.SHA256) },
		"no hash":            func(p *sensorlink.JobPack) { p.SHA256 = "" },
	} {
		j := r.job(id1)
		mut(&j.Nuclei.Pack)
		r.core.push(j)
		got := r.core.next(t)
		if got.res.Status != "refused" || got.res.Reason != "pack_mismatch" {
			t.Errorf("%s: result = %+v", name, got.res)
		}
	}
	if r.nu.Argv() != "" {
		t.Fatal("nuclei ran for another pack")
	}
}

// The files must be what the index says: a changed template, a missing one, or an index that does not parse refuses the job
// (pack_invalid).
func TestNucleiRefusesAPackThatDoesNotCheckOut(t *testing.T) {
	t.Parallel()
	t.Run("a changed template", func(t *testing.T) {
		t.Parallel()
		r := startNuclei(t, printJSONL)
		if err := os.WriteFile(r.pack.File("CVE-2024-2"), []byte("id: CVE-2024-2\nrequests: evil\n"), 0o644); err != nil { //nolint:gosec // test file
			t.Fatal(err)
		}
		r.core.push(r.job(id1))
		if got := r.core.next(t); got.res.Status != "refused" || got.res.Reason != "pack_invalid" {
			t.Fatalf("result = %+v", got.res)
		}
		if r.nu.Argv() != "" {
			t.Fatal("nuclei ran")
		}
	})
	t.Run("a template that is gone", func(t *testing.T) {
		t.Parallel()
		r := startNuclei(t, printJSONL)
		if err := os.Remove(r.pack.File("CVE-2024-1")); err != nil {
			t.Fatal(err)
		}
		r.core.push(r.job(id1))
		if got := r.core.next(t); got.res.Status != "refused" || got.res.Reason != "pack_invalid" {
			t.Fatalf("result = %+v", got.res)
		}
	})
	t.Run("a damaged index", func(t *testing.T) {
		t.Parallel()
		r := startNuclei(t, printJSONL)
		if err := os.WriteFile(r.pack.Index, []byte(`{"version":"2026.11.10"`), 0o644); err != nil { //nolint:gosec // test file
			t.Fatal(err)
		}
		r.core.push(r.job(id1))
		if got := r.core.next(t); got.res.Status != "refused" || got.res.Reason != "pack_invalid" {
			t.Fatalf("result = %+v", got.res)
		}
	})
}

// Extra (b): the pack is read with Lstat and holds regular files and directories only. A symlink or any other kind of file
// anywhere in it refuses the job, whether it is one of the job's templates or not.
func TestNucleiRefusesALinkOrASpecialFileAnywhereInThePack(t *testing.T) {
	t.Parallel()
	for name, plant := range map[string]func(t *testing.T, p *workertest.Pack){
		"a template that is a symlink to an identical file": func(t *testing.T, p *workertest.Pack) {
			same := filepath.Join(filepath.Dir(p.Dir), "same.yaml")
			b, _ := os.ReadFile(p.File("CVE-2024-1"))
			if err := os.WriteFile(same, b, 0o644); err != nil { //nolint:gosec // test file
				t.Fatal(err)
			}
			_ = os.Remove(p.File("CVE-2024-1"))
			if err := os.Symlink(same, p.File("CVE-2024-1")); err != nil {
				t.Fatal(err)
			}
		},
		"a symlink to a file outside, not named by the job": func(t *testing.T, p *workertest.Pack) {
			if err := os.Symlink("/etc/passwd", filepath.Join(p.Dir, "http", "payload.txt")); err != nil {
				t.Fatal(err)
			}
		},
		"a symlink to a directory": func(t *testing.T, p *workertest.Pack) {
			if err := os.Symlink("/etc", filepath.Join(p.Dir, "http", "cves", "etc")); err != nil {
				t.Fatal(err)
			}
		},
		"a dangling symlink": func(t *testing.T, p *workertest.Pack) {
			if err := os.Symlink("/nonexistent", filepath.Join(p.Dir, "dangling")); err != nil {
				t.Fatal(err)
			}
		},
		"a fifo": func(t *testing.T, p *workertest.Pack) {
			if err := syscall.Mkfifo(filepath.Join(p.Dir, "http", "pipe"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a unix socket": func(t *testing.T, p *workertest.Pack) {
			if err := syscall.Mknod(filepath.Join(p.Dir, "sock"), syscall.S_IFSOCK|0o600, 0); err != nil {
				t.Skipf("cannot make a socket node here: %v", err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := startNuclei(t, printJSONL)
			plant(t, r.pack)
			r.core.push(r.job(id1))
			if got := r.core.next(t); got.res.Status != "refused" || got.res.Reason != "pack_invalid" {
				t.Fatalf("result = %+v", got.res)
			}
			if r.nu.Argv() != "" {
				t.Fatal("nuclei ran")
			}
		})
	}
	t.Run("the templates directory itself is a symlink", func(t *testing.T) {
		t.Parallel()
		r := startNuclei(t, printJSONL)
		moved := r.pack.Dir + "-real"
		if err := os.Rename(r.pack.Dir, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, r.pack.Dir); err != nil {
			t.Fatal(err)
		}
		r.core.push(r.job(id1))
		if got := r.core.next(t); got.res.Status != "refused" || got.res.Reason != "pack_invalid" {
			t.Fatalf("result = %+v", got.res)
		}
	})
}

// stderr is never posted, and output over 4 MiB is cut at 4 MiB and flagged.
func TestNucleiStderrIsNeverPostedAndOutputIsCapped(t *testing.T) {
	t.Parallel()
	t.Run("stderr", func(t *testing.T) {
		t.Parallel()
		r := startNuclei(t, workertest.StderrNoise)
		r.core.push(r.job(id1))
		got := r.core.next(t)
		raw := jsonOf(got.res)
		if got.res.Status != "done" || strings.Contains(raw, "SECRET-ON-STDERR") || strings.Contains(string(got.res.JSONL()), "SECRET") {
			t.Fatalf("result = %s", raw)
		}
	})
	t.Run("truncated", func(t *testing.T) {
		t.Parallel()
		r := startNuclei(t, workertest.BigOutput)
		r.core.push(r.job(id1))
		got := r.core.next(t)
		if got.res.Status != "done" || !got.res.Truncated || len(got.res.JSONL()) != nucleiargv.MaxOutput || nucleiargv.MaxOutput != sensorlink.MaxResultJSONL {
			t.Fatalf("status %s truncated %v jsonl %d", got.res.Status, got.res.Truncated, len(got.res.JSONL()))
		}
	})
	t.Run("exit 2 posts no output", func(t *testing.T) {
		t.Parallel()
		r := startNuclei(t, "echo partial; echo oops >&2; exit 2")
		r.core.push(r.job(id1))
		got := r.core.next(t)
		if got.res.Status != "failed" || got.res.ExitCode != 2 || got.res.JSONLB64 != "" {
			t.Fatalf("result = %+v", got.res)
		}
	})
}

func jsonOf(r sensorlink.JobResult) string {
	return fmt.Sprintf("%+v|%s", r, base64.StdEncoding.EncodeToString(r.JSONL()))
}

// D-125 (2): a cancel kills the whole process group (the SIGTERM-ignoring script and its child), and the result is
// stopped/cancelled; so do the job's deadline, the lease, a new core instance and the worker's own shutdown.
func TestNucleiProcessGroupDiesWhenItMust(t *testing.T) {
	t.Parallel()
	gone := func(t *testing.T, r *nrig, pid, child int) {
		t.Helper()
		waitFor(t, "the process group to die", func() bool { return !r.nu.Alive(pid) && !r.nu.Alive(child) })
	}
	t.Run("cancel", func(t *testing.T) {
		t.Parallel()
		r := startNuclei(t, workertest.Sleeper)
		r.core.push(r.job(id1))
		pid, child := r.nu.PID(t, "nuclei.pid"), r.nu.PID(t, "child.pid")
		r.core.cancelJob(id1)
		got := r.core.next(t)
		if got.res.Status != "stopped" || got.res.Reason != "cancelled" || got.res.JSONLB64 != "" {
			t.Fatalf("result = %+v", got.res)
		}
		gone(t, r, pid, child)
	})
	t.Run("deadline", func(t *testing.T) {
		t.Parallel()
		r := startNuclei(t, workertest.Sleeper)
		j := r.job(id1)
		j.TimeoutS = 1
		r.core.push(j)
		pid, child := r.nu.PID(t, "nuclei.pid"), r.nu.PID(t, "child.pid")
		got := r.core.next(t)
		if got.res.Status != "stopped" || got.res.Reason != "deadline" {
			t.Fatalf("result = %+v", got.res)
		}
		gone(t, r, pid, child)
	})
	t.Run("lease", func(t *testing.T) {
		t.Parallel()
		r := startNuclei(t, workertest.Sleeper)
		r.core.push(r.job(id1))
		pid, child := r.nu.PID(t, "nuclei.pid"), r.nu.PID(t, "child.pid")
		r.core.fail(sensorlink.NewError(sensorlink.CodeInternal))
		r.clock.Advance(worker.Lease + time.Second)
		gone(t, r, pid, child)
		r.core.noResult(t, 300*time.Millisecond)
	})
	t.Run("instance", func(t *testing.T) {
		t.Parallel()
		r := startNuclei(t, workertest.Sleeper)
		r.core.push(r.job(id1))
		pid, child := r.nu.PID(t, "nuclei.pid"), r.nu.PID(t, "child.pid")
		r.core.setInstance(strings.Repeat("b", 32))
		gone(t, r, pid, child)
		r.core.noResult(t, 300*time.Millisecond)
	})
	t.Run("shutdown", func(t *testing.T) {
		t.Parallel()
		r := startNuclei(t, workertest.Sleeper)
		r.core.push(r.job(id1))
		pid, child := r.nu.PID(t, "nuclei.pid"), r.nu.PID(t, "child.pid")
		r.stop()
		gone(t, r, pid, child)
		r.core.noResult(t, 100*time.Millisecond)
	})
}

// The heartbeat says whether nuclei runs, its version (nuclei prints it on stderr) and the pack of the image.
func TestNucleiHeartbeat(t *testing.T) {
	t.Parallel()
	next := func(t *testing.T, r *rig) sensorlink.ActiveHeartbeat {
		t.Helper()
		select {
		case hb := <-r.core.beats:
			return hb
		case <-time.After(10 * time.Second):
			t.Fatal("no heartbeat")
			return sensorlink.ActiveHeartbeat{}
		}
	}
	t.Run("present", func(t *testing.T) {
		t.Parallel()
		r := startNuclei(t, printJSONL)
		hb := next(t, r.rig)
		if !hb.Nuclei.Present || hb.Nuclei.Version != "v3.3.7" || hb.Nuclei.Pack.Version != r.pack.Version || hb.Nuclei.Pack.SHA256 != r.pack.SHA256 {
			t.Fatalf("heartbeat = %+v", hb.Nuclei)
		}
		if !hb.Nmap.Present {
			t.Fatalf("nmap went missing: %+v", hb)
		}
	})
	t.Run("nuclei missing", func(t *testing.T) {
		t.Parallel()
		r := startNuclei(t, printJSONL, func(c *worker.Config) { c.NucleiPath = filepath.Join(t.TempDir(), "no-nuclei-here") })
		hb := next(t, r.rig)
		if hb.Nuclei.Present || hb.Nuclei.Version != "" || hb.Nuclei.Pack.SHA256 == "" {
			t.Fatalf("heartbeat = %+v", hb.Nuclei)
		}
		r.core.push(r.job(id1)) // still answered: nuclei_missing
		if got := r.core.next(t); got.res.Status != "failed" || got.res.Reason != "nuclei_missing" {
			t.Fatalf("result = %+v", got.res)
		}
	})
	t.Run("no pack", func(t *testing.T) {
		t.Parallel()
		r := startNuclei(t, printJSONL)
		if err := os.Remove(r.pack.Index); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "a heartbeat without a pack", func() bool {
			hb := next(t, r.rig)
			return hb.Nuclei.Present && hb.Nuclei.Pack.SHA256 == ""
		})
	})
	t.Run("a worker set up for nmap only", func(t *testing.T) {
		t.Parallel()
		r := start(t, writeNmap(t, printXML))
		hb := next(t, r)
		if hb.Nuclei.Present || hb.Nuclei.Version != "" || hb.Nuclei.Pack.SHA256 != "" {
			t.Fatalf("heartbeat = %+v", hb.Nuclei)
		}
		j := sensorlink.Job{ID: id1, Kind: sensorlink.KindNuclei, TimeoutS: 5, Nuclei: &sensorlink.NucleiJob{Pack: sensorlink.JobPack{Version: "2026.11.10", SHA256: strings.Repeat("a", 64)}, Templates: []string{"CVE-2024-1"}, Targets: []sensorlink.NucleiTarget{{Host: "192.168.10.20", Port: 80}}, Rate: 1, MaxHostErrors: 2}}
		r.core.push(j)
		if got := r.core.next(t); got.res.Status != "failed" || got.res.Reason != "nuclei_missing" {
			t.Fatalf("result = %+v", got.res)
		}
	})
}

// A job without a kind is an nmap job (a core of protocol 1 sent none), and a nuclei-configured worker still runs it.
func TestKindlessJobStillRunsAsNmap(t *testing.T) {
	t.Parallel()
	r := startNuclei(t, printJSONL)
	j := job(id1)
	if j.Kind != "" {
		t.Fatal("the helper sets a kind")
	}
	r.core.push(j)
	got := r.core.next(t)
	if got.res.Status != "done" || !strings.Contains(string(got.xml), "192.168.10.20") || got.res.JSONLB64 != "" {
		t.Fatalf("result = %+v", got.res)
	}
	if r.nu.Argv() != "" {
		t.Fatal("nuclei ran for an nmap job")
	}
	r.core.push(sensorlink.Job{ID: id2, Kind: sensorlink.KindNmap, Shape: "normal", Rate: 100, Targets: []string{"192.168.10.20"}, TimeoutS: 60})
	if got := r.core.next(t); got.id != id2 || got.res.Status != "done" {
		t.Fatalf("result = %+v", got.res)
	}
}

// D-165, INV-6: nuclei's error log (-elog /dev/stderr) is counted per target into host_errors, and stderr itself is never
// posted. The error-log lines are HAND-MADE in the shape of nuclei v3.11.1 (JSONLogRequest), not recorded; the lab check
// with the real binary is a deferred item.
func TestNucleiHostErrorsAreCountedFromTheErrorLog(t *testing.T) {
	t.Parallel()
	lines := []string{
		`{"template":"a.yaml","type":"http","input":"10.0.0.7:22","address":"10.0.0.7:22","error":"i/o timeout SECRET-IN-LOG","kind":"network-temporary-error"}`,
		`{"template":"b.yaml","type":"tcp","input":"10.0.0.7:22","address":"10.0.0.7:22","error":"i/o timeout","kind":"network-temporary-error"}`,
		`{"template":"a.yaml","type":"tcp","input":"10.0.0.7:22","address":"10.0.0.7:22","error":"i/o timeout","kind":"network-temporary-error"}`,
		`{"template":"a.yaml","type":"http","input":"http://192.168.10.20:8080","address":"192.168.10.20:8080","error":"connection refused","kind":"network-permanent-error"}`,
		`{"template":"a.yaml","type":"http","input":"http://192.168.10.20:8080","address":"192.168.10.20:8080","error":"i/o timeout","kind":"network-temporary-error"}`,
		`{"template":"a.yaml","type":"http","input":"http://192.168.10.99:80","address":"192.168.10.99:80","error":"i/o timeout","kind":"network-temporary-error"}`,
	}
	r := startNuclei(t, "cat >&2 <<'EOF'\n"+strings.Join(lines, "\n")+"\nEOF\n"+printJSONL)
	r.core.push(r.job(id1))
	got := r.core.next(t)
	want := []sensorlink.HostError{{Target: "192.168.10.20:8080", Errors: 1}, {Target: "10.0.0.7:22", Errors: 3, Unreachable: true}}
	raw := jsonOf(got.res)
	if got.res.Status != "done" || !slices.Equal(got.res.HostErrors, want) || strings.Contains(raw, "SECRET-IN-LOG") || string(got.res.JSONL()) != jsonlLine {
		t.Fatalf("result = %s", raw)
	}
	if !slices.Contains(strings.Split(strings.TrimSpace(r.nu.Argv()), "\n"), "-elog") {
		t.Fatalf("nuclei was not asked for its error log: %s", r.nu.Argv())
	}
}

// host_errors has one entry per target at most, so its cap is the job's target cap.
func TestHostErrorsCapIsTheTargetCap(t *testing.T) {
	t.Parallel()
	if sensorlink.MaxHostErrors != nucleiargv.MaxTargets {
		t.Fatalf("sensorlink.MaxHostErrors %d, nucleiargv.MaxTargets %d", sensorlink.MaxHostErrors, nucleiargv.MaxTargets)
	}
}

// A run that fails or is stopped carries no host errors, and a quiet stderr carries none.
func TestNucleiNoHostErrorsWhenNothingTimedOut(t *testing.T) {
	t.Parallel()
	r := startNuclei(t, "echo '[INF] hello' >&2\n"+printJSONL)
	r.core.push(r.job(id1))
	if got := r.core.next(t); got.res.Status != "done" || len(got.res.HostErrors) != 0 {
		t.Fatalf("result = %+v", got.res)
	}
}

// Truncated means stdout: a flood on stderr (kept to 64 KiB in memory, never posted) does not make a good run "truncated".
func TestNucleiStderrFloodDoesNotMeanTruncated(t *testing.T) {
	t.Parallel()
	r := startNuclei(t, "head -c 5242880 /dev/zero >&2\n"+printJSONL)
	r.core.push(r.job(id1))
	got := r.core.next(t)
	if got.res.Status != "done" || got.res.Truncated || string(got.res.JSONL()) != jsonlLine {
		t.Fatalf("result = %+v", got.res)
	}
}
