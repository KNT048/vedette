// Package workertest holds what tests of the worker and of the Dispatcher share for the nuclei job: a template pack on disk
// with its index, and a fake nuclei (a shell script run through the real core/exec). No test runs the real nuclei or sends a
// packet. Only tests import it.
package workertest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/knt048/vedette/core/exec"
	"github.com/knt048/vedette/core/exec/exectest"
)

// Pack is a template pack of a test: the files under Dir and the index that names them.
type Pack struct {
	Dir     string // where the worker reads the templates (Config.TemplatesDir)
	Index   string // path of index.json (Config.NucleiIndex)
	Version string
	SHA256  string
	Paths   map[string]string // template id -> path relative to the templates directory
}

// NewPack writes one template file per id (kev-tagged, with a CVE derived from its position) and the index.
func NewPack(t testing.TB, ids ...string) *Pack {
	t.Helper()
	root := t.TempDir()
	p := &Pack{Dir: filepath.Join(root, "templates"), Index: filepath.Join(root, "index.json"), Version: "2026.11.10", Paths: map[string]string{}}
	sum := sha256.Sum256([]byte(strings.Join(ids, ",")))
	p.SHA256 = hex.EncodeToString(sum[:])
	type tmpl struct {
		ID      string   `json:"id"`
		CVE     string   `json:"cve"`
		Path    string   `json:"path"`
		SHA256  string   `json:"sha256"`
		Tags    []string `json:"tags"`
		Request string   `json:"request"`
		OwnIP   bool     `json:"own_ip,omitempty"`
		Sets    []string `json:"sets"` // D-527: kev, and deep so a full job may run it too
		Name    string   `json:"name"`
		Sev     string   `json:"severity"`
	}
	var ts []tmpl
	for i, id := range ids {
		rel := "http/cves/" + strings.ToLower(id) + ".yaml"
		body := []byte("id: " + id + "\ninfo:\n  name: test " + strconv.Itoa(i) + "\n")
		full := filepath.Join(p.Dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil { //nolint:gosec // a test's temp directory
			t.Fatal(err)
		}
		if err := os.WriteFile(full, body, 0o644); err != nil { //nolint:gosec // a test's temp file
			t.Fatal(err)
		}
		h := sha256.Sum256(body)
		ts = append(ts, tmpl{ID: id, CVE: fmt.Sprintf("CVE-2024-%04d", i+1), Path: rel, SHA256: hex.EncodeToString(h[:]), Tags: []string{"kev"}, Request: "GET / HTTP/1.1", OwnIP: true,
			Sets: []string{"kev", "deep"}, Name: "test " + strconv.Itoa(i), Sev: "high"})
		p.Paths[id] = rel
	}
	raw, err := json.Marshal(map[string]any{"version": p.Version, "sha256": p.SHA256, "templates": ts})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.Index, raw, 0o644); err != nil { //nolint:gosec // a test's temp file
		t.Fatal(err)
	}
	return p
}

// File is the full path of the template file of id.
func (p *Pack) File(id string) string { return filepath.Join(p.Dir, filepath.FromSlash(p.Paths[id])) }

// Nuclei is a fake nuclei: it answers -version on stderr like the real one, records its argv and its environment, and then
// runs the body it was given (which may use $DIR and $HOME).
type Nuclei struct {
	Path string
	Dir  string
}

// NewNuclei writes the script. Whatever the script leaves alive when the test ends is killed and fails the test.
func NewNuclei(t testing.TB, body string) *Nuclei {
	t.Helper()
	dir := t.TempDir()
	script := fmt.Sprintf(`#!/bin/sh
DIR=%q
if [ "$1" = "-version" ]; then echo "[INF] Nuclei Engine Version: v3.3.7" >&2; exit 0; fi
printf '%%s\n' "$@" >> "$DIR/argv.log"
env > "$DIR/env.log"
ls -A "$HOME" > "$DIR/home.log"
echo $$ > "$DIR/nuclei.pid"
%s
`, dir, body)
	n := &Nuclei{Path: filepath.Join(dir, "nuclei"), Dir: dir}
	exectest.WriteScript(t, n.Path, script)
	t.Cleanup(func() {
		for _, name := range []string{"nuclei.pid", "child.pid"} {
			b, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // a file of the test's own temp directory
			if err != nil {
				continue
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
			if err != nil || pid < 2 {
				continue
			}
			for deadline := time.Now().Add(5 * time.Second); n.Alive(pid); <-time.After(20 * time.Millisecond) {
				if time.Now().After(deadline) {
					_ = syscall.Kill(pid, syscall.SIGKILL)
					t.Errorf("orphan process %d (%s) outlived the test", pid, name)
					break
				}
			}
		}
	})
	return n
}

func (n *Nuclei) read(name string) string {
	b, _ := os.ReadFile(filepath.Join(n.Dir, name)) //nolint:gosec // a file of the test's own temp directory
	return string(b)
}

// Argv is every argument of every run, one per line (empty: it never ran a job).
func (n *Nuclei) Argv() string { return n.read("argv.log") }

// Env is the environment of the latest run, one KEY=value per line.
func (n *Nuclei) Env() string { return n.read("env.log") }

// HomeListing is what the latest run found in its HOME when it started.
func (n *Nuclei) HomeListing() string { return n.read("home.log") }

// PID waits for the pid file of name ("nuclei.pid" or "child.pid") and returns it.
func (n *Nuclei) PID(t testing.TB, name string) int {
	t.Helper()
	var pid int
	for deadline := time.Now().Add(30 * time.Second); ; <-time.After(10 * time.Millisecond) {
		if v, err := strconv.Atoi(strings.TrimSpace(n.read(name))); err == nil {
			pid = v
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", name)
		}
	}
	return pid
}

var (
	psOnce   sync.Once
	psRunner *exec.Runner
)

// Alive says whether pid is a live process of this fake: not a zombie, and its command line holds the fake's directory or
// "sleep 300", so a pid the system has handed to something else since does not count (and is never killed).
func (n *Nuclei) Alive(pid int) bool {
	psOnce.Do(func() {
		psRunner, _ = exec.NewRunner(slog.New(slog.DiscardHandler), exec.Binary{Name: "ps", Path: "/bin/ps", MaxOutput: 64 << 10, Validate: func(a []string) error {
			if len(a) != 4 || a[0] != "-o" || a[1] != "stat=,command=" || a[2] != "-p" || strings.Trim(a[3], "0123456789") != "" {
				return fmt.Errorf("only ps -o stat=,command= -p PID")
			}
			return nil
		}})
	})
	if psRunner == nil || pid < 2 {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := psRunner.Run(ctx, "ps", []string{"-o", "stat=,command=", "-p", strconv.Itoa(pid)}, nil)
	if err != nil {
		return false
	}
	state, cmd, _ := strings.Cut(strings.TrimSpace(string(res.Stdout)), " ")
	return !strings.HasPrefix(state, "Z") && (strings.Contains(cmd, n.Dir) || strings.Contains(cmd, "sleep 300"))
}

// Bodies of the fake. A line of nuclei's -jsonl -ms output has "host" as host:port or as a URL in the shape every nuclei 3.x
// before 3.2 used (HostPort), and, from nuclei 3.2 on, possibly as a bare hostname with "port" and "url" apart (BareHost):
// the fixtures carry both (testdata/*.jsonl).
const (
	// Sleeper starts a grandchild, ignores SIGTERM and never finishes.
	Sleeper = `trap '' TERM
sleep 300 &
echo $! > "$DIR/child.pid"
wait
`
	// StderrNoise writes what a hostile target could make nuclei say on stderr, then one JSONL line.
	StderrNoise = `echo "token=SECRET-ON-STDERR" >&2
echo '{"template-id":"CVE-2024-1","host":"192.168.10.20:8080","matcher-status":false}'
`
	// BigOutput prints 5 MiB.
	BigOutput = `head -c 5242880 /dev/zero | tr '\0' 'a'
`
)
