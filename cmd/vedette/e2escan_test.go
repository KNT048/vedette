package main

// The scan worker of the real-backend end-to-end run (D-427): the REAL worker of sensor-active (modules/sensor-active/worker), started in
// this process on the box's real sensor link with the credentials of the active sensor, running a FAKE nuclei that sends nothing anywhere.
// The vedette-sensor binary cannot be used for this: it reads the template pack from the fixed path of the scan image
// (nucleiargv.TemplatesDir), which a development machine does not have; worker.Config.TemplatesDir is the test seam for that.
//
//	POST /sensors/scan {"nuclei": "match"|"nomatch"|"hang"|"dead"} -> 204; starts the worker when it is not running (it takes the place of an
//	                                                                   active vedette-sensor child: one worker per link) and sets what the fake
//	                                                                   nuclei answers from its next run on
//	DELETE /sensors/active                                          -> 204; stops it (the same slot as the child)
//	GET  /sensors/scan/argv                                         -> {"lines": ["<argv of one nuclei run>", ...]}, oldest first
//
// The pack the worker holds is the committed index (content/nucleipack) with the same version and hash, so core's job passes the pack check
// of both the Dispatcher and the worker; each template file is a stand-in and the index carries its hash, so the worker's file check runs for
// real. The fake nuclei reads the template ids from the -t paths (a pack template id is its file name) and the targets from -u:
//
//	match   the first target of each template matches (with a request and a response), every other line is a non-match
//	nomatch every template and target is a non-match
//	hang    never answers (Stop now)
//	dead    every line is an error, so the device "stops responding" (INV-6)
//
// Everything here is a _test.go file: the production binary has none of it.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	osexec "os/exec" //nolint:depguard // test harness: runs the fake nuclei this file wrote, fixed argv, no shell; SYS-1 is about the product
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/knt048/vedette/content/nucleipack"
	"github.com/knt048/vedette/core/sensorlink"
	"github.com/knt048/vedette/modules/scan/nucleiargv"
	"github.com/knt048/vedette/modules/scan/nucleiout"
	"github.com/knt048/vedette/modules/scan/pack"
	"github.com/knt048/vedette/modules/sensor-active/worker"
)

// e2eScanModes are what the fake nuclei can answer.
var e2eScanModes = map[string]bool{"match": true, "nomatch": true, "hang": true, "dead": true}

// e2eScanFakes are the files of the scan worker, under <box dir>/scan.
type e2eScanFakes struct {
	dir, templates, index, nuclei, nmap string
}

func (f *e2eScanFakes) modeFile() string { return filepath.Join(f.dir, "nuclei-mode") }
func (f *e2eScanFakes) argvLog() string  { return filepath.Join(f.dir, "nuclei-argv.log") }

// e2eFakeNuclei answers `-version` like nuclei 3, logs its argv, then prints JSON lines by the mode file (see the top of the file).
const e2eFakeNuclei = `#!/bin/sh
if [ "$1" = "-version" ]; then echo "[INF] Nuclei Engine Version: v3.3.7" >&2; exit 0; fi
echo "$*" >> '@ARGV@'
mode=$(cat '@MODE@' 2>/dev/null)
if [ "$mode" = hang ]; then exec sleep 300; fi
ids=''
hosts=''
while [ $# -gt 0 ]; do
	case "$1" in
	-t) ids="$ids ${2##*/}"; shift ;;
	-u) hosts="$hosts $2"; shift ;;
	esac
	shift
done
for f in $ids; do
	id=${f%.yaml}
	first=1
	for u in $hosts; do
		hp=${u#*://}
		if [ "$mode" = dead ]; then
			printf '{"template-id":"%s","host":"%s","matcher-status":false,"error":"context deadline exceeded"}\n' "$id" "$hp"
		elif [ "$mode" = match ] && [ $first = 1 ]; then
			printf '{"template-id":"%s","host":"%s","matcher-status":true,"request":"GET / HTTP/1.1\\r\\nHost: %s\\r\\n\\r\\n","response":"HTTP/1.1 200 OK\\r\\n\\r\\ne2e fixture: the vulnerable page"}\n' "$id" "$hp" "$hp"
		else
			printf '{"template-id":"%s","host":"%s","matcher-status":false}\n' "$id" "$hp"
		fi
		first=0
	done
done
`

// scanFakes writes the pack, the fake nuclei and a fake nmap of its own on first use (its own argv log: the sensors spec reads the other one).
func (s *e2eSensors) scanFakes() (*e2eScanFakes, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scan != nil {
		return s.scan, nil
	}
	dir := filepath.Join(s.dir, "scan")
	f := &e2eScanFakes{dir: dir, templates: filepath.Join(dir, "templates"), index: filepath.Join(dir, "index.json"), nuclei: filepath.Join(dir, "nuclei"), nmap: filepath.Join(dir, "nmap")}
	ix, err := nucleipack.Index()
	if err != nil {
		return nil, err
	}
	out := pack.Index{Version: ix.Version, SHA256: ix.SHA256, Templates: make([]pack.Template, len(ix.Templates))}
	for i, t := range ix.Templates {
		body := []byte("id: " + t.ID + "\n# a stand-in of the end-to-end run: the fake nuclei never reads it\n")
		full := filepath.Join(f.templates, filepath.FromSlash(t.Path))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(full, body, 0o600); err != nil {
			return nil, err
		}
		sum := sha256.Sum256(body)
		t.SHA256 = hex.EncodeToString(sum[:])
		out.Templates[i] = t
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(f.index, raw, 0o600); err != nil {
		return nil, err
	}
	script := strings.NewReplacer("@ARGV@", f.argvLog(), "@MODE@", f.modeFile()).Replace(e2eFakeNuclei)
	if err := os.WriteFile(f.nuclei, []byte(script), 0o700); err != nil { //nolint:gosec // a fake program must be executable
		return nil, err
	}
	if err := writeFakeNmap(f.nmap, filepath.Join(dir, "nmap-argv.log")); err != nil {
		return nil, err
	}
	s.scan = f
	return f, nil
}

// startScan starts the in-process worker in the slot of the active sensor, unless it already runs there.
func (s *e2eSensors) startScan(f *e2eScanFakes) error {
	s.ctl.Lock()
	defer s.ctl.Unlock()
	s.mu.Lock()
	addr, cur := s.addr, s.kids["active"]
	s.mu.Unlock()
	if cur != nil && cur.cmd == nil {
		return nil
	}
	if addr == "" {
		return errors.New("the sensor link is not listening yet")
	}
	s.stopLocked("active")
	client, err := sensorlink.NewClient(sensorlink.ClientOptions{BaseURL: "https://" + addr, CredsPath: filepath.Join(s.creds, "active", "sensor.pem")})
	if err != nil {
		return err
	}
	logf, err := os.OpenFile(filepath.Join(s.dir, "sensor-scan.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // test harness: the folder is the one the script made
	if err != nil {
		return err
	}
	w, err := worker.New(worker.Config{Link: client, NmapPath: f.nmap, Version: "1.0.0", Log: slog.New(slog.NewJSONHandler(logf, nil)),
		NucleiPath: f.nuclei, NucleiIndex: f.index, NucleiHome: filepath.Join(f.dir, "home"), TemplatesDir: f.templates, Heartbeat: 5 * time.Second})
	if err != nil {
		_ = logf.Close()
		return err
	}
	ctx, cancel := context.WithCancel(s.ctx)
	k := &e2eKid{cancel: cancel, done: make(chan struct{})}
	go func() { _ = w.Run(ctx); _ = logf.Close(); close(k.done) }()
	s.mu.Lock()
	s.kids["active"] = k
	s.mu.Unlock()
	return nil
}

func (s *e2eSensors) scanRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /sensors/scan", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Nuclei string `json:"nuclei"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil || !e2eScanModes[in.Nuclei] {
			http.Error(w, "nuclei must be match, nomatch, hang or dead", http.StatusBadRequest)
			return
		}
		f, err := s.scanFakes()
		if err == nil {
			err = os.WriteFile(f.modeFile(), []byte(in.Nuclei), 0o600)
		}
		if err == nil {
			err = s.startScan(f)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /sensors/scan/argv", func(w http.ResponseWriter, _ *http.Request) {
		f, err := s.scanFakes()
		var b []byte
		if err == nil {
			b, err = os.ReadFile(f.argvLog())
		}
		if err != nil && !os.IsNotExist(err) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		lines := []string{}
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if l != "" {
				lines = append(lines, l)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"lines": lines})
	})
}

// TestE2EScanFakes pins the fakes of the scan worker without starting a box: the worker's index is the committed pack with the same version and
// hash and a file per template that matches its hash, and the fake nuclei, given the argv core builds, prints lines core's parser accepts with
// the outcome of each mode.
func TestE2EScanFakes(t *testing.T) {
	s := &e2eSensors{dir: t.TempDir()}
	f, err := s.scanFakes()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(f.index)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pack.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	want, err := nucleipack.Index()
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != want.Version || got.SHA256 != want.SHA256 || len(got.Templates) != len(want.Templates) {
		t.Fatalf("index %s %s %d, want %s %s %d", got.Version, got.SHA256, len(got.Templates), want.Version, want.SHA256, len(want.Templates))
	}
	tpl := got.ForCVE("CVE-2002-1131")[0]
	body, err := os.ReadFile(filepath.Join(f.templates, filepath.FromSlash(tpl.Path))) //nolint:gosec // a file of the test's temp folder
	if sum := sha256.Sum256(body); err != nil || hex.EncodeToString(sum[:]) != tpl.SHA256 {
		t.Fatalf("the file of %s does not match its index entry: %v", tpl.ID, err)
	}
	if tpl.ID != strings.TrimSuffix(filepath.Base(tpl.Path), ".yaml") { // what the fake nuclei relies on
		t.Fatalf("template id %s is not its file name %s", tpl.ID, tpl.Path)
	}
	targets := []nucleiargv.Target{{Host: "10.1.100.1", Port: 80, Scheme: "http"}, {Host: "10.1.100.1", Port: 443, Scheme: "https"}}
	argv, err := nucleiargv.Build(nucleiargv.Job{Templates: []string{tpl.Path}, Targets: targets, Rate: 1, MaxHostErrors: 3})
	if err != nil {
		t.Fatal(err)
	}
	for mode, want := range map[string]string{"match": "true,false", "nomatch": "false,false", "dead": "error,error"} {
		if err := os.WriteFile(f.modeFile(), []byte(mode), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		out, err := osexec.CommandContext(ctx, f.nuclei, argv...).Output() //nolint:gosec // the fake this test wrote, fixed argv
		cancel()
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		res, err := nucleiout.Parse(out, []string{tpl.ID}, []string{"10.1.100.1:80", "10.1.100.1:443"})
		if err != nil {
			t.Fatalf("%s: %v\n%s", mode, err, out)
		}
		var seen []string
		for _, r := range res {
			switch {
			case r.Error != "":
				seen = append(seen, "error")
			default:
				seen = append(seen, strconv.FormatBool(r.Matched))
			}
		}
		if strings.Join(seen, ",") != want {
			t.Errorf("%s: %v, want %s", mode, seen, want)
		}
	}
}
