package main

// The sensors of the real-backend end-to-end run (WP-30 slice 7): the box opens its sensor link (-sensor-listen on a loopback port,
// credentials under <dir>/creds) and the specs start the REAL `vedette-sensor` binary as a child through the control endpoint:
//
//	POST   /sensors/passive {"replay":"lan-discovery"}  -> 204; `vedette-sensor passive -replay <recording>` (the recordings of
//	                                                       modules/sensor-passive/testdata; no card, no capture rights needed)
//	POST   /sensors/active  {}                          -> 204; `vedette-sensor active -nmap <fake nmap>`; the fake scans nothing: it answers
//	                                                       from the fixtures of modules/sensor-active/testdata by the shape of its argv (below)
//	DELETE /sensors/{role}                              -> 204; stops that child (a missing child is not an error)
//	GET    /sensors/active/argv                         -> {"lines": ["<argv of one nmap run>", ...]}, every run the fake nmap saw, oldest first
//
// The fake nmap: `--version` answers like nmap; "-sn" (the sweep) prints sweep.xml; "-T2" (the gentle first scan of a fragile or unknown
// device, INV-5) prints fragile.xml; anything else prints device.xml. sweep.xml also holds 203.0.113.9, which is outside every private
// range and must never be an argument of nmap or a device (INV-1: core sends only addresses of the confirmed range; and it keeps only the hosts it asked about). Every run appends its argv to a
// file first, so a spec can prove what the box actually sent.
//
// Everything here is a _test.go file: the production binary has none of it. The children are in the box's process group, so the
// script's group kill stops them too; they also stop with the box's context.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec" //nolint:depguard // test harness: starts the vedette-sensor binary the script built, fixed argv, no shell; SYS-1 is about the product
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// e2eRecordings are the recordings a spec may replay (names, not paths: the control endpoint never takes a path).
var e2eRecordings = map[string]string{
	"lan-discovery":  "lan-discovery.pcap",
	"span-metadata":  "span-metadata.pcapng",
	"span-own-only":  "span-own-only.pcap",
	"malformed-pcap": "malformed.pcap",
}

// e2eRepoRoot is the repository root, found from this file (the test binary is built without -trimpath, as the fixtures of opstest need).
func e2eRepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// e2eSensors holds the box side of the sensors: where the link is, where its credentials are, and the running children.
type e2eSensors struct {
	ctx   context.Context
	bin   string // the vedette-sensor binary
	dir   string // the box folder: creds, the fake nmap and its argv log
	creds string

	ctl  sync.Mutex // one start or stop at a time: the stop-then-start of a role must not interleave with another call
	mu   sync.Mutex
	addr string // the sensor link's address, "" until the box logs it
	kids map[string]*e2eKid
	nmap string // the fake nmap, written once (a running sensor may be executing it)
}

type e2eKid struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func newE2ESensors(ctx context.Context, bin, dir string) *e2eSensors {
	return &e2eSensors{ctx: ctx, bin: bin, dir: dir, creds: filepath.Join(dir, "creds"), kids: map[string]*e2eKid{}}
}

// linkUp is called by the box log when core logs "sensor link listening".
func (s *e2eSensors) linkUp(addr string) {
	s.mu.Lock()
	s.addr = addr
	s.mu.Unlock()
}

func (s *e2eSensors) argvLog() string { return filepath.Join(s.dir, "nmap-argv.log") }

// fakeNmap writes the fake nmap script on first use and returns its path.
func (s *e2eSensors) fakeNmap() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nmap != "" {
		return s.nmap, nil
	}
	root := filepath.Join(e2eRepoRoot(), "modules", "sensor-active", "testdata")
	// A device scan (one target, the last argument) is answered with the fixture re-addressed to that target, so the result is about the
	// device that was asked for (core keeps only the targets it asked for, INV-7): device.xml is a Linux server with ssh and two web
	// services, fragile.xml an embedded printer.
	body := fmt.Sprintf(`#!/bin/sh
case "$1" in --version) echo "Nmap version 7.95 ( https://nmap.org )"; exit 0;; esac
echo "$*" >> '%[1]s'
for last; do :; done
case " $* " in
*" -sn "*) cat '%[2]s/sweep.xml';;
*" -T2 "*) sed "s/192\.168\.10\.30/$last/g" '%[2]s/fragile.xml';;
*) sed "s/192\.168\.10\.20/$last/g" '%[2]s/device.xml';;
esac
`, s.argvLog(), root)
	path := filepath.Join(s.dir, "fake-nmap")
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil { //nolint:gosec // a fake program must be executable
		return "", err
	}
	s.nmap = path
	return path, nil
}

// start (re)starts the sensor of role with its own arguments.
func (s *e2eSensors) start(role string, extra []string) error {
	s.ctl.Lock()
	defer s.ctl.Unlock()
	s.mu.Lock()
	addr := s.addr
	s.mu.Unlock()
	if addr == "" {
		return fmt.Errorf("the sensor link is not listening yet")
	}
	s.stopLocked(role)
	logf, err := os.OpenFile(filepath.Join(s.dir, "sensor-"+role+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // test harness: the folder is the one the script made
	if err != nil {
		return err
	}
	args := append([]string{role, "-core", "https://" + addr, "-creds", filepath.Join(s.creds, role, "sensor.pem")}, extra...)
	cmd := exec.CommandContext(s.ctx, s.bin, args...) //nolint:gosec // test harness: the binary is the one the script built
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		_ = logf.Close()
		return err
	}
	k := &e2eKid{cmd: cmd, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); _ = logf.Close(); close(k.done) }()
	s.mu.Lock()
	s.kids[role] = k
	s.mu.Unlock()
	return nil
}

func (s *e2eSensors) stop(role string) {
	s.ctl.Lock()
	defer s.ctl.Unlock()
	s.stopLocked(role)
}

func (s *e2eSensors) stopLocked(role string) {
	s.mu.Lock()
	k := s.kids[role]
	delete(s.kids, role)
	s.mu.Unlock()
	if k == nil {
		return
	}
	_ = k.cmd.Process.Signal(os.Interrupt)
	select {
	case <-k.done:
	case <-time.After(6 * time.Second):
		_ = k.cmd.Process.Kill()
		<-k.done
	}
}

func (s *e2eSensors) stopAll() {
	for _, r := range []string{"passive", "active"} {
		s.stop(r)
	}
}

// routes adds the sensor calls to the control mux (the token check is the control server's).
func (s *e2eSensors) routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /sensors/passive", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Replay string `json:"replay"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		file, ok := e2eRecordings[in.Replay]
		if !ok {
			http.Error(w, "unknown recording", http.StatusBadRequest)
			return
		}
		pcap := filepath.Join(e2eRepoRoot(), "modules", "sensor-passive", "testdata", file)
		if err := s.start("passive", []string{"-replay", pcap}); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /sensors/active", func(w http.ResponseWriter, _ *http.Request) {
		nmap, err := s.fakeNmap()
		if err == nil {
			err = s.start("active", []string{"-nmap", nmap})
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("DELETE /sensors/{role}", func(w http.ResponseWriter, r *http.Request) {
		role := r.PathValue("role")
		if role != "passive" && role != "active" {
			http.Error(w, "unknown role", http.StatusBadRequest)
			return
		}
		s.stop(role)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /sensors/active/argv", func(w http.ResponseWriter, _ *http.Request) {
		b, err := os.ReadFile(s.argvLog()) //nolint:gosec // test harness: a file in the folder the script made, not taken from a request
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
