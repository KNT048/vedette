package honeypot_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knt048/vedette/modules/honeypot"
)

func (e *env) hitCount() int { return e.count(`SELECT count(*) FROM hp_hits`) }

func TestTailPartialLineWaitsForItsNewline(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	line := sshNew("192.168.10.157", 1, t0).json()
	if err := os.MkdirAll(filepath.Dir(e.logPath()), 0o750); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(e.logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(line[:40])
	e.poll()
	if e.hitCount() != 0 {
		t.Fatal("a half line was used")
	}
	_, _ = f.WriteString(line[40:] + "\n")
	e.poll()
	if e.hitCount() != 1 {
		t.Fatalf("%d hits", e.hitCount())
	}
	e.poll()
	if e.hitCount() != 1 || e.svc.Stats().Hits != 1 {
		t.Fatal("a second poll read the line again")
	}
}

func TestTailRotationAndTruncation(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	e.appendLog(sshNew("192.168.10.157", 1, t0).json(), sshNew("192.168.10.158", 2, t0.Add(time.Second)).json())
	e.poll()
	if e.hitCount() != 2 {
		t.Fatalf("%d", e.hitCount())
	}
	// rotation: the file is renamed and a new one starts (logrotate create)
	if err := os.Rename(e.logPath(), e.logPath()+".1"); err != nil {
		t.Fatal(err)
	}
	e.appendLog(sshNew("192.168.10.159", 3, t0.Add(2*time.Second)).json())
	e.poll()
	if e.hitCount() != 3 {
		t.Fatalf("after rotation %d hits", e.hitCount())
	}
	// the new file is longer than the old offset would suggest: the head tells it is a new file
	e.appendLog(sshNew("192.168.10.160", 4, t0.Add(3*time.Second)).json(), sshNew("192.168.10.161", 5, t0.Add(4*time.Second)).json(), sshNew("192.168.10.162", 6, t0.Add(5*time.Second)).json())
	e.poll()
	if e.hitCount() != 6 {
		t.Fatalf("%d", e.hitCount())
	}
	// truncation (copytruncate)
	if err := os.Truncate(e.logPath(), 0); err != nil {
		t.Fatal(err)
	}
	e.appendLog(sshNew("192.168.10.170", 7, t0.Add(6*time.Second)).json())
	e.poll()
	if e.hitCount() != 7 {
		t.Fatalf("after truncation %d hits", e.hitCount())
	}
	// replaced by a file of different content that is as long or longer
	if err := os.WriteFile(e.logPath(), []byte(strings.Repeat(sshNew("192.168.10.171", 8, t0.Add(7*time.Second)).json()+"\n", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	e.poll()
	if e.hitCount() != 8 {
		t.Fatalf("after replacement %d hits", e.hitCount())
	}
	if e.svc.Stats().Rotations < 2 {
		t.Fatalf("%+v", e.svc.Stats())
	}
	// the file disappears and comes back
	if err := os.Remove(e.logPath()); err != nil {
		t.Fatal(err)
	}
	e.poll()
	e.appendLog(sshNew("192.168.10.172", 9, t0.Add(8*time.Second)).json())
	e.poll()
	if e.hitCount() != 9 {
		t.Fatalf("after removal %d hits", e.hitCount())
	}
}

func TestTailDropsLongLinesAndCountsThem(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	huge := `{"logtype":4000,"src_host":"192.168.10.157","logdata":{"USERNAME":"` + strings.Repeat("x", honeypot.MaxLine) + `"}}`
	giant := `{"logtype":4000,"src_host":"192.168.10.158","logdata":{"USERNAME":"` + strings.Repeat("y", 200<<10) + `"}}`
	e.appendLog(sshNew("192.168.10.150", 1, t0).json(), huge, giant, sshNew("192.168.10.151", 2, t0.Add(time.Second)).json())
	e.poll()
	if e.hitCount() != 2 {
		t.Fatalf("%d hits", e.hitCount())
	}
	if st := e.svc.Stats(); st.TooLong != 2 {
		t.Fatalf("%+v", st)
	}
	// a long line that is still being written is dropped as soon as it is too long, and its rest is skipped
	f, _ := os.OpenFile(e.logPath(), os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"logtype":4000,"src_host":"192.168.10.152","logdata":{"U":"` + strings.Repeat("z", honeypot.MaxLine+10))
	e.poll()
	_, _ = f.WriteString(strings.Repeat("z", 1000) + "\"}}\n" + sshNew("192.168.10.153", 3, t0.Add(2*time.Second)).json() + "\n")
	_ = f.Close()
	e.poll()
	if e.hitCount() != 3 {
		t.Fatalf("%d hits", e.hitCount())
	}
	if st := e.svc.Stats(); st.TooLong != 3 {
		t.Fatalf("%+v", st)
	}
}

func TestTailResumesAfterRestartWithoutReplay(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	e.appendLog(sshNew("192.168.10.157", 1, t0).json())
	e.poll()
	svc2, err := honeypot.New(e.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.appendLog(sshNew("192.168.10.158", 2, t0.Add(time.Second)).json())
	if err := svc2.Poll(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if e.hitCount() != 2 || len(e.pub.all()) != 2 {
		t.Fatalf("%d hits, %d published: the restart replayed or lost lines", e.hitCount(), len(e.pub.all()))
	}
	// even a replay from zero (the saved position lost) changes nothing: one connection is one hit
	if _, err := e.db.Reader().ExecContext(e.ctx(), `SELECT 1`); err != nil {
		t.Fatal(err)
	}
	if err := e.db.Write(e.ctx(), func(tx *sqlTx) error {
		_, err := tx.ExecContext(e.ctx(), `DELETE FROM hp_config WHERE key = 'tail'`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	svc3, _ := honeypot.New(e.cfg)
	if err := svc3.Poll(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if e.hitCount() != 2 || len(e.pub.all()) != 2 {
		t.Fatalf("replay made %d hits, %d published", e.hitCount(), len(e.pub.all()))
	}
}

func TestIngestCapsOneSourceFlood(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	var lines []string
	for i := range 500 {
		lines = append(lines, sshNew("192.168.10.157", 1000+i, t0).json())
	}
	lines = append(lines, sshNew("192.168.10.158", 1, t0).json())
	e.appendLog(lines...)
	e.poll()
	if n := e.hitCount(); n != 201 {
		t.Fatalf("%d hits", n)
	}
	if e.svc.Stats().Flooded != 300 {
		t.Fatalf("%+v", e.svc.Stats())
	}
}

func TestIngestSkipsLogtypesItDoesNotMap(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.setup()
	e.appendLog(
		`{"logtype":1001,"src_host":"","dst_host":"","logdata":{"msg":"boot"}}`,
		ln{LogType: 1004, Src: "192.168.10.157", At: t0}.json(),
		ln{LogType: 5001, Src: "192.168.10.157", Dst: "192.168.10.241", DstPort: 3306, At: t0}.json(),
		ln{LogType: 5002, Src: "192.168.10.157", Dst: "192.168.10.241", DstPort: 3307, At: t0.Add(time.Minute)}.json(), // the same sweep
		ln{LogType: 14001, Src: "192.168.10.157", SrcPort: 7, Dst: "192.168.10.240", DstPort: 3389, At: t0, Data: map[string]any{"USERNAME": "admin", "DOMAIN": "x"}}.json(),
		ln{LogType: 9001, Src: "192.168.10.157", SrcPort: 8, Dst: "192.168.10.240", DstPort: 1433, At: t0, Data: map[string]any{"USERNAME": "sa", "PASSWORD": "p"}}.json(),
		ln{LogType: 3000, Src: "192.168.10.157", SrcPort: 9, Dst: "192.168.10.240", DstPort: 80, At: t0, Data: map[string]any{"PATH": "/admin", "USERAGENT": "curl/8"}}.json(),
		ln{LogType: 5000, Src: "192.168.10.157", At: t0, Data: map[string]any{"FILENAME": "x.txt"}}.json(),
	)
	e.poll()
	hits, _ := e.svc.Hits(e.ctx(), honeypot.HitFilter{})
	got := map[string]int{}
	for _, h := range hits {
		got[string(h.Kind)+"/"+fmt.Sprint(h.Service)]++
		if h.Kind == honeypot.KindService && h.Port == nil {
			t.Fatalf("no port: %+v", h)
		}
	}
	if len(hits) != 5 || got["scan/<nil>"] != 1 {
		t.Fatalf("%v", got)
	}
	var smb honeypot.Hit
	for _, h := range hits {
		if h.Service != nil && *h.Service == honeypot.SMB {
			smb = h
		}
	}
	if *smb.Port != 445 {
		t.Fatalf("smb port %d", *smb.Port)
	}
	d, _ := e.svc.HitDetail(e.ctx(), smb.ID)
	if d.TrapIP != "192.168.10.240" {
		t.Fatalf("trap ip %q: a line without a destination falls back to the secondary IP", d.TrapIP)
	}
}

// The run loop applies the state, tails the log, and stops with the context; a module that was switched off takes the
// container and the IPs down (SYS-5).
func TestRunAppliesPollsAndSwitchesOff(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(e *env) { e.cfg.PollEvery = 10 * time.Millisecond })
	e.setup()
	ctx, cancel := context.WithCancel(e.ctx())
	var wg sync.WaitGroup
	wg.Add(1)
	var runErr error
	go func() { defer wg.Done(); runErr = e.svc.Run(ctx) }()
	waitFor(t, "container started", func() bool { return e.host.isRunning() })
	e.appendLog(sshNew("192.168.10.157", 1, t0).json())
	waitFor(t, "hit", func() bool { return e.hitCount() == 1 })
	if _, err := e.svc.SetTrap(e.ctx(), "a", honeypot.RDP, true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "kick applied", func() bool {
		b, _ := os.ReadFile(filepath.Join(e.dir, "vol", honeypot.ConfFile))
		return strings.Contains(string(b), `"rdp.enabled": true`)
	})
	e.gate.set(true) // the module is switched off, then the scheduler cancels the job
	cancel()
	wg.Wait()
	if runErr != nil {
		t.Fatal(runErr)
	}
	if e.host.isRunning() || e.host.ipCount() != 0 {
		t.Fatalf("module off but running=%v ips=%d", e.host.isRunning(), e.host.ipCount())
	}
	if e.hitCount() != 1 {
		t.Fatal("data lost")
	}
}

func TestRunStoppedByShutdownLeavesTrapsUp(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(e *env) { e.cfg.PollEvery = 10 * time.Millisecond })
	e.setup()
	ctx, cancel := context.WithCancel(e.ctx())
	done := make(chan error, 1)
	go func() { done <- e.svc.Run(ctx) }()
	waitFor(t, "container started", func() bool { return e.host.isRunning() })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !e.host.isRunning() {
		t.Fatal("a restart of core took the traps down")
	}
}

func TestSubscribeKicksOnlyWhileOn(t *testing.T) {
	t.Parallel()
	e := newEnv(t, func(e *env) { e.cfg.PollEvery = 10 * time.Millisecond })
	e.setup()
	bus := &fakeBus{}
	e.svc.Subscribe(bus)
	if len(bus.names) != 2 || bus.names[0] != "inventory.asset.discovered" || bus.names[1] != "inventory.asset.updated" {
		t.Fatalf("%v", bus.names)
	}
	ctx, cancel := context.WithCancel(e.ctx())
	defer cancel()
	go func() { _ = e.svc.Run(ctx) }()
	waitFor(t, "started", func() bool { return e.host.isRunning() })
	e.inv.add(dev("a-late", "192.168.10.240", "LATE", "pc"))
	_ = bus.fns[0](ctx, eventOf("inventory.asset.discovered"))
	waitFor(t, "conflict applied (container stopped)", func() bool { return !e.host.isRunning() })
}
