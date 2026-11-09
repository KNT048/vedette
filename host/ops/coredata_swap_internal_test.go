package ops

import (
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// A sticky, world-writable parent (like /tmp) is refused: in a sticky directory the owner of an
// entry may still rename it, and core owns core_data. sshd StrictModes has no sticky exception.
func TestOpenCoreRefusesAStickyWorldWritableParent(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	parent := filepath.Join(base, "sticky")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	core := filepath.Join(parent, "core")
	if err := os.Mkdir(core, 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(base, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	o, err := NewWithDeps(Config{StateDir: state, CoreData: core, CoreUnit: "vedette-core.service", CoreUID: os.Getuid(), CoreGID: os.Getgid(), OwnerUID: os.Getuid()}, Deps{Root: base})
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if tr, err := o.openCore(); err == nil {
		tr.close()
		t.Fatal("a sticky world-writable parent was accepted")
	}
	// The same tree under a closed parent opens (control).
	if err := os.Chmod(parent, 0o700); err != nil { //nolint:gosec // a directory needs the x bit
		t.Fatal(err)
	}
	tr, err := o.openCore()
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	tr.close()
}

// Something that can rename core_data (here the test, in place of a raced owner) swaps it for a FIFO
// again and again while the host opens it: open(2) of a FIFO blocks, so os.OpenRoot on the name would
// hang the root host. The directory is opened with O_DIRECTORY|O_NONBLOCK first and OpenRoot gets
// the descriptor's path, so the host never blocks.
func TestOpenCoreNeverBlocksOnAFIFOSwappedIntoPlace(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	core := filepath.Join(parent, "core")
	aside := filepath.Join(parent, "core.aside")
	if err := os.Mkdir(core, 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(base, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	o, err := NewWithDeps(Config{StateDir: state, CoreData: core, CoreUnit: "vedette-core.service", CoreUID: os.Getuid(), CoreGID: os.Getgid(), OwnerUID: os.Getuid()}, Deps{Root: base})
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	// A good tree opens.
	if tr, err := o.openCore(); err != nil {
		t.Fatalf("control: %v", err)
	} else {
		tr.close()
	}

	var stop atomic.Bool
	racerDone := make(chan struct{})
	go func() { // core: swap the entry in its parent, dir <-> FIFO
		defer close(racerDone)
		for !stop.Load() {
			if os.Rename(core, aside) != nil {
				continue
			}
			_ = syscall.Mkfifo(core, 0o600)
			runtime.Gosched()
			_ = os.Remove(core)
			_ = os.Rename(aside, core)
		}
	}()
	stuck := make(chan struct{})
	go func() { // the host: one openCore per command
		for !stop.Load() {
			done := make(chan struct{})
			go func() {
				if tr, err := o.openCore(); err == nil {
					tr.close()
				}
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				close(stuck) // this goroutine stays blocked in open(2) until the test binary exits
				return
			}
		}
	}()
	hung := false
	select {
	case <-stuck:
		hung = true
	case <-time.After(20 * time.Second):
	}
	stop.Store(true)
	<-racerDone
	if hung {
		t.Errorf("openCore blocked for 2 s on a FIFO swapped in for core_data")
	}
}
