package ops_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/knt048/vedette/host/ops/opstest"
)

// os.Root.OpenFile ignores O_NOFOLLOW for the last component (it always passes O_NOFOLLOW to
// openat itself and, on ELOOP, resolves the link inside the root). The Lstat + SameFile check after
// the open in coreTree.openFile is what refuses a symlink, so that check is load-bearing and must
// stay. This test records the platform behaviour it depends on.
func TestRootOpenFileFollowsAFinalSymlinkDespiteONOFOLLOW(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "target"), []byte("core bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	f, err := r.OpenFile("link", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err == nil {
		_ = f.Close()
		t.Log("documented: Root.OpenFile(O_NOFOLLOW) opened a symlink as the last component; only the Lstat/SameFile check in openFile refuses it")
		return
	}
	t.Logf("this Go version refuses it: %v", err)
}

// The start-up sweep of core's tree must not be holdable: Root.RemoveAll rereads a directory until it
// is short, so core keeping a ".vedette-restore-x" directory full would hold the root host in Start.
// The sweep removes only regular files with the exact temp name, reads a bounded number of names,
// and never recurses.
func TestStartSweepCannotBeHeldByCoreRefillingADirectory(t *testing.T) {
	t.Parallel()
	m := opstest.NewMachine(t)
	o := m.Ops(nil)
	defer o.Close()
	planted := filepath.Join(m.CoreData, ".vedette-restore-core")
	if err := os.Mkdir(planted, 0o700); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	var n atomic.Int64
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; !stop.Load(); i++ {
				if os.WriteFile(filepath.Join(planted, fmt.Sprintf("%d-%d", w, i)), nil, 0o600) == nil {
					n.Add(1)
				}
			}
		}()
	}
	for n.Load() < 4096 { // core fills it before the host starts
		runtime.Gosched()
	}
	done := make(chan struct{})
	go func() {
		o.Start(context.Background(), nil)
		close(done)
	}()
	held := false
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		held = true
	}
	stop.Store(true)
	wg.Wait()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("Start did not return after core stopped refilling")
	}
	if held {
		t.Errorf("the root host was still in Start after 3 s while core refilled a planted .vedette-restore-* directory (%d files created)", n.Load())
	}
	if _, err := os.Stat(planted); err != nil {
		t.Errorf("the sweep must not delete a directory: %v", err)
	}
}

// The sweep deletes the temp files a restore that died left (exact name, regular file) and nothing
// else, in particular not a file or directory that only starts with the prefix.
func TestStartSweepRemovesOnlyExactRestoreTempFiles(t *testing.T) {
	t.Parallel()
	m := opstest.NewMachine(t)
	o := m.Ops(nil)
	defer o.Close()
	gone := filepath.Join(m.CoreData, ".vedette-restore-0123456789abcdef")
	keep := []string{".vedette-restore-core", ".vedette-restore-0123456789abcdeg", ".vedette-restore-0123456789abcde", "vedette.db"}
	if err := os.WriteFile(gone, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, k := range keep {
		if err := os.WriteFile(filepath.Join(m.CoreData, k), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	dirLike := filepath.Join(m.CoreData, ".vedette-restore-fedcba9876543210")
	if err := os.Mkdir(dirLike, 0o700); err != nil {
		t.Fatal(err)
	}
	o.Start(context.Background(), nil)
	if _, err := os.Lstat(gone); err == nil {
		t.Error("the restore temp file was not swept")
	}
	for _, k := range append(keep, filepath.Base(dirLike)) {
		if _, err := os.Lstat(filepath.Join(m.CoreData, k)); err != nil {
			t.Errorf("%s was removed: %v", k, err)
		}
	}
}
