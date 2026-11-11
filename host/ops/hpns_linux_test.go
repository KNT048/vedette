//go:build linux

package ops

import (
	"fmt"
	"os"
	"os/exec" //nolint:depguard // the test starts a plain child process in new namespaces; SYS-1 is about the product
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The real namespace check, on files that change nothing: this process's own namespace link is on
// nsfs and is a network namespace, but it is the host's own and is refused; a regular file is not
// a namespace. (Creating a namespace is not done in unit tests; see the lab checks.)
func TestIsNetNSOnRealFiles(t *testing.T) {
	t.Parallel()
	ns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Skipf("no /proc/self/ns/net: %v", err)
	}
	defer func() { _ = ns.Close() }()
	if ok, err := isNetNS(ns); err != nil || ok {
		t.Fatalf("/proc/self/ns/net must be refused as the process's own: %v %v", ok, err)
	}
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p) //nolint:gosec // a file the test just made
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if ok, err := isNetNS(f); err != nil || ok {
		t.Fatalf("a regular file: %v %v", ok, err)
	}
}

// The type is read from the kernel, not assumed: this process's own namespace links say what they are (#349: the type was
// read back as 0, so no namespace was ever a network one). Needs no privilege.
func TestNSTypeReadsTheKernelsAnswer(t *testing.T) {
	t.Parallel()
	if _, err := os.Stat("/proc/self/ns/net"); err != nil {
		t.Skipf("no /proc/self/ns: %v", err)
	}
	for path, want := range map[string]int{"/proc/self/ns/net": unix.CLONE_NEWNET, "/proc/self/ns/mnt": unix.CLONE_NEWNS} {
		f, err := os.Open(path) //nolint:gosec // a fixed path of /proc
		if err != nil {
			t.Fatal(err)
		}
		got, err := nsType(f)
		_ = f.Close()
		if err != nil || got != want {
			t.Errorf("nsType(%s) = %#x, %v; want %#x", path, got, err, want)
		}
	}
}

// A real network namespace that is not this process's own is accepted: the one of a child started in new user and network
// namespaces (no root needed where unprivileged user namespaces are allowed; skipped where they are not).
func TestIsNetNSAcceptsAnotherNamespace(t *testing.T) {
	t.Parallel()
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	cmd := exec.CommandContext(t.Context(), sleep, "30") //nolint:gosec // the sleep binary found on PATH, a fixed argument
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a process in new user and network namespaces here: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	f, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if ok, err := isNetNS(f); err != nil || !ok {
		t.Fatalf("the child's network namespace was refused: %v %v", ok, err)
	}
}
