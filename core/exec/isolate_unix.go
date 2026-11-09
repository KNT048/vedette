//go:build unix

package exec

import (
	"errors"
	osexec "os/exec"
	"syscall"
)

// isolate puts the child in its own process group and makes cancellation kill the whole group,
// so grandchildren cannot outlive the deadline.
//
// ponytail: a child that calls setsid/setpgid leaves the group and escapes this kill; the
// upgrade path is a cgroup (systemd transient scope) per run, owned by vedette-host.
func isolate(cmd *osexec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	parentDeath(cmd.SysProcAttr)
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return killGroup(cmd.Process.Pid)
	}
	return nil
}

// reapGroup kills any member left in the child's process group after the command finished
// (a background job started by the child, for example).
func reapGroup(cmd *osexec.Cmd) {
	if cmd.Process != nil {
		_ = killGroup(cmd.Process.Pid) // the group is usually already empty
	}
}

// killGroup signals the group led by pgid. After the leader was waited for, its pid could in theory
// be reused as another group's id; that needs the whole group to be empty and a new group leader
// to take the same pid within microseconds, which is accepted here.
func killGroup(pgid int) error {
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}
