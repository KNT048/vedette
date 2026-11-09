//go:build linux

package exec

import "syscall"

// parentDeath makes the kernel kill the child if the Vedette process dies.
func parentDeath(a *syscall.SysProcAttr) { a.Pdeathsig = syscall.SIGKILL }
