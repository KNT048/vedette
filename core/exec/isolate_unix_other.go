//go:build unix && !linux

package exec

import "syscall"

// parentDeath: no portable equivalent of Pdeathsig outside Linux.
func parentDeath(*syscall.SysProcAttr) {}
