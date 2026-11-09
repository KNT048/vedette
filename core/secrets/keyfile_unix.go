//go:build unix

package secrets

import "syscall"

// openFlags: never block on a FIFO, never follow a symlink in the last path element.
const openFlags = syscall.O_NONBLOCK | syscall.O_NOFOLLOW
