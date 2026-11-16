package exec

import "syscall"

// SetPTMX points the Runner at another master device, so a test sees what happens when no terminal can be opened.
func SetPTMX(r *Runner, path string) { r.ptmx = path }

// SetInTerminal replaces how a TTY child takes its terminal, so a test can make that fail in the child.
func SetInTerminal(r *Runner, f func(*syscall.SysProcAttr)) { r.inTerminal = f }

// InTerminal is the real one.
var InTerminal = inTerminal
