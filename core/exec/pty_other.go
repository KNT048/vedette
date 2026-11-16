//go:build !linux

package exec

import (
	"errors"
	"os"
	"syscall"
)

// openTerm: a terminal for the child is opened on Linux only (the scan container); elsewhere the program runs without one.
func openTerm(string) (master, peer *os.File, err error) {
	return nil, nil, errors.New("exec: no terminal for a child on this system")
}

func inTerminal(*syscall.SysProcAttr) {}
