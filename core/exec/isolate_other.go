//go:build !unix

package exec

import osexec "os/exec"

func isolate(*osexec.Cmd) error { return ErrUnsupportedOS }

func reapGroup(*osexec.Cmd) {}
