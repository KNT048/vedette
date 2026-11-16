//go:build !linux

package exec_test

import "os"

func ttyHelper([]string) { os.Exit(98) }
