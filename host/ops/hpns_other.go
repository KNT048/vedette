//go:build !linux

package ops

import (
	"errors"
	"os"
)

// isNsfs: there are no network namespaces here (the host is a Linux program; this keeps the package
// building on a developer's Mac). Tests give Deps.IsNsfs their own.
func isNsfs(*os.File) (bool, error) { return false, errors.New("ops: network namespaces need Linux") }
