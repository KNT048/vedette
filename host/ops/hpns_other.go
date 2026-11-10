//go:build !linux

package ops

import (
	"errors"
	"os"
)

// isNetNS: there are no network namespaces here (the host is a Linux program; this keeps the package
// building on a developer's Mac). Tests give Deps.IsNetNS their own.
func isNetNS(*os.File) (bool, error) { return false, errors.New("ops: network namespaces need Linux") }
