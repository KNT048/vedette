//go:build !linux

package ops

import "errors"

// unmountDetach: there are no container mounts to remove here (the host is a Linux program; this keeps the package building on a
// developer's Mac).
func unmountDetach(string) error { return errors.New("ops: unmounting needs Linux") }
