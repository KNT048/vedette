//go:build !linux

package ops

// dialARP: there is no packet socket here. The host is a Linux program; this keeps the package
// building on a developer's Mac.
func dialARP(string) (arpSocket, error) { return nil, ErrARPUnsupported }
