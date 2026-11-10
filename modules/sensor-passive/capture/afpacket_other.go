//go:build !linux

package capture

import "errors"

// ErrNoLiveCapture is returned by OpenLive where there is no AF_PACKET (everything but Linux). Development on
// such a system replays recordings with OpenFile.
var ErrNoLiveCapture = errors.New("capture: live capture needs Linux (AF_PACKET); replay a recording instead")

// OpenLive is not available on this system.
func OpenLive(string) (Source, error) { return nil, ErrNoLiveCapture }
