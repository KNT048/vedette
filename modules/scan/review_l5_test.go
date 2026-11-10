package scan

import (
	"context"
	"fmt"
	"testing"

	"github.com/knt048/vedette/modules/scan/nucleiargv"
)

// errDeviceTimeoutForTest is what an engine returns when the device did not finish in time.
var errDeviceTimeoutForTest = fmt.Errorf("the job ran out of time: %w", context.DeadlineExceeded)

// L5: a device that did not finish in time has its own reason, not "did not respond".
func TestReview_L5_DeviceTimeoutHasItsOwnReason(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.eng.reply = func(nucleiargv.Job) (Output, error) { return Output{}, errDeviceTimeoutForTest }
	v := r.start("a-web01", "a-nas02")
	r.wait()
	got := r.run(v.ID)
	if got.Status != "auto_stopped" || *got.StopReason != "WEB01 (192.168.10.12) did not finish within 15 minutes. Vedette stopped so the device is not hung." {
		t.Fatalf("%+v", got)
	}
}
