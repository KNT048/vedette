package scan

import (
	"fmt"
	"strings"
	"testing"

	"github.com/knt048/vedette/modules/scan/nucleiargv"
)

// S5: when the scanner says it cannot run jobs at all (the worker holds another template pack, or it is gone), the run
// stops with the scanner's own words instead of trying every device and failing each one.
func TestS5_AScannerThatCannotRunJobsStopsTheRun(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	r.eng.reply = func(nucleiargv.Job) (Output, error) {
		return Output{}, fmt.Errorf("%w: the scan image has template pack 2026.11.2, the request needs 2026.11.1", ErrEngineDown)
	}
	v := r.start("a-web01", "a-srv")
	r.wait()
	got := r.run(v.ID)
	if got.Status != "auto_stopped" || got.StopReason == nil || !strings.Contains(*got.StopReason, "template pack 2026.11.2") {
		t.Fatalf("run: status %s, reason %v", got.Status, got.StopReason)
	}
	if n := len(r.eng.sent()); n != 1 {
		t.Fatalf("%d jobs sent after the scanner said it cannot run any", n)
	}
}
