package findings

import "testing"

// Ignoring a device changes none of its findings; Home's open count and Fix first, To fix and the risk marker leave them out.
func TestIgnoredDevice_LeftOutOfHomeAndToFix(t *testing.T) {
	t.Parallel()
	e := newHTTPEnv(t)
	id := e.seed()
	count := func() (int, int) {
		t.Helper()
		_, b := e.call("GET", "/findings/overview", "viewer", "")
		open, _ := b["open"].(map[string]any)
		tf, err := e.svc.ToFix(t.Context(), true, "")
		if err != nil {
			t.Fatal(err)
		}
		total, _ := open["findings"].(float64)
		return int(total), len(tf.Devices)
	}
	if o, d := count(); o != 1 || d != 1 {
		t.Fatalf("watched: open %d, to fix %d", o, d)
	}
	e.inv.mu.Lock()
	e.inv.ignored = map[string]bool{"a-1": true}
	e.inv.mu.Unlock()
	e.svc.gen.Add(1) // a new answer, not the cached one
	if o, d := count(); o != 0 || d != 0 {
		t.Fatalf("ignored: open %d, to fix %d", o, d)
	}
	if f, err := e.svc.Finding(t.Context(), id); err != nil || f.State != StateOpen {
		t.Fatalf("the finding changed: %+v %v", f, err)
	}
}
