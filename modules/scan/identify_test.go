package scan

import (
	"context"
	"slices"
	"sync"
	"testing"
)

// fakeIdentify is sensor-active's identification in tests: what it answers per device, and an action it takes (the finding the
// findings module would match from the software it recorded).
type fakeIdentify struct {
	mu     sync.Mutex
	answer map[string]Identification
	errs   map[string]error
	then   func(assetID string)
	asked  []string
}

func (f *fakeIdentify) Identify(_ context.Context, assetID string) (Identification, error) {
	f.mu.Lock()
	f.asked = append(f.asked, assetID)
	a, err, then := f.answer[assetID], f.errs[assetID], f.then
	f.mu.Unlock()
	if then != nil {
		then(assetID)
	}
	return a, err
}

func (f *fakeIdentify) askedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.asked)
}

// Review M2: sensor-active stopping an identification by itself (the device or the settings changed) skips that device with its
// reason and the run goes on; review M3: once discovery was busy, the rest of the run says busy without asking again.
func TestScanNowInterruptedAndBusyIdentification(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	id := &fakeIdentify{errs: map[string]error{"a-web01": ErrIdentifyInterrupted}, answer: map[string]Identification{"a-srv": {Why: "busy"}}}
	r.svc.cfg.Identify = id
	v := r.start("a-web01", "a-srv", "a-nas02")
	r.wait()
	v = r.run(v.ID)
	if v.Status != "done" {
		t.Fatalf("status %s, want the run to go on after the interrupted device", v.Status)
	}
	if row := rowOf(v, "a-web01", ""); row == nil || row.Result != "skipped" || row.Note != noteIdentInterrupted {
		t.Errorf("a-web01 result = %+v, want skipped with the interruption note", row)
	}
	if got := identOf(v, "a-web01"); got == nil || got.Reason == nil || *got.Reason != "not_scanned" || got.Note != noteIdentInterrupted {
		t.Errorf("a-web01 identification = %+v", got)
	}
	for _, dev := range []string{"a-srv", "a-nas02"} {
		if got := identOf(v, dev); got == nil || got.Reason == nil || *got.Reason != "busy" {
			t.Errorf("%s identification = %+v, want busy", dev, got)
		}
	}
	if asked := id.askedIDs(); !slices.Equal(asked, []string{"a-web01", "a-srv"}) {
		t.Errorf("asked %v: after busy the run must not ask (and wait) again", asked)
	}
}

func identOf(v RunView, id string) *IdentRow {
	for i := range v.Identification {
		if v.Identification[i].TargetID == id {
			return &v.Identification[i]
		}
	}
	return nil
}

// D-501: Scan now identifies each device before it checks it. A device known only by its address (no finding before) gets the
// finding its identified software matched and is checked for it; each device says what was identified, or exactly why nothing was.
func TestScanNowIdentifiesBeforeItChecks(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	id := &fakeIdentify{answer: map[string]Identification{
		"a-srv":   {Found: []string{"Operating system: Microsoft Windows Server 2016", "Software: Microsoft Windows Server 2016"}},
		"a-web01": {Why: "no_version"},
		"a-nas02": {Why: "gentle_only"},
	}}
	id.then = func(assetID string) {
		if assetID == "a-srv" { // what the findings module does when the inventory announces the new software
			r.findings.mu.Lock()
			r.findings.list = append(r.findings.list, FindingRef{ID: "f-9", AssetID: "a-srv", CVE: "CVE-2024-3400", Status: "suspected"})
			r.findings.mu.Unlock()
		}
	}
	r.svc.cfg.Identify = id
	v := r.start("a-srv", "a-web01", "a-nas02")
	r.wait()
	v = r.run(v.ID)
	if row := rowOf(v, "a-srv", ""); row == nil || row.Result == "not_applicable" || row.FindingID == nil || *row.FindingID != "f-9" {
		t.Fatalf("a-srv was not checked for what its identification matched: %+v", v.Results)
	}
	srv := identOf(v, "a-srv")
	if srv == nil || srv.Reason != nil || len(srv.Found) != 2 || srv.Note != identNote[""] {
		t.Errorf("a-srv identification = %+v", srv)
	}
	for dev, want := range map[string]string{"a-web01": "no_version", "a-nas02": "gentle_only"} {
		got := identOf(v, dev)
		if got == nil || got.Reason == nil || *got.Reason != want || got.Note != identNote[want] {
			t.Errorf("%s identification = %+v, want %s", dev, got, want)
		}
	}
	if len(v.Identification) != 3 {
		t.Errorf("%d identification rows, want one per device", len(v.Identification))
	}
}

// Without an Identifier (sensor-active off or not wired) a Scan now run still checks what is known, and each device says why it
// was not identified. A device the run skips says the run's own reason.
func TestScanNowWithoutIdentifierSaysWhy(t *testing.T) {
	t.Parallel()
	r := newRunEnv(t)
	v := r.start("a-web01")
	r.wait()
	v = r.run(v.ID)
	if got := identOf(v, "a-web01"); got == nil || got.Reason == nil || *got.Reason != "unavailable" {
		t.Errorf("a-web01 = %+v, want unavailable", got)
	}
	d := Device{ID: "a-x", Label: "X", IP: "192.168.10.9"}
	for why, want := range map[string]string{"unapproved": "not_approved", "excluded": "out_of_scope", reasonNoScope: "scope_not_confirmed", reasonBox: "box", reasonNever: "regular_scan_never", ReasonGone: "not_scanned"} {
		if got := skippedRow(d, why); got.Reason == nil || *got.Reason != want || got.Note != skipNote[why] {
			t.Errorf("skipped %s = %+v, want %s with the skip note", why, got, want)
		}
	}
}
