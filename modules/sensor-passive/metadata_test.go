package sensorpassive_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/knt048/vedette/core/sensorlink"
	sp "github.com/knt048/vedette/modules/sensor-passive"
)

// POST /metadata hands the batch to the MirrorMatcher as it is and stores nothing itself; with the module turned off since the
// listener let the request in it is module_off (SYS-5); a matcher that fails is store_busy, so the sensor sends the batch again.
func TestMetadataGoesToTheMirrorMatcher(t *testing.T) {
	t.Parallel()
	var got []sensorlink.MetadataItem
	var fail error
	e := newEnv(t, nil, true, func(c *sp.Config, _ *env) {
		c.Mirror = func(_ context.Context, items []sensorlink.MetadataItem) error { got = items; return fail }
	})
	req := &sensorlink.MetadataRequest{Items: []sensorlink.MetadataItem{{Kind: sensorlink.MetaDNS, At: time.Now(), Src: "10.0.0.5", Dest: "bad.example.com"}}}
	if err := e.svc.Metadata(t.Context(), req); err != nil || len(got) != 1 || got[0].Dest != "bad.example.com" {
		t.Fatalf("%v %+v", err, got)
	}
	fail = errors.New("logs.db is locked")
	var se *sensorlink.Error
	if err := e.svc.Metadata(t.Context(), req); !errors.As(err, &se) || se.Code != sensorlink.CodeStoreBusy {
		t.Fatalf("a failing matcher: %v", err)
	}
	e.off.Store(true)
	got = nil
	if err := e.svc.Metadata(t.Context(), req); !errors.As(err, &se) || se.Code != sensorlink.CodeModuleOff || got != nil {
		t.Fatalf("module off: %v %+v", err, got)
	}
}
