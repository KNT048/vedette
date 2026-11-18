package sensoractive

import (
	"errors"
	"testing"

	"github.com/knt048/vedette/core/sensorlink"
)

// A job for a typed public IP is sent only to a worker whose heartbeat says typed_ip; an older worker with a fence key gets none.
func TestDomainSupported_TypedNeedsItsOwnHeartbeatFlag(t *testing.T) {
	t.Parallel()
	typed := &sensorlink.DomainScope{Domain: "9.9.9.9", Name: "9.9.9.9", Typed: &sensorlink.TypedScope{Method: "file"}}
	plain := &sensorlink.DomainScope{Domain: "acme.example", Name: "www.acme.example"}
	for name, c := range map[string]struct {
		domainIP, typedIP bool
		scope             *sensorlink.DomainScope
		want              error
	}{
		"a domain on a fenced worker":         {true, false, plain, nil},
		"a typed IP on a worker that says so": {true, true, typed, nil},
		"a typed IP on an older fenced one":   {true, false, typed, ErrTypedUnsupported},
		"a typed IP with no fence key":        {false, false, typed, ErrDomainUnsupported},
	} {
		d := &Dispatcher{domainIP: c.domainIP, typedIP: c.typedIP}
		if err := d.domainSupported(c.scope); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}
