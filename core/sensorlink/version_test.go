package sensorlink_test

import (
	"testing"

	"github.com/knt048/vedette/core/sensorlink"
)

func TestValidVersion(t *testing.T) {
	t.Parallel()
	for v, want := range map[string]bool{
		"0.0.0-dev": true, "1.2.3": true, "10.20.30-rc.1+build.5": true,
		"dev": false, "v1.2.3": false, "1.2": false, "": false, "1.2.3 ": false,
	} {
		if got := sensorlink.ValidVersion(v); got != want {
			t.Errorf("ValidVersion(%q) = %v, want %v", v, got, want)
		}
	}
}
