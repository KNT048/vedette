package httpenc_test

import (
	"testing"

	"github.com/knt048/vedette/internal/httpenc"
)

func TestAcceptsGzip(t *testing.T) {
	t.Parallel()
	for v, want := range map[string]bool{
		"": false, "identity": false, "gzip": true, "GZip": true, "br, gzip;q=0.5": true, "deflate,gzip": true,
		"gzip;q=0": false, "gzip;Q=0": false, "gzip;foo=1;q=0": false, "gzip; q=0.0": false, "gzip;q=0, br": false, "gzip;q=0.1": true, "x-gzip": false,
	} {
		if got := httpenc.AcceptsGzip(v); got != want {
			t.Errorf("%q: %v, want %v", v, got, want)
		}
	}
}
