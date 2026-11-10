package write_test

import (
	"testing"

	"github.com/knt048/vedette/core/conn"
	"github.com/knt048/vedette/core/conn/conntest"
	"github.com/knt048/vedette/core/conn/write"
)

// L2: a connection edited between opening the credential and dialling is not dialled: connection_changed, nothing sent.
func TestWriterRefusesAConnectionEditedWhileTheCredentialWasOpen(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	f := conntest.NewHTTPS(t, nil)
	c := r.api(f)
	n := len(f.Requests())
	r.w.SetAfterCredentialForTest(func() {
		r.update(c.ID, func(in *conn.Input) { in.Allow = append(in.Allow, f.URL+"/api/other/") })
	})
	res := r.do(post(c, f, "/api/v2/block", `{"ip":"198.51.100.7"}`))
	wantStatus(t, res, write.StatusConnectionChanged)
	if len(f.Requests()) != n {
		t.Error("a request was sent for a connection that changed")
	}
}
