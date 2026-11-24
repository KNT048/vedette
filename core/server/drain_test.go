package server_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/server"
	"github.com/knt048/vedette/core/server/servertest"
)

// refusingCore answers the file upload after reading only the file's header, as a wrong backup password does; a file whose
// first byte is "!" is refused without being read at all, as a busy box or a wrong setup code is.
type refusingCore struct{}

func (refusingCore) CorePostCoreDataRestoreUpload(_ context.Context, req oas.CorePostCoreDataRestoreUploadReq, params oas.CorePostCoreDataRestoreUploadParams) (*oas.CorePostCoreDataRestoreUploadOK, error) {
	if params.XBackupPassword.Or("") == "untouched" {
		return nil, apierr.New(http.StatusConflict, "busy", "Busy.")
	}
	if _, err := io.ReadFull(req.Data, make([]byte, 64)); err != nil {
		return nil, err
	}
	return nil, apierr.New(http.StatusBadRequest, "wrong_backup_password", "The backup password is wrong.")
}

type refusingComposite struct {
	server.Fallback
	feedsHandler
	refusingCore
}

// countingReader counts what the server read of a request body.
type countingReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// An upload the handler refuses after its first bytes is still read to its end (within the operation's cap) before the
// answer goes out. Left unread, the server closes the connection while the browser is still sending the file, and the
// browser sends the whole request again: one press of the button became two judged requests (two counted password guesses),
// and the page showed the answer to the copy. A body over the cap is not read past it, and one the handler refused without
// looking at is not taken in.
func TestRefusedUploadIsReadToItsEnd(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.DiscardHandler)
	const capBytes = 4 << 20
	h, err := server.New(server.Config{
		API:  refusingComposite{Fallback: server.Fallback{Log: log}, feedsHandler: feedsHandler{&seen{}}, refusingCore: refusingCore{}},
		Auth: &servertest.Auth{Users: servertest.StandardUsers()}, Modules: servertest.NewGate(), Log: log,
		BodyLimits: map[string]int64{"core_post_core_data_restore_upload": capBytes},
	})
	if err != nil {
		t.Fatal(err)
	}
	post := func(size int, declared bool, password ...string) (*httptest.ResponseRecorder, int64) {
		body := &countingReader{r: bytes.NewReader(make([]byte, size))}
		hr := httptest.NewRequestWithContext(t.Context(), "POST", server.Prefix+"/core/data/restore/upload", body)
		hr.ContentLength = -1
		if declared {
			hr.ContentLength = int64(size)
		}
		hr.Header.Set("Content-Type", "application/octet-stream")
		hr.Header.Set(servertest.CSRFHeader, servertest.CSRFValue)
		if len(password) > 0 {
			hr.Header.Set("X-Backup-Password", password[0])
		}
		hr.AddCookie(&http.Cookie{Name: servertest.CookieName, Value: "admin", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, hr)
		return rec, body.n.Load()
	}
	const size = 3 << 20
	rec, read := post(size, true)
	wantError(t, rec, 400, "wrong_backup_password")
	if read != size {
		t.Fatalf("the server read %d of the %d bytes of a refused upload before answering, want all of them", read, size)
	}
	// Over the cap, with no declared length: cut at the cap, never read to the end.
	_, read = post(3*capBytes, false)
	if read > capBytes+64<<10 {
		t.Fatalf("the server read %d bytes of a body over its %d-byte cap", read, capBytes)
	}
	rec, read = post(size, true, "untouched")
	wantError(t, rec, 409, "busy")
	if read > 64<<10 {
		t.Fatalf("the server read %d bytes of an upload refused before the handler looked at it", read)
	}
}
