package core

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/knt048/vedette/core/api/oas"
)

// The secret of a request body is read into a value that prints, formats and marshals as a placeholder, so a log line or an error that
// shows the decoded request cannot show the secret, and it still reaches the store intact.
func TestConnectionRequestSecretIsRedactedWhenFormatted(t *testing.T) {
	t.Parallel()
	const secret = "par-0123456789-cdef"
	var w wireInput
	body := `{"name":"Lab","kind":"http","target":"https://192.168.10.1","auth_type":"token","secret":"` + secret + `","allow":["https://192.168.10.1/"],"enabled":true}`
	if err := json.Unmarshal([]byte(body), &w); err != nil {
		t.Fatal(err)
	}
	for _, got := range []string{fmt.Sprintf("%v", w), fmt.Sprintf("%+v", w), fmt.Sprintf("%#v", w), fmt.Sprint(w.Secret), fmt.Sprintf("%s", w.Secret)} { //nolint:gosec,staticcheck // the point
		if strings.Contains(got, secret) || strings.Contains(got, "0123456789") {
			t.Errorf("a formatted request shows the secret: %s", got)
		}
	}
	b, err := json.Marshal(w)
	if err != nil || strings.Contains(string(b), secret) {
		t.Errorf("json.Marshal(request) = %s %v", b, err)
	}
	if !w.Secret.IsSet() || w.Secret.Reveal() != secret {
		t.Error("the secret did not reach the value")
	}
	for _, null := range []string{`{"secret":null}`, `{}`} {
		var n wireInput
		if err := json.Unmarshal([]byte(null), &n); err != nil || n.Secret.IsSet() {
			t.Errorf("%s: set=%v err=%v", null, n.Secret.IsSet(), err)
		}
	}
	// Through the generated request type, as the handler reads it.
	var req oas.CorePostCoreConnectionsReq
	if err := req.UnmarshalJSON([]byte(body)); err != nil {
		t.Fatal(err)
	}
	in, err := connInput(&req)
	if err != nil {
		t.Fatal(err)
	}
	if in.Secret.Reveal() != secret || strings.Contains(fmt.Sprintf("%+v", in), secret) {
		t.Errorf("connInput: the secret is lost or the input shows it: %+v", in)
	}
}
