package response

import "testing"

// The shared test vector of core/conn.Fingerprint (core/conn/conn_test.go TestFingerprintVector): the fingerprint stored in every
// request item is the one core/conn computes, so an upgrade does not make the requests that are waiting fail as connection_changed.
func TestConnFPIsTheSharedVector(t *testing.T) {
	t.Parallel()
	got := connFP(ConnectionInfo{Connection: Connection{ID: "cn-1", Kind: "http"}, Target: "https://192.168.10.1", UpdatedAt: "2026-11-09T10:00:00.000Z"})
	if got != "5c44d33d9abf4dc98bc0a226d8bc8f37" {
		t.Fatalf("connFP = %s", got)
	}
}
