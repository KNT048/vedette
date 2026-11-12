package response

import "testing"

// D-179 (3): execHash is stored with every request and compared at every undo. A change of execRec (a field, a tag, the order) would change
// every hash from then on and silently block the undo of every change in force, so the hash of a fixed record is pinned. Change it only with a
// plan for the requests already stored (a migration, or the fallback in undoStepsProblem).
func TestWP31_ExecHashIsPinned(t *testing.T) {
	t.Parallel()
	ex := &execRec{
		Precheck: &execStep{Method: "GET", URL: "https://fw.lan/api/v2/monitor/user/banned/select"},
		Run:      &execStep{Method: "POST", URL: "https://fw.lan/api/v2/monitor/user/banned/add_users", Body: `{"ip_addresses":["198.51.100.7"],"expiry":1800}`, Headers: map[string]string{"X-Trace": "a"}},
		Rollback: &execStep{Lines: []string{"configure terminal", "no shutdown"}},
		Verify:   &execStep{Tool: "get", Args: []byte(`{"id":1}`)},
		Refuse:   []string{"Mode: trunk"}, PrecheckExpect: "static access", Expect: "198.51.100.7",
	}
	const want = "cefeaf3aabf9346b02e0e72fa705635858041a74c52b2d9bc2ff8b23deede0a7"
	if got := execHash(ex); got != want {
		t.Fatalf("execHash = %s, want %s", got, want)
	}
	if execHash(nil) != "" {
		t.Error("a nil record has a hash")
	}
}
