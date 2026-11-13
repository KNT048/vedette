package feeds

import (
	"testing"
	"time"
)

// D-484 (W1-3): "I have this" scopes the one device it declared, from a week before the answered entry (the "This week"
// window, so that week's other entries of the product count). The first "have" sets the date; a later answer never moves
// it, and while the answer is "not relevant" there is no scope.
func TestHaveSince_FirstHaveScopesTheDeclaredDevice(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.loadKEV()
	id := "synology%7Cdiskstation%20manager"
	post := func(answer string) {
		t.Helper()
		if c, b, _ := e.do("POST", "/feeds/weekly/"+id, "operator", `{"answer":"`+answer+`"}`); c != 200 {
			t.Fatalf("%s: %d %v", answer, c, b)
		}
	}
	var added string
	if err := e.db.Reader().QueryRowContext(t.Context(), `SELECT max(date_added) FROM feeds_vuln WHERE product_key = 'synology|diskstation manager'`).Scan(&added); err != nil {
		t.Fatal(err)
	}
	d, _ := time.Parse(time.DateOnly, added)
	want := Have{Key: "synology|diskstation manager", Since: d.Add(-HaveWindow)}
	read := func() map[string]Have {
		t.Helper()
		got, err := e.svc.Store().HaveSince(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	post("have")
	if got := read(); len(got) != 1 || got["a-declared-1"] != want {
		t.Fatalf("after have: %v, want a-declared-1 %v", got, want)
	}
	e.setNow(e.clock().Add(30 * 24 * time.Hour))
	post("not_relevant")
	if got := read(); len(got) != 0 {
		t.Fatalf("not relevant still scopes: %v", got)
	}
	post("have")
	if got := read(); len(got) != 1 || got["a-declared-1"] != want || len(e.inv.added) != 1 {
		t.Fatalf("a later have moved the scope: %v (%d devices)", got, len(e.inv.added))
	}
}
