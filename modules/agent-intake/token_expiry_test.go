package agentintake_test

import (
	"strings"
	"testing"
	"time"
)

// A token no machine enrolled with stops working a day after it was made, even though its set expiry is 7 days.
func TestToken_UnusedExpiresInADay(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	w.clock.Advance(23 * time.Hour)
	w.enroll(secret, "srv-early", peerA) // still good just before the day ends
	_, late := w.token("late", 7)
	w.clock.Advance(25 * time.Hour)
	if r := w.post("/intake/osquery/enroll", peerA, enrollBody(late, "srv-late")); !r.invalid() {
		t.Fatalf("an unused token enrolled a machine after 24 h: %d %s", r.code, r.raw)
	}
	page := w.admin("GET", "/inventory/agents", nil)
	for _, tk := range tokenList(t, page) {
		if tk["name"] == "late" && tk["expires_at"] == nil {
			t.Fatal("the list does not show the one-day expiry of an unused token")
		}
	}
}

// A token that enrolled a machine keeps its normal expiry, so more machines can join with it; the machines already enrolled keep reporting.
func TestToken_UsedKeepsItsExpiry(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("srv", 7)
	key := w.enroll(secret, "srv-1", peerA)
	w.clock.Advance(3 * 24 * time.Hour)
	w.enroll(secret, "srv-2", peerA)
	w.clock.Advance(5 * 24 * time.Hour) // past the 7 days: no new machine, the enrolled ones still report
	if r := w.post("/intake/osquery/enroll", peerA, enrollBody(secret, "srv-3")); !r.invalid() {
		t.Fatalf("an expired token enrolled a machine: %d %s", r.code, r.raw)
	}
	if r := w.post("/intake/osquery/config", peerA, map[string]any{"node_key": key}); r.invalid() {
		t.Fatalf("expiry stopped an enrolled machine: %s", r.raw)
	}
}

// Prune removes unused tokens after their day and expired tokens that have no machine; it never touches a token that has machines or their node_keys.
func TestPrune_RemovesExpiredUnusedTokensButNotEnrolledMachines(t *testing.T) {
	w := newWorld(t)
	_, used := w.token("used", 7)
	key := w.enroll(used, "srv-1", peerA)
	w.token("unused", 7)
	w.pruneFor(time.Hour)
	if w.count(`SELECT count(*) FROM intake_agent_tokens`) != 2 {
		t.Fatal("prune removed a token inside its day")
	}
	w.pruneFor(24 * time.Hour)
	if n := w.count(`SELECT count(*) FROM intake_agent_tokens WHERE name = 'unused'`); n != 0 {
		t.Fatal("an unused token older than a day survived prune")
	}
	w.pruneFor(40 * 24 * time.Hour) // the used token is long expired, its machine is still the token's
	if w.count(`SELECT count(*) FROM intake_agent_tokens WHERE name = 'used'`) != 1 || w.count(`SELECT count(*) FROM intake_osquery_nodes`) != 1 {
		t.Fatal("prune removed a token that has a machine, or the machine")
	}
	_ = key
}

// Remove unused tokens: admin only, audited. "Unused" means no machine enrolled now: a token whose machines were all removed goes too, a token
// with a machine stays, and a token made in the last hour stays (its command may be on screen).
func TestAdmin_RemoveUnusedTokens(t *testing.T) {
	w := newWorld(t)
	w.token("never used", 7)
	_, emptied := w.token("emptied", 7)
	w.enroll(emptied, "srv-gone", peerA)
	w.exec(`DELETE FROM intake_osquery_nodes`) // its machine was removed since
	_, used := w.token("used", 7)
	w.enroll(used, "srv-1", peerA)
	w.clock.Advance(2 * time.Hour)
	w.token("just made", 7)
	for _, u := range []string{"viewer", "operator"} {
		if r := w.as(u, "POST", "/inventory/agents/tokens/remove-unused", true); r.code != 403 {
			t.Fatalf("%s: %d", u, r.code)
		}
	}
	w.exec(`DELETE FROM intake_osquery_nodes WHERE host_identifier <> 'srv-1'`)
	r := w.admin("POST", "/inventory/agents/tokens/remove-unused", nil)
	if r.code != 200 || r.body["removed"] != float64(2) {
		t.Fatalf("remove unused: %d %s", r.code, r.raw)
	}
	if w.count(`SELECT count(*) FROM intake_agent_tokens WHERE name IN ('used', 'just made')`) != 2 || w.count(`SELECT count(*) FROM intake_agent_tokens`) != 2 {
		t.Fatal("remove unused touched a token with a machine or a token made in the last hour")
	}
	if w.count(`SELECT count(*) FROM core_audit WHERE action = 'inventory.agent_tokens_remove_unused' AND user = 'admin@acme.example'`) != 1 {
		t.Fatal("remove unused was not audited")
	}
}

// Prune also removes a token whose machines were all removed once it is past its own expiry, and keeps it before.
func TestPrune_EmptiedTokenGoesAtItsOwnExpiry(t *testing.T) {
	w := newWorld(t)
	_, secret := w.token("emptied", 7)
	w.enroll(secret, "srv-1", peerA)
	w.exec(`DELETE FROM intake_osquery_nodes`)
	w.pruneFor(3 * 24 * time.Hour)
	if w.count(`SELECT count(*) FROM intake_agent_tokens`) != 1 {
		t.Fatal("prune removed an emptied token before its expiry")
	}
	w.pruneFor(5 * 24 * time.Hour)
	if w.count(`SELECT count(*) FROM intake_agent_tokens`) != 0 {
		t.Fatal("an emptied token past its expiry survived prune")
	}
}

// The cap is hit by tokens whose machines were removed: the 409 says to use Remove unused tokens, and that action frees the room.
func TestToken_CapReachedByEmptiedTokensIsFreedByRemoveUnused(t *testing.T) {
	w := newWorld(t)
	w.exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 500)
		INSERT INTO intake_agent_tokens (id, name, token_hash, last4, created_at, expires_at, first_enrolled_at) SELECT 'e' || i, 'emptied ' || i, printf('%064d', i), 'abcd', '2000-01-01T00:00:00.000Z', '2999-01-01T00:00:00.000Z', '2000-01-01T01:00:00.000Z' FROM n`)
	r := w.admin("POST", "/inventory/agents/tokens", map[string]any{"name": "one too many"})
	if r.code != 409 || r.errCode() != "too_many_tokens" || !strings.Contains(r.raw, "Remove unused tokens") {
		t.Fatalf("at the cap: %d %s", r.code, r.raw)
	}
	if r := w.admin("POST", "/inventory/agents/tokens/remove-unused", nil); r.code != 200 || r.body["removed"] != float64(500) {
		t.Fatalf("remove unused: %d %s", r.code, r.raw)
	}
	if r := w.admin("POST", "/inventory/agents/tokens", map[string]any{"name": "fits now"}); r.code != 201 {
		t.Fatalf("after remove unused: %d %s", r.code, r.raw)
	}
}

// The limit is 500 tokens; the error says so in words and names the way out, and unused tokens past their day do not count.
func TestToken_LimitMessageAndDeadTokensDoNotCount(t *testing.T) {
	w := newWorld(t)
	w.exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 500)
		INSERT INTO intake_agent_tokens (id, name, token_hash, last4, created_at) SELECT 'old' || i, 'old ' || i, printf('%064d', i), 'abcd', '2000-01-01T00:00:00.000Z' FROM n`)
	if _, _, err := w.svc.IssueToken(t.Context(), "a@b.example", "fresh", 7); err != nil {
		t.Fatalf("dead tokens blocked a new one: %v", err)
	}
	w.exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 499)
		INSERT INTO intake_agent_tokens (id, name, token_hash, last4, created_at) SELECT 'new' || i, 'new ' || i, printf('%064d', i + 1000), 'abcd', '2999-01-01T00:00:00.000Z' FROM n`)
	r := w.admin("POST", "/inventory/agents/tokens", map[string]any{"name": "one too many"})
	if r.code != 409 || r.errCode() != "too_many_tokens" {
		t.Fatalf("501st token: %d %s", r.code, r.raw)
	}
	if msg, _ := r.body["error"].(map[string]any); msg == nil || !strings.Contains(r.raw, "500") || !strings.Contains(r.raw, "Remove unused tokens") {
		t.Fatalf("the limit message does not say the limit and the way out: %s", r.raw)
	}
}
