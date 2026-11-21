package agentintake

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
)

// The state of an agent, judged by its own rhythm (NodeHealth). The box cannot see the flags on the machine, so the rhythm is what the
// agent was told and what it does. call_every_s is how often it was told to call: osquery fetches its config every five minutes
// (--config_refresh=300 of the install scripts), the package reporter of scripts/osquery.sh (for systems osquery does not run on) runs
// once an hour, a Wazuh agent is judged at the pull interval by when Wazuh last heard from it. call_gap_s is the agent's own smoothed gap between two config fetches in a row
// (the calls the refresh promises, at the pace it was told), forgotten when results come after a silence it called quiet (forgetSQL). report_every_s is the longest interval of its report schedule: it delivers results at least that
// often whether or not it fetches its config. Quiet is a silence longer than three of the rhythm: the longer of what it was told and
// what it does, or, while the box has not seen it fetch its config twice, of what it was told and its report schedule. One lost call (a
// busy box, a network blip) never makes an agent quiet, a stopped osquery service is found within a quarter of an hour, and an agent that
// calls less often than it was told (an older install without the config refresh, which calls only with its hourly results, or the
// package reporter) is never quiet between two of its own calls.
const (
	StateReporting     = "reporting"
	StateQuiet         = "quiet"
	StateNeverReported = "never_reported"
	StateReplaced      = "replaced" // a newer agent of the same machine took over; the older record is only kept until it is removed or pruned

	configRefresh = 5 * time.Minute // what the install scripts set (--config_refresh=300)
	// reporterEvery is the package reporter's schedule: one run an hour, at a minute of its own plus up to a minute of random delay.
	reporterEvery = time.Hour + time.Minute
	quietCalls    = 3 // missed calls before quiet

	// refreshSlack: a gap between two config fetches is the refresh the agent was told when it is within 1/refreshSlack of it (nextGap):
	// ±10 s of 300 s. osquery's refresh is a timer (the next fetch starts 300 s after the last one ended), so a refreshing agent's
	// fetches reach the box seconds from 300 s apart; two service starts would have to fall in those 20 s to look like a refresh.
	refreshSlack = 30
)

// Cadence is what NodeHealth judges an agent by.
type Cadence struct {
	Enrolled   time.Time     // zero for an agent that does not enrol with the box (Wazuh)
	LastCall   time.Time     // its last call (osquery: config or results; Wazuh: the last pull that delivered it)
	LastResult time.Time     // its last delivered data; zero = none yet
	CallEvery  time.Duration // how often it was told to call
	CallGap    time.Duration // its own smoothed gap between config fetches; 0 = not learned yet
	// ReportEvery is the longest interval of the schedule it was given: it delivers results at least that often, config refresh or not.
	// Only read while CallGap is not learned yet.
	ReportEvery time.Duration
	ReplacedBy  string // a newer record of the same machine took over (supersededBy); "" when none
}

// Rhythm is the interval an agent is judged by: the longer of what it was told and what it does; before the box has seen what it does,
// the longer of what it was told and its report schedule.
func (c Cadence) Rhythm() time.Duration {
	if c.CallGap > 0 {
		return max(c.CallEvery, c.CallGap)
	}
	return max(c.CallEvery, c.ReportEvery)
}

// NodeHealth is the state of an agent at now, the one rule every reader of agent state uses (the agents list, the device's source row,
// "I updated it", the findings' "no agent reports this device now"). Replaced first: the record is only left to remove. Then quiet:
// silent for more than quietCalls of its rhythm, whatever else is true, since a silent agent needs its service looked at (quietSince is
// its last call). Then never reported: it calls, but delivered nothing within its first-report window (firstReportWindow, schedule.go).
func NodeHealth(c Cadence, now time.Time) (state string, quietSince time.Time) {
	switch {
	case c.ReplacedBy != "":
		return StateReplaced, time.Time{}
	case now.Sub(c.LastCall) > quietCalls*c.Rhythm():
		return StateQuiet, c.LastCall
	case c.LastResult.IsZero() && !c.Enrolled.IsZero() && now.Sub(c.Enrolled) > firstReportWindow:
		return StateNeverReported, time.Time{}
	}
	return StateReporting, time.Time{}
}

// nextGap is the agent's smoothed gap between config fetches after a fetch gap after the call before (old: what it was, 0 = nothing
// learned yet; every: how often it was told to fetch its config). A gap is learned only when it is the refresh the agent was told,
// within refreshSlack: osquery refreshes on a timer, so two fetches of a refreshing agent are its --config_refresh apart, while two
// service starts of an agent without the refresh (an upgrade, then a reboot) are as far apart as they happen to be. Anything else is
// not learned, and the agent stays judged by its report schedule, which covers any slower refresh. A shorter gap within the slack moves
// the rhythm by an eighth of the difference, a longer one at once.
func nextGap(old, gap, every time.Duration) time.Duration {
	if gap < every-every/refreshSlack || gap > every+every/refreshSlack {
		return old
	}
	if gap >= old {
		return gap
	}
	return old - (old-gap)/8
}

// NodeState is one enrolled osquery agent as the screens show it.
type NodeState struct {
	ID, TokenID, Host, OS string // OS is "windows" or "linux" (what picks the service commands)
	State                 string
	HostID                string        // the name it enrolled under, which tells two records of one machine apart
	EnrolledAt, LastSeen  time.Time     // LastSeen is its last call (last_call_at), not the prune-adjusted last_seen
	LastResult            time.Time     // zero = no result log yet
	QuietSince            time.Time     // State quiet: the last call; zero otherwise
	ReplacedBy            string        // State replaced: the id of the newer node
	Rhythm                time.Duration // the interval it is judged by (Cadence.Rhythm): quiet after three of it
}

// forgetSQL is the call_gap_s a result post leaves (SQL, inside the UPDATE that records the post, ?1 = now): forgotten (NULL, judged by
// its report schedule again) when the post comes after a silence that was quiet by the learned refresh. An agent that delivers results
// but does not fetch its config at that pace does not refresh it; one that does relearns its pace from its next two fetches. Computed
// from the row as it is when written, never from a value read before (a config fetch handled at the same time may have changed it).
const forgetSQL = `CASE WHEN call_gap_s IS NOT NULL AND (julianday(?1) - julianday(ifnull(last_call_at, last_seen))) * 86400 > 3 * max(call_gap_s, call_every_s)
	THEN NULL ELSE call_gap_s END`

// supersededBy says whether a newer record is the same machine as this one by what the box itself saw: both are bound to the same
// source address (bound_ip is the TCP peer address of the node's own reports, set by the binding of INV-12, and an unbound node has
// none). The name a node claims, its token and the MAC it declares are claims, not identity: a holder of any token can enrol under another
// machine's name, and two honest machines may share a default name. A newer record that is not bound yet supersedes nothing.
func supersededBy(older nodeStateRow, newer nodeStateRow) bool {
	return newer.enrolled.After(older.enrolled) && older.boundIP != "" && older.boundIP == newer.boundIP
}

// nodeStateRow is the stored times and rhythm of a node.
type nodeStateRow struct {
	id, tokenID, host, hostID, platform string
	boundIP                             string
	enrolled, lastCall, lastResult      time.Time
	callEvery, callGap, reportEvery     time.Duration
}

const nodeStateCols = `id, token_id, ifnull(hostname, host_identifier), host_identifier, ifnull(platform, ''), ifnull(bound_ip, ''), enrolled_at, ifnull(last_call_at, last_seen), ifnull(last_result_at, ''), call_every_s, ifnull(call_gap_s, 0), report_every_s`

func scanNodeState(sc interface{ Scan(...any) error }, extra ...any) (nodeStateRow, error) {
	var r nodeStateRow
	var enrolled, call, result string
	var every, gap, report int64
	if err := sc.Scan(append([]any{&r.id, &r.tokenID, &r.host, &r.hostID, &r.platform, &r.boundIP, &enrolled, &call, &result, &every, &gap, &report}, extra...)...); err != nil {
		return r, err
	}
	r.enrolled, _ = time.Parse(time.RFC3339Nano, enrolled)
	r.lastCall, _ = time.Parse(time.RFC3339Nano, call)
	r.lastResult, _ = time.Parse(time.RFC3339Nano, result)
	r.callEvery, r.callGap, r.reportEvery = time.Duration(every)*time.Second, time.Duration(gap)*time.Second, time.Duration(report)*time.Second
	return r, nil
}

// cadence is the node's Cadence; replacedBy is the newer record that took over ("" when none).
func (r nodeStateRow) cadence(replacedBy string) Cadence {
	return Cadence{Enrolled: r.enrolled, LastCall: r.lastCall, LastResult: r.lastResult, CallEvery: r.callEvery, CallGap: r.callGap, ReportEvery: r.reportEvery,
		ReplacedBy: replacedBy}
}

func (r nodeStateRow) state(now time.Time, replacedBy string) NodeState {
	c := r.cadence(replacedBy)
	n := NodeState{ID: r.id, TokenID: r.tokenID, Host: r.host, HostID: r.hostID, OS: osOf(r.platform), EnrolledAt: r.enrolled, LastSeen: r.lastCall, LastResult: r.lastResult,
		Rhythm: c.Rhythm(), ReplacedBy: replacedBy}
	n.State, n.QuietSince = NodeHealth(c, now)
	return n
}

// osOf maps osquery's platform name ("windows", "ubuntu", "centos", "darwin"...) to the two systems the install scripts serve.
func osOf(platform string) string {
	if strings.EqualFold(platform, "windows") {
		return "windows"
	}
	return "linux"
}

// Nodes lists every enrolled osquery agent with its state: the quiet ones first, then the others by name, the replaced ones last.
func (s *Service) Nodes(ctx context.Context) ([]NodeState, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT `+nodeStateCols+` FROM intake_osquery_nodes ORDER BY lower(ifnull(hostname, host_identifier)), id`)
	if err != nil {
		return nil, fmt.Errorf("agentintake: list nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var all []nodeStateRow
	for rows.Next() {
		r, err := scanNodeState(rows)
		if err != nil {
			return nil, fmt.Errorf("agentintake: list nodes: %w", err)
		}
		all = append(all, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	now := s.now()
	newest := map[string]nodeStateRow{} // the newest record bound to each source address
	for _, r := range all {
		if cur, ok := newest[r.boundIP]; r.boundIP != "" && (!ok || r.enrolled.After(cur.enrolled)) {
			newest[r.boundIP] = r
		}
	}
	var quiet, rest, replaced []NodeState
	for _, r := range all {
		by := ""
		if top, ok := newest[r.boundIP]; ok && top.id != r.id && supersededBy(r, top) {
			by = top.id
		}
		switch n := r.state(now, by); n.State {
		case StateReplaced:
			replaced = append(replaced, n)
		case StateQuiet:
			quiet = append(quiet, n)
		default:
			rest = append(rest, n)
		}
	}
	return append(append(quiet, rest...), replaced...), nil
}

// RemoveNode deletes one agent record (admin, audited) and releases its device, so that a stale record (an uninstalled agent, a
// decommissioned server, an older record of a re-installed one) is cleared without revoking the token other machines use.
func (s *Service) RemoveNode(ctx context.Context, actor, id string) error {
	err := s.db.Write(ctx, func(tx *sql.Tx) error {
		var host, token string
		err := tx.QueryRowContext(ctx, `SELECT ifnull(hostname, host_identifier), (SELECT name FROM intake_agent_tokens t WHERE t.id = token_id) FROM intake_osquery_nodes WHERE id = ?`, id).Scan(&host, &token)
		if errors.Is(err, sql.ErrNoRows) {
			return apierr.NotFound()
		}
		if err != nil {
			return fmt.Errorf("agentintake: read node: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM intake_osquery_nodes WHERE id = ?`, id); err != nil {
			return fmt.Errorf("agentintake: delete node: %w", err)
		}
		return s.auditTx(ctx, tx, actor, "inventory.agent_node_remove", host, fmt.Sprintf("token %q", token))
	})
	if err == nil {
		s.releaseNodes(ctx, []string{id})
	}
	return err
}
