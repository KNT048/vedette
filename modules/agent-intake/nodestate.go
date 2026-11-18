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

// The state of an enrolled osquery agent, from its own check-ins against its own schedule. The install scripts set --config_refresh=300,
// so a running agent asks for its config every five minutes; the box cannot see the flag on the machine, and the config it serves is the
// one that sets it, so that interval is the schedule. Quiet after three missed calls: one lost call (a busy box, a network blip) must not
// raise it, and a stopped service is found within a quarter of an hour.
const (
	StateReporting     = "reporting"
	StateQuiet         = "quiet"
	StateNeverReported = "never_reported"
	StateReplaced      = "replaced" // a newer agent of the same machine took over; the older record is only kept until it is removed or pruned

	configRefresh = 5 * time.Minute
	quietAfter    = 3 * configRefresh
)

// NodeState is one enrolled osquery agent as the screens show it.
type NodeState struct {
	ID, TokenID, Host, OS string // OS is "windows" or "linux" (what picks the service commands)
	State                 string
	HostID                string    // the name it enrolled under, which tells two records of one machine apart
	EnrolledAt, LastSeen  time.Time // LastSeen is its last call (last_call_at), not the prune-adjusted last_seen
	LastResult            time.Time // zero = no result log yet
	QuietSince            time.Time // State quiet: the last call; zero otherwise
	ReplacedBy            string    // State replaced: the id of the newer node
}

// stateOf classifies a node. Quiet wins over never reported: a silent agent needs its service looked at, whatever else is true. A node
// that checks in but delivered nothing is only "never reported" once its first-report window (firstReportWindow, schedule.go) is over.
func stateOf(now, enrolled, lastCall, lastResult time.Time) (string, time.Time) {
	if now.Sub(lastCall) > quietAfter {
		return StateQuiet, lastCall
	}
	if lastResult.IsZero() && now.Sub(enrolled) > firstReportWindow {
		return StateNeverReported, time.Time{}
	}
	return StateReporting, time.Time{}
}

// supersededBy says whether a newer record of the same machine (same host identifier, any token) took over from this one: it was enrolled
// later and the older agent did not call after it (a re-install under another token stops the old agent first). An older agent that still
// calls after the newer one enrolled is another machine with the same name, and keeps its own state.
func supersededBy(older nodeStateRow, newer nodeStateRow) bool {
	return newer.enrolled.After(older.enrolled) && !older.lastCall.After(newer.enrolled.Add(time.Minute))
}

// nodeStateRow is the stored times of a node.
type nodeStateRow struct {
	id, tokenID, host, hostID, platform string
	enrolled, lastCall, lastResult      time.Time
}

const nodeStateCols = `id, token_id, ifnull(hostname, host_identifier), host_identifier, ifnull(platform, ''), enrolled_at, ifnull(last_call_at, last_seen), ifnull(last_result_at, '')`

func scanNodeState(sc interface{ Scan(...any) error }) (nodeStateRow, error) {
	var r nodeStateRow
	var enrolled, call, result string
	if err := sc.Scan(&r.id, &r.tokenID, &r.host, &r.hostID, &r.platform, &enrolled, &call, &result); err != nil {
		return r, err
	}
	r.enrolled, _ = time.Parse(time.RFC3339Nano, enrolled)
	r.lastCall, _ = time.Parse(time.RFC3339Nano, call)
	r.lastResult, _ = time.Parse(time.RFC3339Nano, result)
	return r, nil
}

func (r nodeStateRow) state(now time.Time) NodeState {
	n := NodeState{ID: r.id, TokenID: r.tokenID, Host: r.host, HostID: r.hostID, OS: osOf(r.platform), EnrolledAt: r.enrolled, LastSeen: r.lastCall, LastResult: r.lastResult}
	n.State, n.QuietSince = stateOf(now, r.enrolled, r.lastCall, r.lastResult)
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
	newest := map[string]nodeStateRow{} // the newest record of each machine name
	for _, r := range all {
		k := strings.ToLower(r.hostID)
		if cur, ok := newest[k]; !ok || r.enrolled.After(cur.enrolled) {
			newest[k] = r
		}
	}
	var quiet, rest, replaced []NodeState
	for _, r := range all {
		n := r.state(now)
		if top := newest[strings.ToLower(r.hostID)]; top.id != r.id && supersededBy(r, top) {
			n.State, n.QuietSince, n.ReplacedBy = StateReplaced, time.Time{}, top.id
			replaced = append(replaced, n)
		} else if n.State == StateQuiet {
			quiet = append(quiet, n)
		} else {
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
