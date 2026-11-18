package agentintake

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// The state of an enrolled osquery agent, from its own check-ins against its own schedule. The install scripts set --config_refresh=300,
// so a running agent asks for its config every five minutes; the box cannot see the flag on the machine, and the config it serves is the
// one that sets it, so that interval is the schedule. Quiet after three missed calls: one lost call (a busy box, a network blip) must not
// raise it, and a stopped service is found within a quarter of an hour.
const (
	StateReporting     = "reporting"
	StateQuiet         = "quiet"
	StateNeverReported = "never_reported"

	configRefresh = 5 * time.Minute
	quietAfter    = 3 * configRefresh
)

// NodeState is one enrolled osquery agent as the screens show it.
type NodeState struct {
	ID, TokenID, Host, OS string // OS is "windows" or "linux" (what picks the service commands)
	State                 string
	EnrolledAt, LastSeen  time.Time
	LastResult            time.Time // zero = no result log yet
	QuietSince            time.Time // State quiet: the last call; zero otherwise
}

// stateOf classifies a node. Quiet wins over never reported: a silent agent needs its service looked at, whatever else is true. A node
// that checks in but delivered nothing is only "never reported" once its first-report window (firstReportWindow, schedule.go) is over.
func stateOf(now, enrolled, lastSeen, lastResult time.Time) (string, time.Time) {
	if now.Sub(lastSeen) > quietAfter {
		return StateQuiet, lastSeen
	}
	if lastResult.IsZero() && now.Sub(enrolled) > firstReportWindow {
		return StateNeverReported, time.Time{}
	}
	return StateReporting, time.Time{}
}

// osOf maps osquery's platform name ("windows", "ubuntu", "centos", "darwin"...) to the two systems the install scripts serve.
func osOf(platform string) string {
	if strings.EqualFold(platform, "windows") {
		return "windows"
	}
	return "linux"
}

// Nodes lists every enrolled osquery agent with its state, the quiet ones first, then by name.
func (s *Service) Nodes(ctx context.Context) ([]NodeState, error) {
	rows, err := s.db.Reader().QueryContext(ctx, `SELECT id, token_id, ifnull(hostname, host_identifier), ifnull(platform, ''), enrolled_at, last_seen, ifnull(last_result_at, '')
		FROM intake_osquery_nodes ORDER BY lower(ifnull(hostname, host_identifier)), id`)
	if err != nil {
		return nil, fmt.Errorf("agentintake: list nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()
	now := s.now()
	out := []NodeState{}
	for rows.Next() {
		var n NodeState
		var platform, enrolled, seen, result string
		if err := rows.Scan(&n.ID, &n.TokenID, &n.Host, &platform, &enrolled, &seen, &result); err != nil {
			return nil, fmt.Errorf("agentintake: list nodes: %w", err)
		}
		n.OS = osOf(platform)
		n.EnrolledAt, _ = time.Parse(time.RFC3339Nano, enrolled)
		n.LastSeen, _ = time.Parse(time.RFC3339Nano, seen)
		n.LastResult, _ = time.Parse(time.RFC3339Nano, result)
		n.State, n.QuietSince = stateOf(now, n.EnrolledAt, n.LastSeen, n.LastResult)
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// quiet first (stable: the name order is kept inside each group)
	quiet := make([]NodeState, 0, len(out))
	rest := make([]NodeState, 0, len(out))
	for _, n := range out {
		if n.State == StateQuiet {
			quiet = append(quiet, n)
		} else {
			rest = append(rest, n)
		}
	}
	return append(quiet, rest...), nil
}
