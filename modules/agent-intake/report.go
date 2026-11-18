package agentintake

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/knt048/vedette/core/apierr"
	"github.com/knt048/vedette/core/observe"
	"github.com/knt048/vedette/core/store"
)

// "I updated it: ask the agent now" (S-MIT-1, INV-23). A person who updated software an osquery agent reads asks
// that device's node to send its software again now instead of within the hour. Nothing new is sent to the node: the ask only makes
// config hand the software queries of the schedule the first-report interval (60 s) while it is open (nodeSchedule), the way the
// first report does. Same queries, same columns, no distributed query (INV-13, INV-15, TestScheduleIsReadOnly).
const (
	// reportWindow ends an ask by itself: osquery fetches its config every 300 s (--config_refresh), runs a 60 s query within the
	// minute, and one source address replaces a software list at most once per sourceWindow, so a list arrives well within it.
	reportWindow = 15 * time.Minute
	// reportCooldown is the least time between two asks of one node (the per-device rate limit): an ask that is still open is
	// answered as it is, a new one sooner is 429.
	reportCooldown = 10 * time.Minute
)

// reportQueries are the software queries an open ask speeds up: the package lists, the running kernel and Windows' update revision
// (an OS update changes these two after its restart). Never the others.
var reportQueries = []string{"deb_packages", "rpm_packages", "programs", "kernel_info", "os_revision"}

// askOpen says a person's ask of this node is open at now: younger than reportWindow and no software list taken since.
func askOpen(n nodeRow, now time.Time) bool {
	if n.askedAt.IsZero() || now.Before(n.askedAt) || now.Sub(n.askedAt) >= reportWindow {
		return false
	}
	return n.softwareAt.Before(n.askedAt)
}

// osAnswer says whether an ask of this node waits for its own operating-system answer, and whether this request carries it: a usable
// os_revision on Windows (the update revision the Windows row of the list is built from), a usable kernel_info elsewhere (the
// running kernel the Kernel row is built from). A node that never gave one (an osquery older than 5.12 on Windows) is not waited
// for: the list alone answers its ask.
func osAnswer(n nodeRow, in logIn) (needed, got bool) {
	if n.platform == "windows" || n.win.version != "" {
		_, got = parseWinOS(in.snaps["os_revision"])
		return n.win.version != "", got
	}
	if rows := in.snaps["kernel_info"]; len(rows) > 0 {
		got = kernelReleaseRE.MatchString(strings.ToLower(rows[0]["version"]))
	}
	return n.kernel != "", got
}

// answeredAsk closes an open ask once the inventory took the node's software list AFTER the node's own OS answer came since the ask
// (review r1 M1 of #953): osquery runs the package list and kernel_info (or os_revision) on separately splayed intervals, so a list
// taken first carries the old kernel or update revision and must not end the ask; the ask stays open and the next list the inventory
// takes, built with the new one, ends it. A request with both counts (its OS answer is stored before its list is built). Config puts
// the node back on the hourly schedule at its next fetch. Nothing is written when no ask is open.
func (s *Service) answeredAsk(ctx context.Context, n nodeRow, in logIn, taken []string) error {
	now := s.now()
	if !askOpen(n, now) {
		return nil
	}
	needed, got := osAnswer(n, in)
	osAt := n.osAt
	if got {
		osAt = now
	}
	done := slices.Contains(taken, "packages") && (!needed || !osAt.IsZero() && !osAt.Before(n.askedAt))
	if !got && !done {
		return nil
	}
	ts := store.FormatTS(now)
	return s.db.Write(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE intake_osquery_nodes SET os_taken_at = CASE WHEN ? THEN ? ELSE os_taken_at END,
			software_taken_at = CASE WHEN ? THEN ? ELSE software_taken_at END WHERE id = ?`, got, ts, done, ts, n.id); err != nil {
			return fmt.Errorf("agentintake: mark the ask answered: %w", err)
		}
		return nil
	})
}

// The agents a device can have, as GET and POST /inventory/agents/devices/{id}/report say it.
const (
	ReportOsquery = "osquery" // an osquery node of this box is bound to the device: Vedette can ask it
	ReportWazuh   = "wazuh"   // only the Wazuh pull reads the device: Vedette cannot ask; the next pull brings the list
	ReportNone    = "none"    // no agent of this box reads the device now
	ReportBox     = "box"     // the Vedette box itself: it reads its own packages (inventory job box, hourly), no agent
)

// ReportState is what "I updated it" needs to know of a device's agent.
type ReportState struct {
	Agent string
	// AskedAt is the open ask (askOpen), zero when none.
	AskedAt time.Time
	// AskAgainAt is when a new ask is possible (the last ask + reportCooldown) while that is in the future, zero otherwise.
	AskAgainAt time.Time
	// LastSeen is when the osquery node last called (config or log), zero when not osquery; Stale is State quiet (nodestate.go: three missed config calls).
	LastSeen time.Time
	Stale    bool
	// State, QuietSince and OS are the agent's state (nodestate.go), set for an osquery agent only.
	State      string
	QuietSince time.Time
	OS         string
	// WazuhMinutes is the Wazuh pull's interval when Agent is ReportWazuh, else 0.
	WazuhMinutes int
}

// askNode is the osquery node bound to a device, as the ask needs it.
type askNode struct {
	id                  string
	askedAt, softwareAt time.Time
}

// ReportState says which agent of this box reads the device and whether an ask is open. 404 not_found for an unknown device.
func (s *Service) ReportState(ctx context.Context, device string) (ReportState, error) {
	st, _, err := s.reportState(ctx, device)
	return st, err
}

func (s *Service) reportState(ctx context.Context, device string) (ReportState, askNode, error) {
	devs, ok := s.cfg.Approver.(observe.AgentDevices)
	if !ok {
		return ReportState{Agent: ReportNone}, askNode{}, nil
	}
	d, found, err := devs.AgentDevice(ctx, device)
	if err != nil {
		return ReportState{}, askNode{}, err
	}
	if !found {
		return ReportState{}, askNode{}, apierr.NotFound()
	}
	if d.IsBox {
		return ReportState{Agent: ReportBox}, askNode{}, nil
	}
	if id, ok := strings.CutPrefix(d.Agent, "osquery:"); ok {
		var enrolledS, callS, resultS string
		var asked, taken string
		var bound nodeStateRow
		err := s.db.Reader().QueryRowContext(ctx, `SELECT ifnull(report_asked_at, ''), ifnull(software_taken_at, ''), `+nodeStateCols+` FROM intake_osquery_nodes WHERE id = ?`, id).
			Scan(&asked, &taken, &bound.id, &bound.tokenID, &bound.host, &bound.hostID, &bound.platform, &bound.boundIP, &enrolledS, &callS, &resultS)
		switch {
		case err == nil:
			bound.enrolled, _ = time.Parse(time.RFC3339Nano, enrolledS)
			bound.lastCall, _ = time.Parse(time.RFC3339Nano, callS)
			bound.lastResult, _ = time.Parse(time.RFC3339Nano, resultS)
			now := s.now()
			n := askNode{id: id}
			n.askedAt, _ = time.Parse(time.RFC3339Nano, asked)
			n.softwareAt, _ = time.Parse(time.RFC3339Nano, taken)
			// The device stays bound to the first node that read it. When the machine was enrolled again (another token, a re-install),
			// its state is the newest record bound to the same source address (what the box saw, not a name a node claims).
			live := bound
			if top, found, err := s.newestOf(ctx, bound); err != nil {
				return ReportState{}, askNode{}, err
			} else if found && supersededBy(bound, top) {
				live = top
			}
			st := ReportState{Agent: ReportOsquery}
			st.LastSeen = live.lastCall
			st.State, st.QuietSince = stateOf(now, live.enrolled, live.lastCall, live.lastResult)
			st.Stale = st.State == StateQuiet // one rule: "no agent reports this device now" and "quiet" are the same fact
			st.OS = osOf(live.platform)
			if askOpen(nodeRow{askedAt: n.askedAt, softwareAt: n.softwareAt}, now) {
				st.AskedAt = n.askedAt
			}
			if again := n.askedAt.Add(reportCooldown); !n.askedAt.IsZero() && again.After(now) {
				st.AskAgainAt = again
			}
			return st, n, nil
		case !errors.Is(err, sql.ErrNoRows): // a binding whose node is gone (the inventory releases it) is no osquery agent
			return ReportState{}, askNode{}, fmt.Errorf("agentintake: read node: %w", err)
		}
	}
	minutes, err := s.wazuhReads(ctx, d)
	if err != nil {
		return ReportState{}, askNode{}, err
	}
	if minutes > 0 {
		return ReportState{Agent: ReportWazuh, WazuhMinutes: minutes}, askNode{}, nil
	}
	return ReportState{Agent: ReportNone}, askNode{}, nil
}

// wazuhReads is the Wazuh pull's interval in minutes when the last pass delivered to the device's address or MAC (the inventory's
// own marker of a Wazuh device, WazuhAgentAddresses), 0 when not or when no Wazuh server is connected.
func (s *Service) wazuhReads(ctx context.Context, d observe.AgentDevice) (int, error) {
	ip := ""
	if d.IP.IsValid() {
		ip = d.IP.String()
	}
	if ip == "" && d.MAC == "" {
		return 0, nil
	}
	var minutes int
	err := s.db.Reader().QueryRowContext(ctx, `SELECT w.interval_minutes FROM intake_wazuh w JOIN intake_wazuh_agent a ON a.generation = w.generation
		WHERE w.id = 1 AND ((?1 <> '' AND a.ip = ?1) OR (?2 <> '' AND lower(a.mac) = lower(?2))) LIMIT 1`, ip, d.MAC).Scan(&minutes)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("agentintake: read wazuh agents: %w", err)
	}
	return minutes, nil
}

// errCannotAsk is the 409 of an ask Vedette cannot make: the device has no osquery node of this box (Wazuh only, or no agent).
func errCannotAsk() error {
	return apierr.New(409, "cannot_ask", "Vedette cannot ask this device's agent to report now: only an osquery agent enrolled with this box can be asked.")
}

// AskReport asks the osquery node bound to the device to send its software now (operator, audited). An ask that is still open is
// answered as it is (nothing written, no second audit row); a new ask within reportCooldown of the last is 429 rate_limited; a device
// Vedette cannot ask (Wazuh only, no agent) is 409 cannot_ask; an unknown device 404.
func (s *Service) AskReport(ctx context.Context, actor, device string) (ReportState, error) {
	st, n, err := s.reportState(ctx, device)
	if err != nil {
		return ReportState{}, err
	}
	if st.Agent != ReportOsquery {
		return ReportState{}, errCannotAsk()
	}
	if !st.AskedAt.IsZero() {
		return st, nil
	}
	now := s.now()
	if !n.askedAt.IsZero() && !now.Before(n.askedAt) && now.Sub(n.askedAt) < reportCooldown {
		wait := reportCooldown - now.Sub(n.askedAt)
		secs := max(1, int((wait+time.Second-1)/time.Second))
		mins := (secs + 59) / 60
		unit := "minutes"
		if mins == 1 {
			unit = "minute"
		}
		return ReportState{}, apierr.New(429, "rate_limited", fmt.Sprintf("Vedette asked this agent less than %d minutes ago and its list came. Ask again in %d %s.", int(reportCooldown/time.Minute), mins, unit)).With("retry_after", secs)
	}
	err = s.db.Write(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE intake_osquery_nodes SET report_asked_at = ? WHERE id = ?`, store.FormatTS(now), n.id)
		if err != nil {
			return fmt.Errorf("agentintake: ask the node: %w", err)
		}
		if c, _ := res.RowsAffected(); c == 0 { // the node was deleted since (revoke, prune, re-enrolment)
			return errCannotAsk()
		}
		return s.auditTx(ctx, tx, actor, "inventory.agent_report_now", device, "osquery node "+n.id)
	})
	if err != nil {
		return ReportState{}, err
	}
	st.AskedAt, st.AskAgainAt = now, now.Add(reportCooldown)
	return st, nil
}

// newestOf is the newest record bound to the same source address as n; found is false when n has no binding or is the newest.
func (s *Service) newestOf(ctx context.Context, n nodeStateRow) (nodeStateRow, bool, error) {
	if n.boundIP == "" {
		return nodeStateRow{}, false, nil
	}
	top, err := scanNodeState(s.db.Reader().QueryRowContext(ctx, `SELECT `+nodeStateCols+` FROM intake_osquery_nodes WHERE bound_ip = ? AND id <> ? ORDER BY enrolled_at DESC LIMIT 1`, n.boundIP, n.id))
	if errors.Is(err, sql.ErrNoRows) {
		return nodeStateRow{}, false, nil
	}
	if err != nil {
		return nodeStateRow{}, false, fmt.Errorf("agentintake: read newest node: %w", err)
	}
	return top, top.enrolled.After(n.enrolled), nil
}
