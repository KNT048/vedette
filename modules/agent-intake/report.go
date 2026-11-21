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

// ReportState is what "I updated it" and the device's agent row need to know of a device's agent.
type ReportState struct {
	Agent string
	// Off: a person turned the agent off for this device (observe.AgentDevice.AgentOff): its data is refused, nothing can be asked, and
	// no agent reports the device now, whatever Agent and State say of the agent itself.
	Off bool
	// AskedAt is the open ask (askOpen), zero when none.
	AskedAt time.Time
	// AskAgainAt is when a new ask is possible (the last ask + reportCooldown) while that is in the future, zero otherwise.
	AskAgainAt time.Time
	// LastSeen is the agent's last call (osquery: config or results; Wazuh: the last pull that delivered the device), zero for the others;
	// State is NodeHealth's answer for it at that time (osquery and Wazuh), "" for the others, and Stale is State quiet.
	LastSeen time.Time
	Stale    bool
	State    string
	// QuietSince is set when State is quiet; Rhythm is the interval the agent is judged by (Cadence.Rhythm), 0 for the box and none.
	QuietSince time.Time
	Rhythm     time.Duration
	// OS is the machine's system (osquery only).
	OS string
	// WazuhMinutes is the Wazuh pull's interval when Agent is ReportWazuh, else 0.
	WazuhMinutes int
	// Setup is the token "Show setup" shows for the device: the token its osquery agent enrolled with, else the newest token a person
	// made for this device that still enrols machines; nil when none.
	Setup *Token
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
	now := s.now()
	setup := func(st ReportState, tokenID string) (ReportState, error) {
		tk, err := s.setupToken(ctx, device, tokenID)
		st.Setup, st.Off = tk, d.AgentOff
		return st, err
	}
	if id, ok := strings.CutPrefix(d.Agent, "osquery:"); ok {
		var asked, taken string
		bound, err := scanNodeState(s.db.Reader().QueryRowContext(ctx, `SELECT `+nodeStateCols+`, ifnull(report_asked_at, ''), ifnull(software_taken_at, '') FROM intake_osquery_nodes WHERE id = ?`, id), &asked, &taken)
		switch {
		case err == nil:
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
			c := live.cadence("")
			st := ReportState{Agent: ReportOsquery, LastSeen: live.lastCall, Rhythm: c.Rhythm(), OS: osOf(live.platform)}
			st.State, st.QuietSince = NodeHealth(c, now)
			st.Stale = st.State == StateQuiet // one rule: "no agent reports this device now" and "quiet" are the same fact
			if askOpen(nodeRow{askedAt: n.askedAt, softwareAt: n.softwareAt}, now) {
				st.AskedAt = n.askedAt
			}
			if again := n.askedAt.Add(reportCooldown); !n.askedAt.IsZero() && again.After(now) {
				st.AskAgainAt = again
			}
			st, err := setup(st, live.tokenID)
			return st, n, err
		case !errors.Is(err, sql.ErrNoRows): // a binding whose node is gone (the inventory releases it) is no osquery agent
			return ReportState{}, askNode{}, fmt.Errorf("agentintake: read node: %w", err)
		}
	}
	w, err := s.wazuhReads(ctx, d)
	if err != nil {
		return ReportState{}, askNode{}, err
	}
	if w.minutes > 0 {
		// Wazuh by its pull: the device's agent last called when Wazuh last heard from it (its keep-alive, as the last pull that
		// delivered it read it), and the pull interval is its rhythm: a disconnected agent, or a pull that stopped, turns quiet.
		c := Cadence{LastCall: w.seen, LastResult: w.seen, CallEvery: time.Duration(w.minutes) * time.Minute}
		st := ReportState{Agent: ReportWazuh, WazuhMinutes: w.minutes, LastSeen: w.seen, Rhythm: c.Rhythm()}
		st.State, st.QuietSince = NodeHealth(c, now)
		st.Stale = st.State == StateQuiet
		st, err := setup(st, "")
		return st, askNode{}, err
	}
	st, err := setup(ReportState{Agent: ReportNone}, "")
	return st, askNode{}, err
}

// wazuhRead is what the saved Wazuh connection's last pass says of a device: the pull's interval in minutes (0 when no agent of it was
// delivered to the device) and when Wazuh last heard from its agent (intake_wazuh_agent.seen_at).
type wazuhRead struct {
	minutes int
	seen    time.Time
}

// wazuhReads is the Wazuh pull's interval and the newest delivery when the last pass delivered to the device's address or MAC (the
// inventory's own marker of a Wazuh device, WazuhAgentAddresses); zero when not or when no Wazuh server is connected.
func (s *Service) wazuhReads(ctx context.Context, d observe.AgentDevice) (wazuhRead, error) {
	ip := ""
	if d.IP.IsValid() {
		ip = d.IP.String()
	}
	if ip == "" && d.MAC == "" {
		return wazuhRead{}, nil
	}
	var seen sql.NullString
	err := s.db.Reader().QueryRowContext(ctx, `SELECT max(a.seen_at) FROM intake_wazuh w JOIN intake_wazuh_agent a ON a.generation = w.generation
		WHERE w.id = 1 AND ((?1 <> '' AND a.ip = ?1) OR (?2 <> '' AND lower(a.mac) = lower(?2)))`, ip, d.MAC).Scan(&seen)
	if errors.Is(err, sql.ErrNoRows) || err == nil && !seen.Valid {
		return wazuhRead{}, nil
	}
	if err != nil {
		return wazuhRead{}, fmt.Errorf("agentintake: read wazuh agents: %w", err)
	}
	t, _ := time.Parse(time.RFC3339Nano, seen.String)
	return wazuhRead{minutes: wazuhMinutes(ctx, s.db.Reader()), seen: t}, nil
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
	if st.Off {
		return ReportState{}, apierr.New(409, "agent_off", "The agent is turned off for this device, so Vedette takes none of its data. Turn it on first.")
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
