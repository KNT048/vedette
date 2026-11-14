package exposure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/knt048/vedette/core/store"
)

// Optional deep scan with Greenbone Community Edition (OpenVAS), off by default (S-EXP-2, CONTRACT INV-25, D-563, plan
// exposure-real-vulns §5 slice d). Greenbone runs as its own unmodified compose project next to Vedette (separate processes; its
// GPL/AGPL code is not embedded); the host starts and stops it and hands over a connection to the gvmd socket (GreenboneHost).
// Exposure decides when it may scan (a verified, committed, not-paused IP target, after the other steps of the same run), talks GMP
// (gmp.go), reads its report as untrusted data and shows the results apart: Greenbone looks from outside without logging in, so
// finding nothing is never "not affected", and its rows never replace, close or hide a version, product or template row.

// GreenboneHost is the host side (vedette-host, Trưởng's): Greenbone's official compose project pinned by image digest, under its
// own podman project name, with the gvmd socket mounted into core and the GMP password generated on install and kept in
// core/secrets. Up starts the project (the first time it pulls about 9 GB of images); Down stops it and keeps its volumes (the
// feed, about 41 GB, and gvmd's database); Dial opens the gvmd unix socket and returns the GMP login the host created. Uninstalling
// Vedette never touches the project or its volumes. A step that cannot run for a reason the page may show returns *Unavailable.
type GreenboneHost interface {
	Up(ctx context.Context) error
	Down(ctx context.Context) error
	Dial(ctx context.Context) (net.Conn, GMPLogin, error)
}

// GreenboneProbe is the probe log row written before Greenbone's task starts (LEGAL §3): the target address, the port list, the
// scan config and a note that Greenbone sends many probes (they cannot be logged one by one: the scanner is Greenbone's).
type GreenboneProbe struct {
	ID       string
	IP       string
	PortList string
	Config   string
	Note     string
}

// GreenboneProbeLog is implemented by the ProbeLog of Config.Probes next to the template and web probes: the row must be written
// when it returns without an error. Greenbone does not run when it fails, or when Config.Probes does not implement it.
type GreenboneProbeLog interface {
	RecordGreenboneProbe(ctx context.Context, p GreenboneProbe) error
}

// ExploitedLookup is an optional second face of the Matcher: which of these CVE ids are on today's list of exploited
// vulnerabilities (CISA KEV), with the entry's name, the day it was listed and the ransomware flag. Greenbone names CVEs by itself;
// only those on the list become exploited-CVE rows. A Matcher that does not implement it leaves Greenbone's CVEs in its own section,
// and the page says they were not compared.
type ExploitedLookup interface {
	Exploited(ctx context.Context, cves []string) (map[string]KEVEntry, error)
}

// KEVEntry is what the list says about one exploited CVE.
type KEVEntry struct {
	Name       string
	DateAdded  *string
	Ransomware bool
}

// GreenboneRow is one result of Greenbone's report (contract.ts GreenboneResult): severity (CVSS 0.1 to 10), the test's name, the port
// ("443/tcp", "general/tcp"; "" when it gave none that reads as one), QoD (70 to 100), the CVE ids the test names, Greenbone's advice
// (clipped) and the test's OID. IP is the scanned address.
type GreenboneRow struct {
	IP       string   `json:"ip"`
	Port     string   `json:"port"`
	Severity float64  `json:"severity"`
	Name     string   `json:"name"`
	QoD      int      `json:"qod"`
	CVEs     []string `json:"cves"`
	Solution string   `json:"solution"`
	OID      string   `json:"oid"`
}

// Limits and timing of the deep scan (INV-25).
const (
	// GreenboneMinMemory is the least memory (MemTotal) the box needs before Greenbone may be enabled: 8 GB decimal, Greenbone's
	// recommended size. Decimal on purpose: a machine sold as "8 GB" has 8 GiB and its kernel reports about 7.7 GiB (8.3e9 bytes) of
	// MemTotal, which passes; the 7 GB N100 of the trial (D-494) does not.
	GreenboneMinMemory = 8_000_000_000
	// GreenboneMinDisk is the least free space of the box data directory's filesystem: images 9 GB + feed volumes 41 GB measured, plus
	// room for the reports and updates. ponytail: statfs of the data dir, since podman keeps its volumes on the same filesystem by
	// default; upgrade: the host measures podman's own storage (graphroot) and reports it.
	GreenboneMinDisk = 60_000_000_000
	// GreenboneTimeout bounds one Greenbone scan (the trial's Full and fast run on one Ubuntu host took 3 min 22 s).
	GreenboneTimeout = 90 * time.Minute
	// GreenboneStartGrace is how long after Up the socket may still be missing before the page calls it an error.
	GreenboneStartGrace = 30 * time.Minute

	maxGreenboneRows = 200 // rows kept per snapshot, the highest severity first
	gbProbeEvery     = 30 * time.Second
	gbDialTimeout    = 15 * time.Second
	gbUpTimeout      = 60 * time.Minute // the first Up pulls about 9 GB of images (25 minutes on the N100)
	gbDownTimeout    = 5 * time.Minute
	gbPollDefault    = 15 * time.Second
	gbNote           = "Greenbone sends many probes: every test of the config on every port of the list. They are not logged one by one."
	gbConfigText     = "Full and fast without brute force, default accounts or denial of service; safe checks on"
)

// The states of the Greenbone setting (contract.ts GreenboneState).
const (
	GBUnavailable = "unavailable" // no GreenboneHost on this box
	GBOff         = "off"
	GBStarting    = "starting"
	GBLoading     = "loading" // the feed loads (the first time about 2 hours): a phase, not a hang
	GBReady       = "ready"
	GBError       = "error"
)

// The sentences of the deep scan. NotAvailableGreenbone is the page's and the scan's line when no GreenboneHost is wired.
const (
	NotAvailableGreenbone = "Greenbone is not available on this box."
	notGBOff              = "Optional deep scan with Greenbone (OpenVAS) is off. An administrator can turn it on under Settings on the External exposure page."
	notGBDomain           = "Greenbone (OpenVAS) runs on the box's own verified public IP only, never on the names of a domain."
	notGBStarting         = "Greenbone (OpenVAS) did not scan: it is still starting."
	notGBLoading          = "Greenbone (OpenVAS) did not scan: it is loading its feed (the first time takes about 2 hours)."
	notGBGate             = "Greenbone (OpenVAS) did not scan: this IP can no longer be scanned (it was removed, paused, no longer verified or needs the scan confirmed again), so nothing was sent."
	notGBNoLog            = "Greenbone (OpenVAS) did not scan: the probe log is not available, and nothing is sent without it."
	notGBSlow             = "Greenbone (OpenVAS) did not finish within 90 minutes, so its results are not shown."
	notGBFail             = "Greenbone (OpenVAS) failed, so its results are not shown. The box log has the error."
	notGBUnread           = "Greenbone (OpenVAS) returned an answer that could not be read, so its results are not shown."
	notGBNotCompared      = "The CVEs Greenbone named were not compared with the list of exploited vulnerabilities: that comparison is not set up on this box yet."
	gbLoadingReason       = "Greenbone is loading its feed (first time takes about 2 hours)"
	gbNotAnswering        = "Greenbone does not answer on its socket. Turn it off and on again to restart it."
	gbAuthFailed          = "Vedette could not sign in to Greenbone (GMP). The login the box created for it was refused."
	gbUnreadable          = "Greenbone answered in a way Vedette could not read."
)

// The answers of the setting.
var (
	ErrGreenboneUnavailable = apiErr(501, "not_implemented", NotAvailableGreenbone)
)

// GreenboneView is the setting as the page sees it (contract.ts Greenbone). Reason says why for error and unavailable. Preflight is
// what this box measures against the thresholds, so the page shows the numbers before Enable.
type GreenboneView struct {
	State     string             `json:"state"`
	Reason    *string            `json:"reason"`
	ChangedBy *string            `json:"changed_by"`
	ChangedAt *string            `json:"changed_at"`
	Preflight GreenbonePreflight `json:"preflight"`
}

// GreenbonePreflight is the measurement of this box: memory (MemTotal) and free disk of the data directory, in bytes (nil when it
// could not be read), whether both meet the thresholds, and the plain-English reason when not.
type GreenbonePreflight struct {
	MemoryBytes   *int64  `json:"memory_bytes"`
	DiskFreeBytes *int64  `json:"disk_free_bytes"`
	OK            bool    `json:"ok"`
	Reason        *string `json:"reason"`
	Code          string  `json:"-"`
}

// gbState is what the Service knows of Greenbone in memory (a restart forgets it and Up runs again when it is enabled).
type gbState struct {
	mu       sync.Mutex
	upping   bool
	upWG     sync.WaitGroup // the Up goroutine (Close and tests wait for it)
	upCancel context.CancelFunc
	upErr    string
	upAt     time.Time
	probeAt  time.Time
	state    string
	reason   string
	// injectable for tests
	memTotal func() (int64, error)
	diskFree func(dir string) (int64, error)
	poll     time.Duration
	cap      time.Duration
}

// gb returns the Greenbone state, made on first use.
func (s *Service) gb() *gbState {
	s.gbOnce.Do(func() {
		s.gbs = &gbState{memTotal: memTotal, diskFree: diskFree, poll: gbPollDefault, cap: GreenboneTimeout}
	})
	return s.gbs
}

// memTotal reads MemTotal from /proc/meminfo, in bytes.
func memTotal() (int64, error) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, fmt.Errorf("reading /proc/meminfo: %w", err)
	}
	return parseMemTotal(string(b))
}

func parseMemTotal(meminfo string) (int64, error) {
	for _, line := range strings.Split(meminfo, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "MemTotal:" && f[2] == "kB" {
			kb, err := strconv.ParseInt(f[1], 10, 64)
			if err != nil || kb <= 0 || kb > 1<<40 {
				break
			}
			return kb * 1024, nil
		}
	}
	return 0, errors.New("no MemTotal line in /proc/meminfo")
}

// diskFree is the space an unprivileged writer may use on dir's filesystem, in bytes.
func diskFree(dir string) (int64, error) {
	if dir == "" {
		return 0, errors.New("no data directory configured")
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", dir, err)
	}
	return int64(st.Bavail) * int64(st.Bsize), nil //nolint:gosec,unconvert // block counts of a real filesystem fit; Bsize differs in type between Linux and macOS
}

// gbText is a byte count as the page says it: decimal GB with one decimal ("7.1 GB").
func gbText(n int64) string { return strconv.FormatFloat(float64(n)/1e9, 'f', 1, 64) + " GB" }

// preflight measures the box against the thresholds (INV-25). The reason names the measured number and the threshold.
func (s *Service) preflight() GreenbonePreflight {
	g := s.gb()
	p := GreenbonePreflight{OK: true}
	refuse := func(code, why string) {
		if p.OK {
			p.OK, p.Code, p.Reason = false, code, &why
		}
	}
	if m, err := g.memTotal(); err != nil {
		refuse("low_memory", "Vedette could not read how much memory this box has, so Greenbone cannot be enabled.")
	} else {
		p.MemoryBytes = &m
		if m < GreenboneMinMemory {
			refuse("low_memory", fmt.Sprintf("This box has %s of memory; Greenbone needs at least %s.", gbText(m), gbText(GreenboneMinMemory)))
		}
	}
	if d, err := g.diskFree(s.cfg.DataDir); err != nil {
		refuse("low_disk", "Vedette could not read how much disk space is free on this box, so Greenbone cannot be enabled.")
	} else {
		p.DiskFreeBytes = &d
		if d < GreenboneMinDisk {
			refuse("low_disk", fmt.Sprintf("This box has %s of free disk space; Greenbone needs at least %s free.", gbText(d), gbText(GreenboneMinDisk)))
		}
	}
	return p
}

// GreenboneSetting is GET /exposure/greenbone: the state of the setting and this box's measurement. Reading it may ask gvmd whether
// it is ready (at most every gbProbeEvery); it never starts a scan.
func (s *Service) GreenboneSetting(ctx context.Context) (GreenboneView, error) {
	v := GreenboneView{Preflight: s.preflight()}
	if s.cfg.Greenbone == nil {
		r := NotAvailableGreenbone
		v.State, v.Reason = GBUnavailable, &r
		return v, nil
	}
	on, by, at, err := loadGreenbone(ctx, s.cfg.DB.Reader())
	if err != nil {
		return GreenboneView{}, err
	}
	v.ChangedBy, v.ChangedAt = by, at
	if !on {
		v.State = GBOff
		return v, nil
	}
	state, reason := s.gbStatus(ctx, false)
	v.State = state
	if reason != "" {
		v.Reason = &reason
	}
	return v, nil
}

// SetGreenbone is PUT /exposure/greenbone (admin). Enabling runs the preflight (409 low_memory or low_disk with the measured numbers),
// records the switch with its audit row and starts Greenbone in the background (the page shows "starting", then "loading" while the
// feed loads). Disabling records the switch first, so no scan uses Greenbone any more, then stops the project and keeps its data
// (502 host_error when it could not be stopped). Setting the state it already has changes nothing.
func (s *Service) SetGreenbone(ctx context.Context, user string, enabled bool) (GreenboneView, error) {
	if s.cfg.Greenbone == nil {
		return GreenboneView{}, ErrGreenboneUnavailable
	}
	on, _, _, err := loadGreenbone(ctx, s.cfg.DB.Reader())
	if err != nil {
		return GreenboneView{}, err
	}
	if on == enabled {
		return s.GreenboneSetting(ctx)
	}
	if enabled {
		p := s.preflight()
		if !p.OK {
			return GreenboneView{}, apiErr(409, p.Code, "%s", *p.Reason)
		}
		detail := fmt.Sprintf("enabled (memory %s, free disk %s)", gbText(*p.MemoryBytes), gbText(*p.DiskFreeBytes))
		if err := s.saveGreenbone(ctx, user, true, detail); err != nil {
			return GreenboneView{}, err
		}
		s.gbStartUp(ctx)
		return s.GreenboneSetting(ctx)
	}
	if err := s.saveGreenbone(ctx, user, false, "disabled (data kept)"); err != nil {
		return GreenboneView{}, err
	}
	g := s.gb()
	g.mu.Lock()
	if g.upCancel != nil {
		g.upCancel()
	}
	g.upErr, g.upAt, g.probeAt = "", time.Time{}, time.Time{}
	g.mu.Unlock()
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gbDownTimeout)
	defer cancel()
	if err := s.cfg.Greenbone.Down(dctx); err != nil {
		s.cfg.Log.ErrorContext(ctx, "exposure: stopping Greenbone failed", "error", err)
		why := "the box log has the error"
		var un *Unavailable
		if errors.As(err, &un) {
			why = clipText(un.Reason, 200)
		}
		return GreenboneView{}, apiErr(502, "host_error", "Greenbone is off for scans, but its containers did not stop: %s.", strings.TrimSuffix(why, "."))
	}
	return s.GreenboneSetting(ctx)
}

func (s *Service) saveGreenbone(ctx context.Context, user string, on bool, detail string) error {
	return s.write(ctx, func(tx *sql.Tx, _ func(string, any)) error {
		v := 0
		if on {
			v = 1
		}
		if _, err := tx.ExecContext(ctx, `UPDATE exp_setting SET greenbone = ?, greenbone_by = ?, greenbone_at = ? WHERE id = 1`, v, user, store.FormatTS(s.clock())); err != nil {
			return fmt.Errorf("saving the Greenbone setting: %w", err)
		}
		return s.audit(ctx, tx, user, "exposure.greenbone", "Greenbone (OpenVAS)", detail)
	})
}

func loadGreenbone(ctx context.Context, q querier) (on bool, by, at *string, err error) {
	var v int
	var b, a sql.NullString
	if err := q.QueryRowContext(ctx, `SELECT greenbone, greenbone_by, greenbone_at FROM exp_setting WHERE id = 1`).Scan(&v, &b, &a); err != nil {
		return false, nil, nil, fmt.Errorf("the Greenbone setting: %w", err)
	}
	if b.Valid {
		by = &b.String
	}
	if a.Valid {
		at = &a.String
	}
	return v == 1, by, at, nil
}

// gbStartUp runs Up in the background on the Service's own context (not the request's): the first start pulls images for about
// 25 minutes. It does nothing while an Up runs.
func (s *Service) gbStartUp(ctx context.Context) {
	g := s.gb()
	g.mu.Lock()
	if g.upping {
		g.mu.Unlock()
		return
	}
	uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gbUpTimeout)
	g.upping, g.upCancel, g.upErr, g.probeAt = true, cancel, "", time.Time{}
	g.upWG.Add(1)
	g.mu.Unlock()
	go func() {
		defer g.upWG.Done()
		defer cancel()
		err := s.cfg.Greenbone.Up(uctx)
		g.mu.Lock()
		defer g.mu.Unlock()
		g.upping, g.upCancel = false, nil
		switch {
		case err == nil:
			g.upAt = s.clock()
		case errors.Is(err, context.Canceled): // disabled meanwhile
		default:
			s.cfg.Log.ErrorContext(uctx, "exposure: starting Greenbone failed", "error", err)
			g.upErr = "Greenbone could not be started. The box log has the error."
			var un *Unavailable
			if errors.As(err, &un) {
				g.upErr = "Greenbone could not be started: " + clipText(un.Reason, 200)
			}
		}
	}()
}

// gbStatus is the state of an enabled Greenbone: starting while Up runs (or right after it, until the socket answers), error when
// Up failed or gvmd does not answer or refuses the login, loading while the feed loads, ready. A box that restarted with Greenbone
// enabled runs Up again. gvmd is asked at most every gbProbeEvery.
func (s *Service) gbStatus(ctx context.Context, fresh bool) (string, string) {
	g := s.gb()
	g.mu.Lock()
	switch {
	case g.upping:
		g.mu.Unlock()
		return GBStarting, ""
	case g.upErr != "":
		defer g.mu.Unlock()
		return GBError, g.upErr
	case g.upAt.IsZero():
		g.mu.Unlock()
		s.gbStartUp(ctx)
		return GBStarting, ""
	case !fresh && !g.probeAt.IsZero() && s.clock().Sub(g.probeAt) < gbProbeEvery:
		defer g.mu.Unlock()
		return g.state, g.reason
	}
	upAt := g.upAt
	g.mu.Unlock()
	state, reason := s.gbProbe(ctx, upAt)
	g.mu.Lock()
	g.probeAt, g.state, g.reason = s.clock(), state, reason
	g.mu.Unlock()
	return state, reason
}

func (s *Service) gbProbe(ctx context.Context, upAt time.Time) (string, string) {
	dctx, cancel := context.WithTimeout(ctx, gbDialTimeout)
	defer cancel()
	conn, login, err := s.cfg.Greenbone.Dial(dctx)
	if err != nil {
		if s.clock().Sub(upAt) < GreenboneStartGrace {
			return GBStarting, ""
		}
		s.cfg.Log.ErrorContext(ctx, "exposure: Greenbone does not answer", "error", err)
		return GBError, gbNotAnswering
	}
	defer func() { _ = conn.Close() }()
	g := &gmpConn{conn: conn}
	if err := g.authenticate(dctx, login); err != nil {
		if errors.Is(err, errGMPAuth) {
			return GBError, gbAuthFailed
		}
		s.cfg.Log.ErrorContext(ctx, "exposure: Greenbone sign-in failed", "error", err)
		return GBError, gbUnreadable
	}
	loading, err := g.readiness(dctx)
	switch {
	case err != nil:
		s.cfg.Log.ErrorContext(ctx, "exposure: asking Greenbone whether it is ready failed", "error", err)
		return GBError, gbUnreadable
	case loading:
		return GBLoading, gbLoadingReason
	}
	return GBReady, ""
}

// greenboneScan is the deep-scan step of a scan (INV-25), after service identification, the templates and the passive web scan, and
// before the snapshot is stored. It runs only for an IP target that passed this run's gate, only when Greenbone is enabled and ready,
// after the gate is checked again and the probe log row is written. Like the other steps, only a stop of the run ends the scan here;
// everything else is a line of what was checked or not checked.
func (s *Service) greenboneScan(ctx context.Context, st ScanTarget, c Content) (Content, error) {
	line := func(text string) (Content, error) {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "greenbone", Text: clipText(text, maxLineText)})
		return c, nil
	}
	if st.Kind != KindIP {
		return line(notGBDomain)
	}
	if s.cfg.Greenbone == nil {
		return line(NotAvailableGreenbone)
	}
	on, _, _, err := loadGreenbone(ctx, s.cfg.DB.Reader())
	if err != nil {
		return c, err
	}
	if !on {
		return line(notGBOff)
	}
	switch state, reason := s.gbStatus(ctx, true); state { // asked again: a scan uses Greenbone only when it is ready now
	case GBReady:
	case GBLoading:
		return line(notGBLoading)
	case GBStarting:
		return line(notGBStarting)
	default:
		return line("Greenbone (OpenVAS) did not scan: " + reason)
	}
	ip, err := netip.ParseAddr(st.Value)
	if err != nil { // an IP target's value is a canonical public IPv4 (INV-2, INV-3): never reached
		return c, fmt.Errorf("exposure: Greenbone on %q: %w", st.Value, err)
	}
	// The gate of the run is many minutes old by now: the target must still be verified, committed, not paused and the box's own IP.
	if _, reason, gerr := s.gate(ctx, st.User, st.ID); gerr != nil || reason != "" {
		if ctx.Err() != nil {
			return c, ctx.Err()
		}
		if gerr != nil {
			s.cfg.Log.ErrorContext(ctx, "exposure: the gate before Greenbone failed", "target", st.Value, "error", gerr)
		}
		return line(notGBGate)
	}
	plog, _ := s.cfg.Probes.(GreenboneProbeLog)
	if plog == nil {
		return line(notGBNoLog)
	}
	g := s.gb()
	g.mu.Lock()
	poll, limit := g.poll, g.cap
	g.mu.Unlock()
	gctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	rows, total, err := s.runGreenbone(gctx, st, ip, plog, poll)
	var un *Unavailable
	switch {
	case err == nil:
	case ctx.Err() != nil: // the run was stopped: nothing is stored
		return c, err
	case errors.Is(err, errGBNoLog):
		return line(notGBNoLog)
	case gctx.Err() != nil:
		return line(notGBSlow)
	case errors.As(err, &un):
		return line("Greenbone (OpenVAS) did not scan: " + un.Reason)
	case errors.Is(err, ErrGMPBad):
		s.cfg.Log.ErrorContext(ctx, "exposure: unreadable Greenbone answer", "target", st.Value, "error", err)
		return line(notGBUnread)
	default:
		s.cfg.Log.ErrorContext(ctx, "exposure: Greenbone failed", "target", st.Value, "error", err)
		return line(notGBFail)
	}
	c.Greenbone = rows
	cves := map[string]bool{}
	for _, r := range rows {
		for _, id := range r.CVEs {
			cves[id] = true
		}
	}
	c.Checks = append(c.Checks, CheckRow{Kind: "greenbone", At: store.FormatTS(s.clock()), Text: clipText(fmt.Sprintf(
		"Greenbone (OpenVAS) scanned %s from outside without logging in (%s; port list %s): %s with QoD %d or more, %s named.",
		ip, gbConfigText, GreenbonePortList, plural(len(rows), "result"), GreenboneMinQoD, plural(len(cves), "CVE")), maxLineText)})
	if total > len(rows) && len(rows) >= maxGreenboneRows {
		c.NotChecked = append(c.NotChecked, NotCheckedRow{Kind: "greenbone", Text: fmt.Sprintf("Greenbone: only the %d highest-severity results are kept.", maxGreenboneRows)})
	}
	return c, nil
}

var errGBNoLog = errors.New("exposure: the Greenbone probe log row could not be written")

// runGreenbone is one scan over GMP: the safe config and the port list (made once, reused by name), a target of exactly ip, a task,
// the probe log row, start, a poll every `poll` until gvmd says Done, then the report (QoD >= GreenboneMinQoD). The task, its report
// and the target are deleted afterwards, and a scan cut short is stopped first.
func (s *Service) runGreenbone(ctx context.Context, st ScanTarget, ip netip.Addr, plog GreenboneProbeLog, poll time.Duration) ([]GreenboneRow, int, error) {
	dctx, cancel := context.WithTimeout(ctx, gbDialTimeout)
	conn, login, err := s.cfg.Greenbone.Dial(dctx)
	cancel()
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = conn.Close() }()
	g := &gmpConn{conn: conn}
	if err := g.authenticate(ctx, login); err != nil {
		return nil, 0, err
	}
	config, err := g.safeConfig(ctx)
	if err != nil {
		return nil, 0, err
	}
	ports, err := g.portList(ctx)
	if err != nil {
		return nil, 0, err
	}
	name := "vedette " + ip.String() + " " + store.NewID("gb")
	target, err := g.createTarget(ctx, name, ip.String(), ports)
	if err != nil {
		return nil, 0, err
	}
	task, running := "", false
	defer func() { s.gbCleanup(ctx, task, target, running) }()
	if task, err = g.createTask(ctx, name, target, config); err != nil {
		return nil, 0, err
	}
	if err := plog.RecordGreenboneProbe(ctx, GreenboneProbe{ID: store.NewID("pb"), IP: ip.String(), PortList: GreenbonePortList,
		Config: GreenboneConfigName + " (" + gbConfigText + ")", Note: gbNote}); err != nil { // LEGAL §3: logged before the task starts
		if ctx.Err() != nil {
			return nil, 0, ctx.Err()
		}
		s.cfg.Log.ErrorContext(ctx, "exposure: writing the Greenbone probe log failed", "target", st.Value, "error", err)
		return nil, 0, errGBNoLog
	}
	report, err := g.startTask(ctx, task)
	if err != nil {
		return nil, 0, err
	}
	running = true
	for {
		state, _, err := g.taskStatus(ctx, task)
		if err != nil {
			return nil, 0, err
		}
		switch state {
		case gmpDone:
			running = false
			return g.report(ctx, report, ip.String())
		case "Stopped", "Interrupted":
			running = false
			return nil, 0, &Unavailable{Reason: "Greenbone ended the scan as " + strings.ToLower(state) + "."}
		}
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-time.After(poll):
		}
	}
}

// gbCleanup stops (when it still runs) and deletes the scan's task, report and target over a new session on its own short context:
// the scan's session may be cut in the middle of an answer (a stop, the cap), and gvmd must not keep scanning.
func (s *Service) gbCleanup(ctx context.Context, task, target string, running bool) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	conn, login, err := s.cfg.Greenbone.Dial(ctx)
	if err != nil {
		s.cfg.Log.ErrorContext(ctx, "exposure: cleaning up after Greenbone failed", "task", task, "error", err)
		return
	}
	defer func() { _ = conn.Close() }()
	g := &gmpConn{conn: conn}
	if err := g.authenticate(ctx, login); err != nil {
		s.cfg.Log.ErrorContext(ctx, "exposure: cleaning up after Greenbone failed", "task", task, "error", err)
		return
	}
	g.cleanup(ctx, task, target, running)
}

// cleanGreenboneRow is the one check a Greenbone row passes before it is stored (INV-10, INV-25); ok is false for a row that is not one.
func cleanGreenboneRow(r GreenboneRow) (GreenboneRow, bool) {
	r.Name, r.Solution = plainText(r.Name, gmpMaxName), plainText(r.Solution, gmpMaxText)
	if !gmpPort.MatchString(r.Port) {
		r.Port = ""
	}
	if !gmpOID.MatchString(r.OID) || len(r.OID) > 64 {
		r.OID = ""
	}
	if a, err := netip.ParseAddr(r.IP); err != nil || a.String() != r.IP {
		r.IP = ""
	}
	cves := []string{}
	for _, id := range r.CVEs {
		if cveID.MatchString(id) && !slices.Contains(cves, id) && len(cves) < gmpMaxCVEs {
			cves = append(cves, id)
		}
	}
	r.CVEs = cves
	r.Severity = float64(int(r.Severity*10+0.5)) / 10
	if r.Name == "" || r.Severity <= 0 || r.Severity > 10 || r.QoD < GreenboneMinQoD || r.QoD > 100 {
		return GreenboneRow{}, false
	}
	return r, true
}

// sanitizeGreenbone keeps the rows that pass cleanGreenboneRow, the highest severity first, at most maxGreenboneRows.
func sanitizeGreenbone(in []GreenboneRow) []GreenboneRow {
	out := []GreenboneRow{}
	for _, r := range in {
		if r, ok := cleanGreenboneRow(r); ok {
			out = append(out, r)
		}
	}
	slices.SortStableFunc(out, func(a, b GreenboneRow) int {
		switch {
		case a.Severity > b.Severity:
			return -1
		case a.Severity < b.Severity:
			return 1
		}
		return 0
	})
	if len(out) > maxGreenboneRows {
		out = out[:maxGreenboneRows]
	}
	return out
}

// greenbonePort is the TCP or UDP port number of "443/tcp"; 0 for "general/tcp" and the like.
func greenbonePort(p string) int {
	n, err := strconv.Atoi(strings.SplitN(p, "/", 2)[0])
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return n
}

// withGreenboneVulns adds an exploited-CVE row of basis "greenbone" for each CVE Greenbone named that is on today's list (INV-25).
// They are added after every other row and never change one: a CVE matched by version and also named by Greenbone shows twice,
// once for each basis, and a version row is never closed or hidden because Greenbone did not name its CVE.
func (s *Service) withGreenboneVulns(ctx context.Context, snap *Snapshot) {
	var ids []string
	for _, r := range snap.Greenbone {
		for _, id := range r.CVEs {
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return
	}
	lk, _ := s.cfg.Matcher.(ExploitedLookup)
	if lk == nil {
		snap.NotChecked = append(snap.NotChecked, NotCheckedRow{Kind: "greenbone", Text: notGBNotCompared})
		return
	}
	kev, err := lk.Exploited(ctx, ids)
	var un *Unavailable
	switch {
	case errors.As(err, &un):
		snap.NotChecked = append(snap.NotChecked, NotCheckedRow{Kind: "greenbone", Text: "The CVEs Greenbone named were not compared with exploited vulnerabilities: " + clipText(un.Reason, 200)})
		return
	case err != nil:
		s.cfg.Log.ErrorContext(ctx, "exposure: comparing Greenbone's CVEs with exploited vulnerabilities failed", "snapshot", snap.ID, "error", err)
		snap.NotChecked = append(snap.NotChecked, NotCheckedRow{Kind: "greenbone", Text: notMatchFail})
		return
	}
	best := map[string]int{} // ip:port:cve -> index in snap.Vulns, the highest QoD kept
	for _, r := range snap.Greenbone {
		port := greenbonePort(r.Port)
		for _, id := range r.CVEs {
			e, ok := kev[id]
			if !ok {
				continue
			}
			row := VulnRow{IP: r.IP, Port: port, CVE: id, Name: clipText(e.Name, 200), Basis: "greenbone", QoD: r.QoD, DateAdded: e.DateAdded, Ransomware: e.Ransomware,
				Summary: clipText(fmt.Sprintf("Scanner: Greenbone, QoD %d. Its test %q names this CVE. Greenbone looked from outside without logging in.", r.QoD, r.Name), maxLineText)}
			k := fmt.Sprintf("%s:%d:%s", r.IP, port, id)
			if i, seen := best[k]; seen {
				if snap.Vulns[i].QoD < row.QoD {
					snap.Vulns[i] = row
				}
				continue
			}
			best[k] = len(snap.Vulns)
			snap.Vulns = append(snap.Vulns, row)
		}
	}
}
