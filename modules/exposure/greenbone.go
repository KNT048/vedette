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
// Vedette never touches the project or its volumes. SyncFeed updates Greenbone's feed (D-564 G6): it pulls the project's seven feed
// data images (notus-data, vulnerability-tests, scap-data, dfn-cert-data, cert-bund-data, report-formats, data-objects) and starts
// them again (`compose pull` then `up -d` of those services, Greenbone's own feed workflow); gvmd then loads the new data by itself.
// A step that cannot run for a reason the page may show returns *Unavailable.
type GreenboneHost interface {
	Up(ctx context.Context) error
	Down(ctx context.Context) error
	Dial(ctx context.Context) (net.Conn, GMPLogin, error)
	SyncFeed(ctx context.Context) error
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
	// GreenboneMinMemory is the least memory (MemTotal) the box needs before OpenVAS may be enabled: 6 GB decimal (D-569). The trial
	// on the 7 GB N100 next to Vedette peaked at about 4.0 GB used, with about 2 GB of swap during the first feed import and
	// 1.9 to 2.4 GB during the scan, so a 7 GB box with swap passes; below 8 GB the box must have GreenboneMinSwap and the page notes the swap use.
	GreenboneMinMemory = 6_000_000_000
	// GreenboneSwapBelow is the memory under which the box also needs GreenboneMinSwap of swap (SwapTotal): the trial's 7 GB box
	// used about 2 GB of swap for the first feed load, so a box under 8 GB without that much swap would run out of memory (D-569).
	GreenboneSwapBelow = 8_000_000_000
	GreenboneMinSwap   = 2_000_000_000
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
	gbProbeBudget    = 2 * time.Minute // the GMP commands of one readiness check, apart from the dial
	// GreenboneLoadGrace: a slow gvmd within this time after Up, or after it last said it was loading, reads as "loading".
	GreenboneLoadGrace = 4 * time.Hour
	gbUpTimeout        = 60 * time.Minute // the first Up pulls about 9 GB of images (25 minutes on the N100)
	gbDownTimeout      = 5 * time.Minute
	gbPollDefault      = 15 * time.Second
	// GreenboneSyncEvery is how often Greenbone's feed is updated while it is enabled (D-564 G6); a failed or refused update is tried
	// again after gbSyncRetry. The first one is due a week after Greenbone was enabled (enabling loads the feed).
	GreenboneSyncEvery = 7 * 24 * time.Hour
	gbSyncRetry        = 24 * time.Hour
	gbSyncTimeout      = 60 * time.Minute // pulling the seven feed images
	gbSyncStopWait     = 30 * time.Second // how long Turn off and Close wait for a cancelled feed update to end (review r1 L2)
	gbNote             = "OpenVAS sends many probes: every test of the config on every port of the list. They are not logged one by one."
	// GreenboneLowBelow: a result below this severity is Low (Greenbone's own classes: Low 0.1 to 3.9, Medium 4.0 to 6.9, High 7.0
	// to 10). Low results are hardening notes (D-564 G3): shown apart, never counted as alerts.
	GreenboneLowBelow = 4.0
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
	NotAvailableGreenbone = "OpenVAS is not available on this box."
	notGBOff              = "Optional deep scan with OpenVAS is off. An administrator can turn it on under Settings on the External exposure page."
	notGBDomain           = "OpenVAS runs on the box's own verified public IP only, never on the names of a domain."
	notGBStarting         = "OpenVAS did not scan: it is still starting."
	notGBLoading          = "OpenVAS did not scan: it is loading its feed (the first time takes about 2 hours)."
	notGBGate             = "OpenVAS did not scan: this IP can no longer be scanned (it was removed, paused, no longer verified or needs the scan confirmed again), so nothing was sent."
	notGBNoLog            = "OpenVAS did not scan: the probe log is not available, and nothing is sent without it."
	notGBSlow             = "OpenVAS did not finish within 90 minutes, so its results are not shown."
	notGBFail             = "OpenVAS failed, so its results are not shown. The box log has the error."
	notGBUnread           = "OpenVAS returned an answer that could not be read, so its results are not shown."
	notGBNotCompared      = "The CVEs OpenVAS named were not compared with the list of exploited vulnerabilities: that comparison is not set up on this box yet."
	gbLoadingReason       = "OpenVAS is loading its feed (first time takes about 2 hours)"
	gbNotAnswering        = "OpenVAS does not answer on its socket. Turn it off and on again to restart it."
	gbAuthFailed          = "Vedette could not sign in to OpenVAS (GMP). The login the box created for it was refused."
	gbUnreadable          = "OpenVAS answered in a way Vedette could not read."
	gbBusyReason          = "OpenVAS is busy loading its feed and answers slowly; Vedette will ask again."
	gbSlowReason          = "OpenVAS did not answer within 2 minutes."
	notGBSlowAnswer       = "OpenVAS did not answer within 2 minutes, so its results are not shown."
	notGBStopped          = "OpenVAS was stopped before it finished, so its results are not shown. The results of the other checks above are kept."
	// notGBTerms: Greenbone runs only on a target whose testing terms are accepted (D-566).
	notGBTerms      = "OpenVAS did not scan: accept the testing terms for this target to run OpenVAS (Ownership tab)."
	gbSyncingReason = "OpenVAS is loading its weekly feed update"
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
	FeedSync  GreenboneFeedSync  `json:"feed_sync"`
	// Enabled is the stored switch; the page offers Turn off whenever it is true (also when the state is unavailable, D-564 r1 M1).
	Enabled bool `json:"enabled"`
}

// GreenboneFeedSync is the weekly feed update as the setting shows it (D-564 G6): when it was last tried, whether it worked and what
// happened (nil before the first), and when the next one is due (nil while Greenbone is off).
type GreenboneFeedSync struct {
	LastAt *string `json:"last_at"`
	OK     *bool   `json:"ok"`
	Note   *string `json:"note"`
	NextAt *string `json:"next_at"`
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
	off      bool // turned off since the box started: no Up may start until it is turned on again (review r1 L3)
	syncing  bool // the weekly feed update runs (D-564 G6): the state is "loading"
	// syncCancel ends the feed update when Greenbone is turned off or the box stops.
	syncCancel context.CancelFunc
	syncDone   chan struct{} // closed when the running feed update has returned; nil when none runs
	loadAt     time.Time     // when gvmd last said it was loading its feed: a slow answer soon after is "loading", not an error
	probeAt    time.Time
	state      string
	reason     string
	// injectable for tests
	memInfo  func() (mem, swap int64, err error)
	diskFree func(dir string) (int64, error)
	poll     time.Duration
	cap      time.Duration
}

// gb returns the Greenbone state, made on first use.
func (s *Service) gb() *gbState {
	s.gbOnce.Do(func() {
		s.gbs = &gbState{memInfo: memInfo, diskFree: diskFree, poll: gbPollDefault, cap: GreenboneTimeout}
	})
	return s.gbs
}

// memInfo reads MemTotal and SwapTotal from /proc/meminfo, in bytes.
func memInfo() (mem, swap int64, err error) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, fmt.Errorf("reading /proc/meminfo: %w", err)
	}
	return parseMemInfo(string(b))
}

// parseMemInfo fails closed: no valid MemTotal is an error; a missing or bad SwapTotal counts as no swap.
func parseMemInfo(meminfo string) (mem, swap int64, err error) {
	for _, line := range strings.Split(meminfo, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[2] != "kB" || (f[0] != "MemTotal:" && f[0] != "SwapTotal:") {
			continue
		}
		kb, err := strconv.ParseInt(f[1], 10, 64)
		if err != nil || kb < 0 || kb > 1<<40 {
			kb = 0
		}
		if f[0] == "MemTotal:" {
			mem = kb * 1024
		} else {
			swap = kb * 1024
		}
	}
	if mem <= 0 {
		return 0, 0, errors.New("no MemTotal line in /proc/meminfo")
	}
	return mem, swap, nil
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

// gbText is a byte count as the page says it: decimal GB with one decimal, rounded down ("7.1 GB"), so a number just under a
// threshold never reads as the threshold itself.
func gbText(n int64) string {
	return strconv.FormatFloat(float64(n/100_000_000)/10, 'f', 1, 64) + " GB"
}

// preflight measures the box against the thresholds (INV-25). The reason names the measured number and the threshold.
func (s *Service) preflight() GreenbonePreflight {
	g := s.gb()
	p := GreenbonePreflight{OK: true}
	refuse := func(code, why string) {
		if p.OK {
			p.OK, p.Code, p.Reason = false, code, &why
		}
	}
	if m, swap, err := g.memInfo(); err != nil {
		refuse("low_memory", "Vedette could not read how much memory this box has, so OpenVAS cannot be enabled.")
	} else {
		p.MemoryBytes = &m
		if m < GreenboneMinMemory {
			refuse("low_memory", fmt.Sprintf("This box has %s of memory; OpenVAS needs at least %s.", gbText(m), gbText(GreenboneMinMemory)))
		} else if m < GreenboneSwapBelow && swap < GreenboneMinSwap {
			refuse("low_memory", fmt.Sprintf("This box has %s of memory and %s of swap; with less than %s of memory OpenVAS needs at least %s of swap for its first feed load.",
				gbText(m), gbText(swap), gbText(GreenboneSwapBelow), gbText(GreenboneMinSwap)))
		}
	}
	if d, err := g.diskFree(s.cfg.DataDir); err != nil {
		refuse("low_disk", "Vedette could not read how much disk space is free on this box, so OpenVAS cannot be enabled.")
	} else {
		p.DiskFreeBytes = &d
		if d < GreenboneMinDisk {
			refuse("low_disk", fmt.Sprintf("This box has %s of free disk space; OpenVAS needs at least %s free.", gbText(d), gbText(GreenboneMinDisk)))
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
	v.ChangedBy, v.ChangedAt, v.Enabled = by, at, on
	if v.FeedSync, err = loadGreenboneSync(ctx, s.cfg.DB.Reader()); err != nil {
		return GreenboneView{}, err
	}
	if !on {
		v.State = GBOff
		return v, nil
	}
	if at != nil {
		if n, ok := nextSync(*at, v.FeedSync); ok {
			if now := s.clock(); n.Before(now) { // due, waiting for a free scan slot or a ready Greenbone: never a date in the past
				n = now
			}
			next := store.FormatTS(n)
			v.FeedSync.NextAt = &next
		}
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
		g := s.gb()
		g.mu.Lock()
		g.off = false
		g.mu.Unlock()
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
	if g.syncCancel != nil { // a feed update that runs ends before the project stops
		g.syncCancel()
	}
	syncDone := g.syncDone
	g.off, g.upErr, g.upAt, g.probeAt = true, "", time.Time{}, time.Time{}
	g.mu.Unlock()
	s.waitSync(syncDone)
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), gbDownTimeout)
	defer cancel()
	if err := s.cfg.Greenbone.Down(dctx); err != nil {
		s.cfg.Log.ErrorContext(ctx, "exposure: stopping Greenbone failed", "error", err)
		why := "the box log has the error"
		var un *Unavailable
		if errors.As(err, &un) {
			why = clipText(un.Reason, 200)
		}
		return GreenboneView{}, apiErr(502, "host_error", "OpenVAS is off for scans, but its containers did not stop: %s.", strings.TrimSuffix(why, "."))
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
		return s.audit(ctx, tx, user, "exposure.greenbone", "OpenVAS", detail)
	})
}

// GreenboneEnabled says whether an administrator has Greenbone enabled (privacy flow 16, D-563); false when it cannot be read.
func (s *Service) GreenboneEnabled(ctx context.Context) bool {
	on, _, _, err := loadGreenbone(ctx, s.cfg.DB.Reader())
	return err == nil && on && s.cfg.Greenbone != nil
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

// GreenboneAtStart starts Greenbone again when an administrator has it enabled (review r1 L4): the box calls it at start-up and the
// module switch calls it when the module is turned on, so the first scan after a restart or an update does not find it "still
// starting". It does nothing when no GreenboneHost is wired, when it is off, or when the setting cannot be read (logged).
// FULL-2 (Trưởng), for Mlee: the hook the host half needed; it only calls gbStartUp.
func (s *Service) GreenboneAtStart(ctx context.Context) {
	if s.cfg.Greenbone == nil {
		return
	}
	on, _, _, err := loadGreenbone(ctx, s.cfg.DB.Reader())
	if err != nil {
		s.cfg.Log.ErrorContext(ctx, "exposure: reading the Greenbone setting at start failed", "error", err)
		return
	}
	if on {
		s.gbStartUp(ctx)
	}
}

// gbModuleOff stops Greenbone's containers when the External exposure module is switched off while Greenbone is enabled (D-529): no
// scan or feed update can use them then, and a 4 GB stack should not keep running for nothing. An Up or a feed update that runs is
// cancelled first; the stop runs in the background (the registry's goroutine must not wait). The setting stays enabled, so switching
// the module on again starts it (GreenboneAtStart).
// FULL-2 (Trưởng), for Mlee: the simplest truthful answer to the open line of feat-exposure-greenbone-mlee.md (module off).
func (s *Service) gbModuleOff(ctx context.Context) {
	if s.cfg.Greenbone == nil {
		return
	}
	on, _, _, err := loadGreenbone(ctx, s.cfg.DB.Reader())
	if err != nil || !on {
		return
	}
	g := s.gb()
	g.mu.Lock()
	if g.upCancel != nil {
		g.upCancel()
	}
	if g.syncCancel != nil {
		g.syncCancel()
	}
	syncDone := g.syncDone
	g.upErr, g.upAt, g.probeAt = "", time.Time{}, time.Time{}
	g.upWG.Add(1)
	g.mu.Unlock()
	go func() {
		defer g.upWG.Done()
		s.waitSync(syncDone)
		dctx, cancel := context.WithTimeout(ctx, gbDownTimeout)
		defer cancel()
		if err := s.cfg.Greenbone.Down(dctx); err != nil {
			s.cfg.Log.ErrorContext(dctx, "exposure: stopping Greenbone after the module was switched off failed", "error", err)
		}
	}()
}

// gbStartUp runs Up in the background on the Service's own context (not the request's): the first start pulls images for about
// 25 minutes. It does nothing while an Up runs.
func (s *Service) gbStartUp(ctx context.Context) {
	g := s.gb()
	g.mu.Lock()
	if g.upping || g.off { // off: a read or a scan that saw "on" just before an administrator turned it off must not start it again
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
			g.upErr = "OpenVAS could not be started. The box log has the error."
			var un *Unavailable
			if errors.As(err, &un) {
				g.upErr = "OpenVAS could not be started: " + clipText(un.Reason, 200)
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
	case g.syncing:
		g.mu.Unlock()
		return GBLoading, gbSyncingReason
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
	conn, login, err := s.cfg.Greenbone.Dial(dctx)
	cancel()
	if err != nil {
		if s.clock().Sub(upAt) < GreenboneStartGrace {
			return GBStarting, ""
		}
		s.cfg.Log.ErrorContext(ctx, "exposure: Greenbone does not answer", "error", err)
		return GBError, gbNotAnswering
	}
	defer func() { _ = conn.Close() }()
	g := &gmpConn{conn: conn}
	pctx, cancel := context.WithTimeout(ctx, gbProbeBudget) // GMP has its own budget, apart from the dial's (review r1 M3)
	defer cancel()
	err = g.authenticate(pctx, login)
	loading := false
	if err == nil {
		loading, err = g.readiness(pctx)
	}
	gs := s.gb()
	switch {
	case err == nil && loading:
		gs.mu.Lock()
		gs.loadAt = s.clock()
		gs.mu.Unlock()
		return GBLoading, gbLoadingReason
	case err == nil:
		return GBReady, ""
	case errors.Is(err, errGMPAuth):
		return GBError, gbAuthFailed
	case errors.Is(err, errGMPSlow) || errors.Is(err, context.DeadlineExceeded):
		// gvmd answers slowly while it loads its feed (D-494): within the first hours after Up, or soon after it last said it was
		// loading, that is the loading phase, not an error.
		gs.mu.Lock()
		loadAt := gs.loadAt
		gs.mu.Unlock()
		if s.clock().Sub(upAt) < GreenboneLoadGrace || (!loadAt.IsZero() && s.clock().Sub(loadAt) < GreenboneLoadGrace) {
			return GBLoading, gbBusyReason
		}
		return GBError, gbSlowReason
	}
	s.cfg.Log.ErrorContext(ctx, "exposure: asking Greenbone whether it is ready failed", "error", err)
	return GBError, gbUnreadable
}

// greenbonePlan decides, before the snapshot is stored, whether the Greenbone step runs in this scan (INV-25, D-566: only with the
// target's testing terms accepted): only for an IP target that passed this run's gate, only when Greenbone is wired, enabled and answers ready now (asked again, not from the cache). When it
// does not run, line says why, for "Not checked".
func (s *Service) greenbonePlan(ctx context.Context, st ScanTarget) (run bool, line string, err error) {
	if st.Kind != KindIP {
		return false, notGBDomain, nil
	}
	if s.cfg.Greenbone == nil {
		return false, NotAvailableGreenbone, nil
	}
	on, _, _, err := loadGreenbone(ctx, s.cfg.DB.Reader())
	if err != nil {
		return false, "", err
	}
	if !on {
		return false, notGBOff, nil
	}
	if !st.Mode.Full { // D-566: Greenbone's checks are covered by the testing terms only
		return false, notGBTerms, nil
	}
	switch state, reason := s.gbStatus(ctx, true); state {
	case GBReady:
		return true, "", nil
	case GBLoading:
		return false, notGBLoading, nil
	case GBStarting:
		return false, notGBStarting, nil
	default:
		return false, clipText("OpenVAS did not scan: "+reason, maxLineText), nil
	}
}

// gbPending is the "Not checked" line a snapshot carries while its Greenbone step runs (review r1 M5): the snapshot of the other
// steps is stored first, and this line is replaced when Greenbone ends. A restart of the box in between leaves it, and it says so.
func gbPending(at string) string {
	return "OpenVAS started at " + at + " and runs for up to 90 minutes; its results are added here when it finishes. If none appear, it was stopped before it finished (a stop or a restart of the box)."
}

// gbOutcome is what the Greenbone step adds to the stored snapshot.
type gbOutcome struct {
	rows   []GreenboneRow
	checks []CheckRow
	not    []NotCheckedRow
	audit  string // the detail of the exposure.greenbone_scan audit row
}

// greenboneStep is the deep scan itself (INV-25), after the snapshot of the other steps is stored: the gate again, the probe log row,
// then runGreenbone, at most the cap. Only a stop of the run returns an error; every other outcome is a line.
func (s *Service) greenboneStep(ctx context.Context, st ScanTarget) (gbOutcome, error) {
	line := func(text, audit string) (gbOutcome, error) {
		return gbOutcome{not: []NotCheckedRow{{Kind: "greenbone", Text: clipText(text, maxLineText)}}, audit: audit}, nil
	}
	ip, err := netip.ParseAddr(st.Value)
	if err != nil { // an IP target's value is a canonical public IPv4 (INV-2, INV-3): never reached
		return gbOutcome{}, fmt.Errorf("exposure: Greenbone on %q: %w", st.Value, err)
	}
	// The gate of the run is many minutes old by now: the target must still be verified, committed, not paused and the box's own IP.
	t, reason, gerr := s.gate(ctx, st.User, st.ID)
	if gerr != nil || reason != "" {
		if ctx.Err() != nil {
			return gbOutcome{}, ctx.Err()
		}
		if gerr != nil {
			s.cfg.Log.ErrorContext(ctx, "exposure: the gate before Greenbone failed", "target", st.Value, "error", gerr)
		}
		return line(notGBGate, "not done: the gate refused")
	}
	// The testing terms again (D-566): withdrawn meanwhile, nothing is sent; the tick taken back, the deep config, not the disruptive.
	if st.Mode = t.mode(); !st.Mode.Full {
		return line(notGBTerms, "not done: the testing terms are not accepted")
	}
	plog, _ := s.cfg.Probes.(GreenboneProbeLog)
	if plog == nil {
		return line(notGBNoLog, "not done: no probe log")
	}
	g := s.gb()
	g.mu.Lock()
	poll, limit := g.poll, g.cap
	g.mu.Unlock()
	gctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	rows, _, problems, err := s.runGreenbone(gctx, st, ip, plog, poll)
	var out gbOutcome
	if len(problems) > 0 {
		s.cfg.Log.ErrorContext(ctx, "exposure: Greenbone left something behind", "target", st.Value, "problems", problems)
		out.not = append(out.not, NotCheckedRow{Kind: "greenbone", Text: clipText("OpenVAS: "+strings.Join(problems, "; ")+". The next scan stops and removes Vedette's leftover tasks before it starts.", maxLineText)})
	}
	add := func(text, audit string) (gbOutcome, error) {
		out.not = append([]NotCheckedRow{{Kind: "greenbone", Text: clipText(text, maxLineText)}}, out.not...)
		out.audit = audit
		if len(problems) > 0 {
			out.audit += "; " + strings.Join(problems, "; ")
		}
		return out, nil
	}
	var un *Unavailable
	switch {
	case err == nil:
	case ctx.Err() != nil: // the run was stopped
		out.audit = "stopped"
		if len(problems) > 0 {
			out.audit += "; " + strings.Join(problems, "; ")
		}
		return out, err
	case errors.Is(err, errGBNoLog):
		return add(notGBNoLog, "not done: the probe log could not be written")
	case gctx.Err() != nil:
		return add(notGBSlow, "not done: did not finish within 90 minutes")
	case errors.As(err, &un):
		return add("OpenVAS did not scan: "+un.Reason, "not done: "+un.Reason)
	case errors.Is(err, errGMPSlow):
		return add(notGBSlowAnswer, "not done: no answer in time")
	case errors.Is(err, ErrGMPBad):
		s.cfg.Log.ErrorContext(ctx, "exposure: unreadable Greenbone answer", "target", st.Value, "error", err)
		return add(notGBUnread, "not done: unreadable answer")
	default:
		s.cfg.Log.ErrorContext(ctx, "exposure: Greenbone failed", "target", st.Value, "error", err)
		return add(notGBFail, "failed")
	}
	cves := map[string]bool{}
	for _, r := range rows {
		for _, id := range r.CVEs {
			cves[id] = true
		}
	}
	low := 0
	for _, r := range rows {
		if r.Severity < GreenboneLowBelow {
			low++
		}
	}
	out.rows = rows
	out.checks = []CheckRow{{Kind: "greenbone", At: store.FormatTS(s.clock()), Text: clipText(fmt.Sprintf(
		"OpenVAS scanned %s from outside without logging in (%s; port list %s): %s with QoD %d or more (%d high or medium, %s), %s named.",
		ip, levelOf(st.Mode).text, GreenbonePortList, plural(len(rows), "result"), GreenboneMinQoD, len(rows)-low, plural(low, "hardening note"), plural(len(cves), "CVE")), maxLineText)}}
	if len(rows) > maxGreenboneRows {
		out.not = append(out.not, NotCheckedRow{Kind: "greenbone", Text: fmt.Sprintf("OpenVAS: only the %d highest-severity of %d results are kept.", maxGreenboneRows, len(rows))})
	}
	out.audit = fmt.Sprintf("done: %s, %s", plural(len(rows), "result"), plural(len(cves), "CVE"))
	if len(problems) > 0 {
		out.audit += "; " + strings.Join(problems, "; ")
	}
	return out, nil
}

// addGreenbone writes the outcome of the Greenbone step into the snapshot stored before it (review r1 M5): the pending line is replaced
// by the outcome's lines, its rows and check are added, and one exposure.greenbone_scan audit row says how it ended, in the same
// transaction. It runs on its own context, so a stop or a shutdown still records it. A snapshot that is gone (the target was deleted
// meanwhile) is left alone.
func (s *Service) addGreenbone(ctx context.Context, user string, t Target, snap *Snapshot, pending string, o gbOutcome) {
	not := []NotCheckedRow{}
	for _, n := range snap.NotChecked {
		if n.Kind != "greenbone" || n.Text != pending {
			not = append(not, n)
		}
	}
	c := snap.Content
	c.NotChecked = append(not, o.not...)
	c.Checks = append(slices.Clone(snap.Checks), o.checks...)
	c.Greenbone = o.rows
	c = sanitize(c)
	snap.Content = c
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	err := s.write(wctx, func(tx *sql.Tx, _ func(string, any)) error {
		d, err := snapshotDocs(c, snap.Counts)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(wctx, `UPDATE exp_snapshot SET checks = ?, not_checked = ?, greenbone = ? WHERE id = ?`, d[6], d[7], d[9], snap.ID); err != nil {
			return fmt.Errorf("adding Greenbone's results: %w", err)
		}
		return s.audit(wctx, tx, user, "exposure.greenbone_scan", t.Value, clipText(o.audit, 500))
	})
	if err != nil {
		s.cfg.Log.ErrorContext(wctx, "exposure: storing Greenbone's results failed", "target", t.Value, "error", err)
	}
}

var errGBNoLog = errors.New("exposure: the Greenbone probe log row could not be written")

// runGreenbone is one scan over GMP: Vedette's leftover tasks and targets removed first, the config of the scan's level (D-566) and the
// port list, a target of exactly ip, a task, the probe log row, start, a poll every `poll` until gvmd says Done, then the report (QoD >= GreenboneMinQoD).
// The task, its report and the target are deleted afterwards (stopped first when cut short), and what could not be is returned in
// problems.
func (s *Service) runGreenbone(ctx context.Context, st ScanTarget, ip netip.Addr, plog GreenboneProbeLog, poll time.Duration) (rows []GreenboneRow, total int, problems []string, err error) {
	dctx, cancel := context.WithTimeout(ctx, gbDialTimeout)
	conn, login, err := s.cfg.Greenbone.Dial(dctx)
	cancel()
	if err != nil {
		return nil, 0, nil, err
	}
	defer func() { _ = conn.Close() }()
	g := &gmpConn{conn: conn}
	if err := g.authenticate(ctx, login); err != nil {
		return nil, 0, nil, err
	}
	if problems, err = g.leftovers(ctx, login.User); err != nil { // never a second task of Vedette's beside one still running
		return nil, 0, problems, err
	}
	lv := levelOf(st.Mode)
	config, err := g.levelConfig(ctx, login.User, lv)
	if err != nil {
		return nil, 0, problems, err
	}
	ports, err := g.portList(ctx)
	if err != nil {
		return nil, 0, problems, err
	}
	name := gbObjectPrefix + ip.String() + "-" + store.NewID("gb")
	target, err := g.createTarget(ctx, name, ip.String(), ports)
	if err != nil {
		return nil, 0, problems, err
	}
	task, running := "", false
	defer func() { problems = append(problems, s.gbCleanup(ctx, task, target, running)...) }()
	if task, err = g.createTask(ctx, name, target, config); err != nil {
		return nil, 0, problems, err
	}
	if err := plog.RecordGreenboneProbe(ctx, GreenboneProbe{ID: store.NewID("pb"), IP: ip.String(), PortList: GreenbonePortList,
		Config: lv.name + " (" + lv.text + ")", Note: gbNote}); err != nil { // LEGAL §3: logged before the task starts
		if ctx.Err() != nil {
			return nil, 0, problems, ctx.Err()
		}
		s.cfg.Log.ErrorContext(ctx, "exposure: writing the Greenbone probe log failed", "target", st.Value, "error", err)
		return nil, 0, problems, errGBNoLog
	}
	report, err := g.startTask(ctx, task)
	if err != nil {
		running = true // it may have started: stop it to be sure
		return nil, 0, problems, err
	}
	running = true
	for {
		state, _, err := g.taskStatus(ctx, task)
		if err != nil {
			return nil, 0, problems, err
		}
		switch state {
		case gmpDone:
			running = false
			rows, total, err := g.report(ctx, report, ip.String())
			return rows, total, problems, err
		case "Stopped", "Interrupted":
			running = false
			return nil, 0, problems, &Unavailable{Reason: "OpenVAS ended the scan as " + strings.ToLower(state) + "."}
		}
		select {
		case <-ctx.Done():
			return nil, 0, problems, ctx.Err()
		case <-time.After(poll):
		}
	}
}

// gbCleanup stops (when it still runs) and deletes the scan's task, report and target over a new session on its own short context:
// the scan's session may be cut in the middle of an answer (a stop, the cap), and gvmd must not keep scanning. Every failure is
// logged and returned (review r1 M4); a task that is left is removed by the next scan before it starts.
func (s *Service) gbCleanup(ctx context.Context, task, target string, running bool) []string {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	fail := func(err error) []string {
		s.cfg.Log.ErrorContext(ctx, "exposure: cleaning up after Greenbone failed", "task", task, "target", target, "error", err)
		return []string{"the task could not be cleaned up: " + clipText(err.Error(), 160)}
	}
	conn, login, err := s.cfg.Greenbone.Dial(ctx)
	if err != nil {
		return fail(err)
	}
	defer func() { _ = conn.Close() }()
	g := &gmpConn{conn: conn}
	if err := g.authenticate(ctx, login); err != nil {
		return fail(err)
	}
	failed := g.cleanup(ctx, task, target, running)
	for _, f := range failed {
		s.cfg.Log.ErrorContext(ctx, "exposure: cleaning up after Greenbone failed", "task", task, "target", target, "step", f)
	}
	return failed
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
		snap.NotChecked = append(snap.NotChecked, NotCheckedRow{Kind: "greenbone", Text: "The CVEs OpenVAS named were not compared with exploited vulnerabilities: " + clipText(un.Reason, 200)})
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
				Summary: clipText(fmt.Sprintf("Scanner: OpenVAS, QoD %d. Its test %q names this CVE. OpenVAS looked from outside without logging in.", r.QoD, r.Name), maxLineText)}
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

// ---- the weekly feed update (D-564 G6) ----

// loadGreenboneSync reads the last feed update from the setting; NextAt is left for the caller.
func loadGreenboneSync(ctx context.Context, q querier) (GreenboneFeedSync, error) {
	var at, note sql.NullString
	var ok sql.NullInt64
	if err := q.QueryRowContext(ctx, `SELECT greenbone_sync_at, greenbone_sync_ok, greenbone_sync_note FROM exp_setting WHERE id = 1`).Scan(&at, &ok, &note); err != nil {
		return GreenboneFeedSync{}, fmt.Errorf("the Greenbone feed update: %w", err)
	}
	var f GreenboneFeedSync
	if at.Valid {
		f.LastAt = &at.String
	}
	if ok.Valid {
		b := ok.Int64 == 1
		f.OK = &b
	}
	if note.Valid {
		f.Note = &note.String
	}
	return f, nil
}

// nextSync is when the next feed update is due: GreenboneSyncEvery after the last one that worked, gbSyncRetry after one that did
// not, and GreenboneSyncEvery after Greenbone was last turned on when no update ran since (turning it on loads the feed; review r1
// L1). ok is false when a stored time cannot be read. It may be in the past (due, not yet run); the page shows it as now.
func nextSync(enabledAt string, f GreenboneFeedSync) (time.Time, bool) {
	on, err := parseTS(enabledAt)
	if err != nil {
		return time.Time{}, false
	}
	if f.LastAt != nil {
		at, err := parseTS(*f.LastAt)
		if err != nil {
			return time.Time{}, false
		}
		if !at.Before(on) {
			if f.OK != nil && *f.OK {
				return at.Add(GreenboneSyncEvery), true
			}
			return at.Add(gbSyncRetry), true
		}
	}
	return on.Add(GreenboneSyncEvery), true
}

// RunGreenboneSync is the body of the weekly feed-update job (D-564 G6). While Greenbone is enabled and ready, once the update is
// due, it takes the box's one scan slot (it never runs during a scan, and no scan starts while it runs), refuses below the 60 GB free
// check and says why, and asks the host to pull and restart Greenbone's feed data images (SyncFeed); the setting reads "loading" while
// it runs, and gvmd's own loading of the new data reads "loading" after it. Each update tried writes its outcome on the setting and
// one exposure.greenbone_sync audit row. Not due, not ready, or a scan running: nothing happens and the next tick asks again.
func (s *Service) RunGreenboneSync(ctx context.Context) error {
	if s.cfg.Greenbone == nil {
		return nil
	}
	on, _, at, err := loadGreenbone(ctx, s.cfg.DB.Reader())
	if err != nil || !on || at == nil {
		return err
	}
	f, err := loadGreenboneSync(ctx, s.cfg.DB.Reader())
	if err != nil {
		return err
	}
	if next, ok := nextSync(*at, f); ok && s.clock().Before(next) {
		return nil
	}
	if state, _ := s.gbStatus(ctx, true); state != GBReady { // starting, loading its feed or in error: the next tick asks again
		return nil
	}
	s.runMu.Lock()
	if s.off || s.closed || s.feedSync || (s.run != nil && s.run.view.Status == RunRunning) {
		s.runMu.Unlock()
		return nil
	}
	s.feedSync, s.feedSyncAt = true, s.clock()
	s.runMu.Unlock()
	defer func() {
		s.runMu.Lock()
		s.feedSync = false
		s.runMu.Unlock()
	}()
	g := s.gb()
	free, derr := g.diskFree(s.cfg.DataDir)
	switch {
	case derr != nil:
		return s.recordSync(ctx, false, "Not updated: Vedette could not read how much disk space is free on this box.")
	case free < GreenboneMinDisk:
		return s.recordSync(ctx, false, fmt.Sprintf("Not updated: this box has %s of free disk space; OpenVAS needs at least %s free.", gbText(free), gbText(GreenboneMinDisk)))
	}
	g.mu.Lock()
	if g.off { // turned off since it was read
		g.mu.Unlock()
		return nil
	}
	sctx, cancel := context.WithTimeout(ctx, gbSyncTimeout)
	done := make(chan struct{})
	g.syncing, g.syncCancel, g.syncDone = true, cancel, done
	g.mu.Unlock()
	err = s.cfg.Greenbone.SyncFeed(sctx)
	cancel()
	close(done)
	g.mu.Lock()
	g.syncing, g.syncCancel, g.syncDone = false, nil, nil
	g.loadAt, g.probeAt = s.clock(), time.Time{} // gvmd now loads the new data: a slow answer is "loading", and the page asks again
	off := g.off
	g.mu.Unlock()
	var un *Unavailable
	switch {
	case err == nil:
		return s.recordSync(ctx, true, "Updated: the OpenVAS feed images were pulled, and OpenVAS now loads the new tests.")
	case off || ctx.Err() != nil:
		return s.recordSync(ctx, false, "Not updated: it was stopped (OpenVAS was turned off, or the box or the module stopped).")
	case sctx.Err() != nil:
		return s.recordSync(ctx, false, "Not updated: it did not finish within 60 minutes.")
	case errors.As(err, &un):
		return s.recordSync(ctx, false, "Not updated: "+clipText(un.Reason, 200))
	}
	s.cfg.Log.ErrorContext(ctx, "exposure: updating Greenbone's feed failed", "error", err)
	return s.recordSync(ctx, false, "Not updated: the update failed. The box log has the error.")
}

// recordSync writes the outcome of one feed update on the setting with its audit row, in one transaction, on its own context (a stop
// still records it).
func (s *Service) recordSync(ctx context.Context, ok bool, note string) error {
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), saveTimeout)
	defer cancel()
	return s.write(wctx, func(tx *sql.Tx, _ func(string, any)) error {
		v := 0
		if ok {
			v = 1
		}
		if _, err := tx.ExecContext(wctx, `UPDATE exp_setting SET greenbone_sync_at = ?, greenbone_sync_ok = ?, greenbone_sync_note = ? WHERE id = 1`, store.FormatTS(s.clock()), v, note); err != nil {
			return fmt.Errorf("saving the Greenbone feed update: %w", err)
		}
		return s.audit(wctx, tx, SystemUser, "exposure.greenbone_sync", "OpenVAS", note)
	})
}

// errScanFeedSync is the 409 busy of a scan asked while the feed update holds the slot (review r1 L4): the real bound, and when it
// started.
func (s *Service) errScanFeedSync(started time.Time) *APIError {
	return apiErr(409, "busy", "OpenVAS is loading its weekly feed update (started %s), which holds the box's scanner while it runs, at most %d minutes. Try the scan again after it.",
		s.momentText(started), int(gbSyncTimeout/time.Minute))
}

// waitSync waits, at most gbSyncStopWait, for a feed update that was just cancelled to end (review r1 L2): the host must not pull or
// start the feed images after Greenbone is stopped.
func (s *Service) waitSync(done <-chan struct{}) {
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(gbSyncStopWait):
		s.cfg.Log.Error("exposure: Greenbone's feed update did not end within 30 seconds of being cancelled")
	}
}
