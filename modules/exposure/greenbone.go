package exposure

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	vprogress "github.com/knt048/vedette/core/progress"
	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/scan/commonports"
)

// Optional deep scan with Greenbone Community Edition (OpenVAS), off by default (S-EXP-2, CONTRACT INV-25).
// Greenbone runs as its own unmodified compose project next to Vedette (separate processes; its
// GPL/AGPL code is not embedded); the host starts and stops it and hands over a connection to the gvmd socket (GreenboneHost).
// Exposure decides when it may scan (a verified, committed, not-paused IP target, after the other steps of the same run), talks GMP
// (gmp.go), reads its report as untrusted data and shows the results apart: Greenbone looks from outside without logging in, so
// finding nothing is never "not affected", and its rows never replace, close or hide a version, product or template row.

// GreenboneHost is the host side (vedette-host): Greenbone's official compose project pinned by image digest, under its
// own podman project name, with the gvmd socket mounted into core and the GMP password generated on install and kept in
// core/secrets. Up starts the project (the first time it pulls several GB of images); Down stops it and keeps its volumes (the
// feed and gvmd's database); Dial opens the gvmd unix socket and returns the GMP login the host created. Uninstalling Vedette never
// touches the project or its volumes. SyncFeed updates Greenbone's feed: it pulls the four feed data images Vedette runs
// (notus-data, vulnerability-tests, report-formats, data-objects) and starts them again (`compose pull` then `up -d` of those
// services, Greenbone's own feed workflow); gvmd then loads the new data by itself. The SCAP and CERT data are off: the scan
// reads CVE ids from the vulnerability tests' own references, readiness never waits for those feeds, and the client never sends the
// commands that need them (get_info, get_resource_names; TestContract_INV25_NeedsNoSCAPOrCERTData).
// A step that cannot run for a reason the page may show returns *Unavailable.
type GreenboneHost interface {
	Up(ctx context.Context) error
	Down(ctx context.Context) error
	Dial(ctx context.Context) (net.Conn, GMPLogin, error)
	SyncFeed(ctx context.Context) error
}

// HostBusy is the error of a GreenboneHost call the host refused for now (rate limited, busy with another run, restarting): the
// call may be sent again later. RetryAfter is the host's hint (0: none). gbStartUp retries an Up refused so with backoff until it
// runs or OpenVAS is turned off (kf-scan item 6: at a box restart greenbone.up got 429 rate_limited and OpenVAS stayed failed).
type HostBusy struct {
	Reason     string
	RetryAfter time.Duration
}

func (e *HostBusy) Error() string { return "exposure: the host refused for now: " + e.Reason }

// GreenboneProbe is the probe log row written before Greenbone's task starts (LEGAL §3): the target address, the domain fence note of
// a domain's address (first: the row is clipped at its end), the port list (clipped, with the
// count), the scan config and a note that Greenbone sends many probes (they cannot be logged one by one: the scanner is Greenbone's).
type GreenboneProbe struct {
	ID       string
	IP       string
	Fence    string // "" for the box's own IP
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
	// GreenboneMinMemory is the least memory (MemTotal) the box needs before OpenVAS may be enabled: 6 GB decimal. The trial
	// on a 7 GB test box next to Vedette peaked at about 4.0 GB used, with about 2 GB of swap during the first feed import and
	// 1.9 to 2.4 GB during the scan, so a 7 GB box with swap passes; below 8 GB the box must have GreenboneMinSwap and the page notes the swap use.
	GreenboneMinMemory = 6_000_000_000
	// GreenboneSwapBelow is the memory under which the box also needs GreenboneMinSwap of swap (SwapTotal): the trial's 7 GB box
	// used about 2 GB of swap for the first feed load, so a box under 8 GB without that much swap would run out of memory.
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
	gbUpTimeout        = 60 * time.Minute // the first Up pulls about 9 GB of images (25 minutes on a test box)
	// gbUpRetryFirst and gbUpRetryLongest bound the wait before an Up the host refused for now (HostBusy) is sent again: doubling from the
	// first to the second, never shorter than the host's own Retry-After and never longer than the second. The host's limit is per minute, so the first retry
	// usually runs.
	gbUpRetryFirst   = 15 * time.Second
	gbUpRetryLongest = 5 * time.Minute
	gbDownTimeout    = 5 * time.Minute
	gbPollDefault    = 15 * time.Second
	// GreenboneSyncEvery is how often Greenbone's feed is updated while it is enabled; a failed or refused update is tried
	// again after gbSyncRetry. The first one is due a week after Greenbone was enabled (enabling loads the feed).
	GreenboneSyncEvery = 7 * 24 * time.Hour
	gbSyncRetry        = 24 * time.Hour
	gbSyncTimeout      = 60 * time.Minute // pulling the four feed images
	gbSyncStopWait     = 30 * time.Second // how long Turn off and Close wait for a cancelled feed update to end
	gbNote             = "OpenVAS sends many probes: every test of the config on every port of the list. They are not logged one by one."
	// gbStopBudget bounds what follows the cap: stop the task, wait for gvmd to say it stopped, read what it found by then.
	gbStopBudget = 5 * time.Minute
	// GreenboneLowBelow: a result below this severity is Low (Greenbone's own classes: Low 0.1 to 3.9, Medium 4.0 to 6.9, High 7.0
	// to 10). Low results are hardening notes: shown apart, never counted as alerts.
	GreenboneLowBelow = 4.0
)

// The states of the Greenbone setting (contract.ts GreenboneState).
const (
	GBUnavailable = "unavailable" // no GreenboneHost on this box
	GBOff         = "off"
	GBStarting    = "starting"
	GBLoading     = "loading" // the feed loads (the first time 1 to 3 hours): a phase, not a hang
	GBReady       = "ready"
	GBError       = "error"
)

// The sentences of the deep scan. NotAvailableGreenbone is the page's and the scan's line when no GreenboneHost is wired.
const (
	NotAvailableGreenbone = "OpenVAS is not available on this box."
	notGBOff              = "Optional deep scan with OpenVAS is off. An administrator can turn it on under Settings on the External exposure page."
	notGBProof            = "OpenVAS did not scan: the proof of this IP (its token file or reverse DNS name) was not found just now."
	notGBDomain           = "OpenVAS runs on the box's own verified public IP only, never on the names of a domain."
	// notGBNoDeep: a domain with accepted terms whose deep scan reached no address this run.
	notGBNoDeep   = "OpenVAS did not scan: no address of this domain's names got the deep scan this run."
	notGBStarting = "OpenVAS did not scan: it is still starting."
	notGBLoading  = "OpenVAS did not scan: it is loading its feed (the first time takes 1 to 3 hours)."
	notGBGate     = "OpenVAS did not scan: this IP can no longer be scanned (it was removed, paused, no longer verified or needs the scan confirmed again), so nothing was sent."
	// notGBNotOwn: the address is not the box's own proven IP (no sighting inside its days, or a typed IP without its scope), so
	// OpenVAS, which has no fence of its own on the host, gets nothing (INV-13).
	notGBNotOwn = "OpenVAS did not scan: this IP is not the box's own proven address (the box has not seen it as its address within the last 90 days, or it is a typed IP without its proof), so nothing was sent."
	notGBNoLog  = "OpenVAS did not scan: the probe log is not available, and nothing is sent without it."
	notGBSlow   = "OpenVAS did not finish within 90 minutes, and what it had found by then could not be read, so its results are not shown."
	// notGBPartial and notGBPartialNone: the cap stopped the task and its report was read: the rows found by then are shown.
	notGBPartial     = "OpenVAS was stopped after 90 minutes; these are the results it had found by then."
	notGBPartialNone = "OpenVAS was stopped after 90 minutes; by then it had found no result with QoD 70 or more. Finding nothing is not proof the services are not affected."
	// notGBQueued: the cap passed and the task never left Requested/Queued: nothing was scanned.
	notGBQueued = "OpenVAS did not start scanning within 90 minutes (the task stayed queued in OpenVAS), so nothing was checked."
	// notGBEnded starts the line of a scan that ended before it finished without Vedette's stop; the reason
	// follows. notGBEndedEarly starts the line of a task OpenVAS ended before it was ever seen scanning: nothing was
	// checked. notGBEndedUnread follows the reason when the ended task's report could not be read.
	notGBEnded       = "OpenVAS ended the scan before it finished: "
	notGBEndedEarly  = "OpenVAS did not scan: it ended the task before it started scanning (for example, its scanner was not connected). "
	notGBEndedUnread = " What it had found could not be read."
	// notGBNoPorts and notGBTooManyPorts: OpenVAS checks only the ports this run found open.
	notGBNoPorts      = "OpenVAS did not scan: this scan found no open port to check."
	notGBTooManyPorts = "OpenVAS did not scan: more than 40 ports answered, more than a normal box exposes (a router or firewall that answers for every port looks like this), so OpenVAS was not sent over them."
	notGBFail         = "OpenVAS failed, so its results are not shown. The box log has the error."
	notGBUnread       = "OpenVAS returned an answer that could not be read, so its results are not shown."
	notGBNotCompared  = "The CVEs OpenVAS named were not compared with the list of exploited vulnerabilities: that comparison is not set up on this box yet."
	gbLoadingReason   = "OpenVAS is loading its feed (first time takes 1 to 3 hours)"
	gbNotAnswering    = "OpenVAS does not answer on its socket. Turn it off and on again to restart it."
	gbAuthFailed      = "Vedette could not sign in to OpenVAS (GMP): it refused the login the box set for it. If OpenVAS has finished loading its feed, turn it off and on again so the box sets the login again."
	gbUnreadable      = "OpenVAS answered in a way Vedette could not read."
	gbBusyReason      = "OpenVAS is busy loading its feed and answers slowly; Vedette will ask again."
	gbSlowReason      = "OpenVAS did not answer within 2 minutes."
	notGBSlowAnswer   = "OpenVAS did not answer within 2 minutes, so its results are not shown."
	notGBStopped      = "OpenVAS was stopped before it finished, so its results are not shown. The results of the other checks above are kept."
	notGBStoppedSome  = "OpenVAS was stopped before it had scanned every address; the results of the addresses it finished are shown. The results of the other checks above are kept."
	// notGBTerms: Greenbone runs only on a target whose testing terms are accepted.
	notGBTerms      = "OpenVAS did not scan: accept the testing terms for this target to run OpenVAS (Ownership tab)."
	gbSyncingReason = "OpenVAS is loading its weekly feed update"
)

// gbLoginPending: a refused login within the load grace after Up. A volume of an earlier start keeps its admin password until gvmd
// has loaded its feed and the host sets Vedette's (host-api §6.16); the sentence claims neither cause.
const gbLoginPending = "OpenVAS may still be loading its feed or setting Vedette's login; Vedette will ask again."

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
	// Feed is the feed OpenVAS itself reports it has loaded (gvmd's get_feeds, T10): nil while it is off or unavailable, and until
	// Vedette has read it since the box started.
	Feed *GreenboneFeed `json:"feed"`
	// Enabled is the stored switch; the page offers Turn off whenever it is true (also when the state is unavailable).
	Enabled bool `json:"enabled"`
}

// GreenboneFeedSync is the weekly feed update as the setting shows it: when it was last tried, whether it worked and what
// happened (nil before the first), and when the next one is due (nil while Greenbone is off).
type GreenboneFeedSync struct {
	LastAt *string `json:"last_at"`
	OK     *bool   `json:"ok"`
	Note   *string `json:"note"`
	NextAt *string `json:"next_at"`
}

// GreenboneFeed is the vulnerability tests (NVT feed) gvmd reports: the feed's version and the UTC time it encodes (nil when gvmd
// gave none or one Vedette cannot read), and when Vedette last read it. It is there from the first feed load at Enable on, so a
// working OpenVAS before its first weekly update shows the date of the tests it has (T10).
type GreenboneFeed struct {
	NVTVersion *string `json:"nvt_version"`
	NVTDate    *string `json:"nvt_date"`
	CheckedAt  string  `json:"checked_at"`
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
	off      bool // turned off since the box started: no Up may start until it is turned on again
	syncing  bool // the weekly feed update runs: the state is "loading"
	// syncCancel ends the feed update when Greenbone is turned off or the box stops.
	syncCancel context.CancelFunc
	syncDone   chan struct{}  // closed when the running feed update has returned; nil when none runs
	loadAt     time.Time      // when gvmd last said it was loading its feed: a slow answer soon after is "loading", not an error
	feed       *GreenboneFeed // what gvmd's get_feeds last said of its NVT feed; nil before the first read since the box started
	probeAt    time.Time
	state      string
	reason     string
	// injectable for tests
	memInfo  func() (mem, swap int64, err error)
	diskFree func(dir string) (int64, error)
	poll     time.Duration
	cap      time.Duration
	upRetry  time.Duration // > 0: the fixed wait between Ups the host refused for now (tests)
}

// gb returns the Greenbone state, made on first use.
func (s *Service) gb() *gbState {
	s.gbOnce.Do(func() {
		s.gbs = &gbState{memInfo: memInfo, diskFree: store.DiskFree, poll: gbPollDefault, cap: GreenboneTimeout}
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
	g := s.gb()
	g.mu.Lock()
	if g.feed != nil {
		f := *g.feed
		v.Feed = &f
	}
	g.mu.Unlock()
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

// GreenboneEnabled says whether an administrator has Greenbone enabled (privacy flow 16); false when it cannot be read.
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

// GreenboneAtStart starts Greenbone again when an administrator has it enabled: the box calls it at start-up and the
// module switch calls it when the module is turned on, so the first scan after a restart or an update does not find it "still
// starting". It does nothing when no GreenboneHost is wired, when it is off, or when the setting cannot be read (logged).
// The start-up hook of the host side; it only calls gbStartUp.
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

// gbModuleOff stops Greenbone's containers when the External exposure module is switched off while Greenbone is enabled: no
// scan or feed update can use them then, and a 4 GB stack should not keep running for nothing. An Up or a feed update that runs is
// cancelled first; the stop runs in the background (the registry's goroutine must not wait). The setting stays enabled, so switching
// the module on again starts it (GreenboneAtStart).
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
	uctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	g.upping, g.upCancel, g.upErr, g.probeAt = true, cancel, "", time.Time{}
	fixed := g.upRetry
	g.upWG.Add(1)
	g.mu.Unlock()
	go func() {
		defer g.upWG.Done()
		defer cancel()
		err := s.upUntilTaken(uctx, fixed)
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

// upUntilTaken sends Up, each attempt bounded by gbUpTimeout, and sends it again after a wait while the host refuses it for now
// (HostBusy: 429 rate_limited, busy, restarting), until it runs, fails otherwise, or ctx ends (turned off, module off, box stopping).
// The page says "starting" meanwhile (upping stays set).
func (s *Service) upUntilTaken(ctx context.Context, fixed time.Duration) error {
	wait := gbUpRetryFirst
	for {
		actx, cancel := context.WithTimeout(ctx, gbUpTimeout)
		err := s.cfg.Greenbone.Up(actx)
		cancel()
		var busy *HostBusy
		if !errors.As(err, &busy) || ctx.Err() != nil {
			return err
		}
		d := upWait(wait, busy.RetryAfter)
		if fixed > 0 {
			d = fixed
		}
		s.cfg.Log.WarnContext(ctx, "exposure: the host refused to start Greenbone for now; trying again", "reason", busy.Reason, "after", d.String())
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return context.Canceled
		case <-t.C:
		}
		wait = min(wait*2, gbUpRetryLongest)
	}
}

// upWait is the wait before the next Up: the backoff, or the host's Retry-After when longer, never past gbUpRetryLongest (review
// r1 L8: a host answering a long Retry-After must not leave OpenVAS "starting" for that long).
func upWait(backoff, hint time.Duration) time.Duration {
	return min(max(backoff, hint), gbUpRetryLongest)
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
	pctx, cancel := context.WithTimeout(ctx, gbProbeBudget) // GMP has its own budget, apart from the dial's
	defer cancel()
	err = g.authenticate(pctx, login)
	loading := false
	var feeds gmpFeeds
	if err == nil {
		loading, feeds, err = g.readiness(pctx)
	}
	gs := s.gb()
	if len(feeds.Feeds) > 0 { // get_feeds answered: what it said of the vulnerability tests is the setting's feed line
		f := &GreenboneFeed{CheckedAt: store.FormatTS(s.clock())}
		if v, at := feeds.nvtFeed(); v != nil {
			f.NVTVersion = v
			if at != nil {
				d := store.FormatTS(*at)
				f.NVTDate = &d
			}
		}
		gs.mu.Lock()
		gs.feed = f
		gs.mu.Unlock()
	}
	switch {
	case err == nil && loading:
		gs.mu.Lock()
		gs.loadAt = s.clock()
		gs.mu.Unlock()
		return GBLoading, gbLoadingReason
	case err == nil:
		return GBReady, ""
	case errors.Is(err, errGMPAuth):
		// gvmd has Vedette's login from the creation of its user, but a volume from an earlier start keeps its own
		// password until gvmd has loaded its feed and the host sets it again; within the load grace after Up that is the loading
		// phase, not a dead end.
		if s.clock().Sub(upAt) < GreenboneLoadGrace {
			return GBLoading, gbLoginPending
		}
		return GBError, gbAuthFailed
	case errors.Is(err, errGMPSlow) || errors.Is(err, context.DeadlineExceeded):
		// gvmd answers slowly while it loads its feed: within the first hours after Up, or soon after it last said it was
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

// greenbonePlan decides, before the snapshot is stored, whether the Greenbone step runs in this scan (INV-25: only with the
// target's testing terms accepted): only for an IP target that passed this run's gate, only when Greenbone is wired, enabled and answers ready now (asked again, not from the cache). When it
// does not run, line says why, for "Not checked".
func (s *Service) greenbonePlan(ctx context.Context, st ScanTarget) (run bool, line string, err error) {
	if st.Kind != KindIP && !st.Mode.Full { // A domain with accepted terms gets it on the addresses its deep scan reached
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
	if !st.Mode.Full { // Greenbone's checks are covered by the testing terms only
		return false, notGBTerms, nil
	}
	if st.Kind == KindIP && st.Typed { // a typed IP: the proof is looked for again (the cached live result of this scan) before OpenVAS starts
		t, err := loadTarget(ctx, s.cfg.DB.Reader(), st.ID)
		if err != nil {
			return false, "", err
		}
		if t, err = s.liveTypedProof(ctx, st.User, t); err != nil {
			return false, "", err
		}
		if t.LastCheck == nil || !t.LastCheck.OK || t.validity(s.clock()) == validityExpired {
			return false, notGBProof, nil
		}
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

// gbPending is the "Not checked" line a snapshot carries while its Greenbone step runs: the snapshot of the other
// steps is stored first, and this line is replaced when Greenbone ends. A restart of the box in between leaves it, and it says so.
// It names no time: the page shows GreenboneRun.StartedAt in the viewer's time zone, like every other time on it.
const gbPending = "OpenVAS is scanning and runs for up to 90 minutes; its results are added here when it finishes. If none appear, it was stopped before it finished (a stop or a restart of the box)."

// The states of a snapshot's OpenVAS step (GreenboneRun.State, contract.ts GreenboneRun): the one source the page reads
// its OpenVAS heading from.
const (
	GBRunRunning = "running" // the snapshot of the other steps is stored and OpenVAS scans now
	GBRunDone    = "done"    // it finished; its rows (maybe none) are the snapshot's
	GBRunPartial = "partial" // the cap stopped it; its rows are what it had found by then
	GBRunNotRun  = "not_run" // it did not scan (off, loading, no open port, terms, gate…); a "Not checked" line says why
	GBRunFailed  = "failed"  // it ran or tried to and failed (an error, an answer that could not be read, the cap without a report)
	GBRunStopped = "stopped" // a Stop, the module or the box ended it before it finished (also a restart: running with no run behind it)
	GBRunEnded   = "ended"   // it scanned and ended before it finished without Vedette's stop: OpenVAS reports it stopped or interrupted, or the domain fence did
)

// GreenboneRun is the state of a snapshot's OpenVAS step and when it started (RFC 3339 UTC, nil when it did not), stored with the
// snapshot (exp_snapshot.greenbone_run, migration 0011). Addresses is the state of each address of a domain's run:
// [] for an IP.
type GreenboneRun struct {
	State     string          `json:"state"`
	StartedAt *string         `json:"started_at"`
	Addresses []GreenboneAddr `json:"addresses"`
	// EndedAt is when the step ended, in any final state (RFC 3339 UTC); nil while it runs, when it did not run, and on a step
	// stored before it was kept. For a restart that cut it, it is when the box started again (the moment it was seen).
	EndedAt *string `json:"ended_at,omitempty"`
	// Stop says why a stopped step was stopped; nil in any other state, and on a step stored before it was kept.
	Stop *GreenboneStop `json:"stop,omitempty"`
	// Again: the step ran on its own, after the scan, on the open ports that scan found (POST …/openvas).
	Again bool `json:"again,omitempty"`
}

// Why an OpenVAS step (or a run) was stopped (GreenboneStop.Reason, contract.ts GreenboneStop).
const (
	StopPerson   = "person"     // someone pressed Stop (By names them)
	StopShutdown = "shutdown"   // Vedette shut down while it ran (an update, a restart or a stop of the service)
	StopRestart  = "restart"    // Vedette started again and found it still "running": it stopped before the step could store how it ended
	StopModule   = "module_off" // the External exposure module was switched off
	StopTerms    = "terms"      // the testing terms of the target were withdrawn or lowered (By names who)
)

var stopReasons = []string{StopPerson, StopShutdown, StopRestart, StopModule, StopTerms}

// GreenboneStop is why and by whom a stopped OpenVAS step was stopped.
type GreenboneStop struct {
	Reason string  `json:"reason"`
	By     *string `json:"by"`
}

// GreenboneAddr is the OpenVAS state of one address of a domain's run.
type GreenboneAddr struct {
	IP    string `json:"ip"`
	State string `json:"state"`
}

// MarshalJSON writes Addresses as [] when there is none (the API and the column never hold null).
func (r GreenboneRun) MarshalJSON() ([]byte, error) {
	type plain GreenboneRun
	if r.Addresses == nil {
		r.Addresses = []GreenboneAddr{}
	}
	return json.Marshal(plain(r))
}

var gbRunStates = []string{GBRunRunning, GBRunDone, GBRunPartial, GBRunNotRun, GBRunFailed, GBRunStopped, GBRunEnded}

// gbOutcome is what the Greenbone step adds to the stored snapshot.
type gbOutcome struct {
	rows   []GreenboneRow
	checks []CheckRow
	not    []NotCheckedRow
	audit  string          // the detail of the exposure.greenbone_scan audit row
	state  string          // GreenboneRun.State after the step
	addrs  []GreenboneAddr // a domain's: the state of each address
	stop   *GreenboneStop  // why a stopped step was stopped (GreenboneRun.Stop)
}

// gbRunOf is the state of OpenVAS over several addresses of a domain: stopped, else ended, else partial, else done, else failed,
// else not run. The rows of the addresses that finished are kept and shown whatever it is.
func gbRunOf(states []string) string {
	for _, st := range []string{GBRunStopped, GBRunEnded, GBRunPartial, GBRunDone, GBRunFailed} {
		if slices.Contains(states, st) {
			return st
		}
	}
	return GBRunNotRun
}

// gbPorts is what OpenVAS checks on ip: the TCP ports this run found open there (the surface scan and service
// identification), ascending, without repeats; a row an earlier scan left (not seen, not checked) is not one.
func gbPorts(rows []PortRow, ip netip.Addr) []int {
	var out []int
	for _, p := range rows {
		if ipKey(p.IP) == ip.String() && p.Port >= 1 && p.Port <= 65535 && p.Misses == 0 && !p.Unchecked && !slices.Contains(out, p.Port) {
			out = append(out, p.Port)
		}
	}
	slices.Sort(out)
	return out
}

// gbPortsLine is why OpenVAS does not scan these ports, "" when it may: none (nothing to check), or more than
// commonports.MaxBelievableOpen (the shape of a router or SYN proxy answering for every port).
func gbPortsLine(ports []int) string {
	switch {
	case len(ports) == 0:
		return notGBNoPorts
	case len(ports) > commonports.MaxBelievableOpen:
		return notGBTooManyPorts
	}
	return ""
}

// greenboneStep is the deep scan itself (INV-25), after the snapshot of the other steps is stored: the gate again, the probe log row,
// then runGreenbone, at most the cap. Only a stop of the run returns an error; every other outcome is a line.
func (s *Service) greenboneStep(ctx context.Context, st ScanTarget, ports []int) (gbOutcome, error) {
	ip, err := netip.ParseAddr(st.Value)
	if err != nil { // an IP target's value is a canonical public IPv4 (INV-2, INV-3): never reached
		return gbOutcome{}, fmt.Errorf("exposure: Greenbone on %q: %w", st.Value, err)
	}
	return s.greenboneAt(ctx, st, ip, ports)
}

// gbOwnNow says that OpenVAS may start on ip, an address without a domain scope: only the box's own IP, proven by the box's sighting
// of it inside its ValidDays (OwnIPProof, the gate of the address, fail closed); a typed IP never (it reaches OpenVAS only with its
// live proof as the scope). An IP of the box that the box does not go out through right now (a second Internet line, a router that
// balances two lines) is scannable by every step for its whole proof window (INV-13), OpenVAS included, as the scan worker's and the
// host's own-IP fences take it on the same proof.
func (s *Service) gbOwnNow(ctx context.Context, actor string, ip netip.Addr) (bool, error) {
	t, ok, err := loadTargetByValue(ctx, s.cfg.DB.Reader(), ip.String())
	if err != nil || !ok || t.Kind != KindIP {
		return false, err
	}
	if t.Typed { // a typed IP reaches OpenVAS only with its live proof as the domain scope (the host's fence); never bare
		return false, nil
	}
	at, ok, err := s.OwnIPProof(ctx, actor, ip) // the gate of the address: a sighting now renews the proof, and it holds for ValidDays
	return ok && !at.IsZero(), err
}

// GreenboneFence is implemented by a GreenboneHost whose host checks the domain fence itself before OpenVAS scans an address of a
// domain that is not the box's own IP (the OpenVAS target is a domain_ip job): the token is
// the box's, the domain's TXT carries it, and scope.Name resolves to ip now. A nil error means the host allows that one scan. Without
// it OpenVAS never scans such an address.
type GreenboneFence interface {
	CheckDomainIP(ctx context.Context, scope DomainScope, ip netip.Addr, c FenceCheck) error
}

// FenceCheck is how GreenboneFence checks: Disruptive asks the CNAME rule too (a name whose CNAME leaves the domain is refused);
// Recheck is the check of a task that runs, which the host answers from DNS, never from its cache.
type FenceCheck struct {
	Disruptive bool
	Recheck    bool
}

// The lines of OpenVAS on a domain's address that is not the box's.
const (
	notGBNoFence = "OpenVAS did not scan: this box's host does not check the domain fence for OpenVAS yet (update the box), so nothing was sent."
	notGBFenced  = "OpenVAS did not scan: the Vedette host's domain fence refused this address, so nothing was sent."
	// notGBFencedMid is the reason of a task the host's fence stopped while it ran: the TXT record or the name moved.
	notGBFencedMid = "the Vedette host's domain fence stopped it while it ran (the domain's TXT record or the name's address changed), and its results were discarded."
)

// gbFenceRecheck is how often a running OpenVAS task on a domain's address asks the host's fence again (the own_ip re-check's period).
const gbFenceRecheck = 3 * time.Minute

// domainNote is what the OpenVAS probe row adds for a domain's address: the domain, the name and its CNAME chain.
func domainNote(st ScanTarget) string {
	if st.Domain == nil {
		return ""
	}
	chain := st.Domain.Chain
	if chain == "" {
		chain = st.Domain.Name + " (CNAME not known)"
	}
	return "Address of " + st.Domain.Domain + " (domain fence), name " + st.Domain.Name + ", CNAME chain " + chain + ". " // first: the note is clipped at its end
}

// greenboneAt is greenboneStep on one address: an IP target's own, or an address a domain's deep scan reached, whose ScanTarget
// then carries the domain (and, for an address that is not the box's, its scope, which the host checks through GreenboneFence). ports
// are the TCP ports this run found open there (gbPorts): OpenVAS checks those only.
func (s *Service) greenboneAt(ctx context.Context, st ScanTarget, ip netip.Addr, ports []int) (gbOutcome, error) {
	line := func(text, audit string) (gbOutcome, error) {
		return gbOutcome{not: []NotCheckedRow{{Kind: "greenbone", Text: clipText(text, maxLineText)}}, audit: audit, state: GBRunNotRun}, nil
	}
	if l := gbPortsLine(ports); l != "" { // nothing is sent: no open port to check, or an address that answers on every port
		return line(l, "not done: "+strings.TrimPrefix(l, "OpenVAS did not scan: "))
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
	// The testing terms again: withdrawn meanwhile, nothing is sent; without the disruptive checks now, the deep config, not the disruptive.
	m := t.mode()
	if !m.Full {
		return line(notGBTerms, "not done: the testing terms are not accepted")
	}
	if st.Domain == nil { // no domain scope: the host has no fence for OpenVAS, so the core checks the box's own address here (INV-13)
		own, err := s.gbOwnNow(ctx, st.User, ip)
		if ctx.Err() != nil {
			return gbOutcome{}, ctx.Err()
		}
		if err != nil {
			s.cfg.Log.ErrorContext(ctx, "exposure: checking the box's own address before Greenbone failed", "target", st.Value, "ip", ip, "error", err)
		}
		if !own {
			return line(notGBNotOwn, "not done: not the box's own proven IP (no sighting within its 90 days, or a typed IP without its scope)")
		}
	}
	// Never above the run's snapshot: withdrawing the terms stops the run; the disruptive checks added while it runs wait for the next one
	st.Mode = ScanMode{Full: true, Disruptive: m.Disruptive && st.Mode.Disruptive}
	if st.Domain != nil { // An address of a domain that is not the box's: the host checks the fence itself, or nothing is sent
		f, ok := s.cfg.Greenbone.(GreenboneFence)
		if !ok {
			return line(notGBNoFence, "not done: no domain fence for OpenVAS")
		}
		if err := f.CheckDomainIP(ctx, *st.Domain, ip, FenceCheck{Disruptive: st.Mode.Disruptive}); err != nil {
			if ctx.Err() != nil {
				return gbOutcome{}, ctx.Err()
			}
			s.cfg.Log.ErrorContext(ctx, "exposure: the domain fence refused OpenVAS", "target", st.Value, "ip", ip, "error", err)
			return line(notGBFenced, "not done: the domain fence refused it")
		}
	}
	plog, _ := s.cfg.Probes.(GreenboneProbeLog)
	if plog == nil {
		return line(notGBNoLog, "not done: no probe log")
	}
	g := s.gb()
	g.mu.Lock()
	poll, limit := g.poll, g.cap
	g.mu.Unlock()
	res, err := s.runGreenbone(ctx, limit, st, ip, ports, plog, poll)
	rows, problems := res.rows, res.problems
	var out gbOutcome
	if len(problems) > 0 {
		s.cfg.Log.ErrorContext(ctx, "exposure: Greenbone left something behind", "target", st.Value, "problems", problems)
		out.not = append(out.not, NotCheckedRow{Kind: "greenbone", Text: clipText("OpenVAS: "+strings.Join(problems, "; ")+". The next scan stops and removes Vedette's leftover tasks before it starts.", maxLineText)})
	}
	add := func(state, text, audit string) (gbOutcome, error) {
		out.not = append([]NotCheckedRow{{Kind: "greenbone", Text: clipText(text, maxLineText)}}, out.not...)
		out.audit, out.state = audit, state
		if len(problems) > 0 {
			out.audit += "; " + strings.Join(problems, "; ")
		}
		return out, nil
	}
	var un *Unavailable
	switch {
	case err == nil:
	case ctx.Err() != nil: // the run was stopped
		out.audit, out.state = "stopped", GBRunStopped
		if len(problems) > 0 {
			out.audit += "; " + strings.Join(problems, "; ")
		}
		return out, err
	case errors.Is(err, errGBNoLog):
		return add(GBRunNotRun, notGBNoLog, "not done: the probe log could not be written")
	case errors.Is(err, errGBCap):
		return add(GBRunFailed, notGBSlow, "not done: did not finish within 90 minutes, and its report could not be read")
	case errors.As(err, &un): // before the task started: leftovers still stopping, a config that does not hold
		return add(GBRunNotRun, "OpenVAS did not scan: "+un.Reason, "not done: "+un.Reason)
	case errors.Is(err, errGMPSlow):
		return add(GBRunFailed, notGBSlowAnswer, "not done: no answer in time")
	case errors.Is(err, ErrGMPBad):
		s.cfg.Log.ErrorContext(ctx, "exposure: unreadable Greenbone answer", "target", st.Value, "error", err)
		return add(GBRunFailed, notGBUnread, "not done: unreadable answer")
	default:
		s.cfg.Log.ErrorContext(ctx, "exposure: Greenbone failed", "target", st.Value, "error", err)
		return add(GBRunFailed, notGBFail, "failed")
	}
	switch res.end {
	case gbEndQueued: // it never scanned, so it did not run
		return add(GBRunNotRun, notGBQueued, "not done: did not start scanning within 90 minutes")
	case gbEndFenced: // its results were discarded
		return add(GBRunEnded, notGBEnded+notGBFencedMid, "ended: the domain fence stopped it")
	case gbEndByGVM:
		if !res.scanned && len(rows) == 0 { // never seen scanning, nothing found: it did not run, no check line
			return add(GBRunNotRun, notGBEndedEarly+res.reason, "not done: OpenVAS ended the task before it started scanning")
		}
		if res.unread { // nothing read: no check line claims a count
			return add(GBRunEnded, notGBEnded+res.reason+notGBEndedUnread, "ended by OpenVAS: its report could not be read")
		}
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
	out.rows, out.state = rows, GBRunDone
	how, text, audit := "scanned", "", "done"
	switch res.end {
	case gbEndCap: // Never "not shown" when rows exist; the line says they are what it had found by the cap
		how, out.state, text, audit = "partly scanned", GBRunPartial, notGBPartial, "stopped after 90 minutes"
		if len(rows) == 0 {
			text = notGBPartialNone
		}
	case gbEndByGVM: // it scanned and OpenVAS ended it (not Vedette); the rows it had found are kept
		how, out.state, text, audit = "partly scanned", GBRunEnded, notGBEnded+res.reason, "ended by OpenVAS"
	}
	out.checks = []CheckRow{{Kind: "greenbone", At: store.FormatTS(s.clock()), Text: clipText(fmt.Sprintf(
		"OpenVAS %s %s from outside without logging in (%s; %s): %s with QoD %d or more (%d high or medium, %s), %s named.",
		how, ip, levelOf(st.Mode).text, gbPortsText(ports), plural(len(rows), "result"), GreenboneMinQoD, len(rows)-low, plural(low, "hardening note"), plural(len(cves), "CVE")), maxLineText)}}
	if text != "" {
		out.not = append([]NotCheckedRow{{Kind: "greenbone", Text: clipText(text, maxLineText)}}, out.not...)
	}
	if len(rows) > maxGreenboneRows {
		out.not = append(out.not, NotCheckedRow{Kind: "greenbone", Text: fmt.Sprintf("OpenVAS: only the %d highest-severity of %d results are kept.", maxGreenboneRows, len(rows))})
	}
	out.audit = fmt.Sprintf("%s: %s, %s", audit, plural(len(rows), "result"), plural(len(cves), "CVE"))
	if len(problems) > 0 {
		out.audit += "; " + strings.Join(problems, "; ")
	}
	return out, nil
}

var errGBNoLog = errors.New("exposure: the Greenbone probe log row could not be written")

// errGBCap: the cap ended the scan and what it had found could not be read (it ended before the task started, or the stop or the
// report failed after it).
var errGBCap = errors.New("exposure: OpenVAS did not finish within the cap")

// gbPortsText names the ports OpenVAS checked in its check line (at most maxLineText): which, while that stays short, else how many.
// The probe log row has the whole list.
func gbPortsText(ports []int) string {
	if r := strings.TrimPrefix(gbPortRange(ports), "T:"); len(r) <= 16 {
		return "TCP ports " + strings.ReplaceAll(r, ",", ", ")
	}
	return fmt.Sprintf("the %d open TCP ports", len(ports))
}

// How a started OpenVAS task ended (gbResult.end).
const (
	gbEndDone   = "done"   // gvmd said Done (also right after Vedette's stop at the cap): rows are its report
	gbEndCap    = "cap"    // the cap stopped it after it had started scanning: rows are what it had found by then
	gbEndQueued = "queued" // the cap passed and it never started scanning (Requested/Queued, no progress, no row): nothing was checked
	gbEndByGVM  = "ended"  // gvmd ended it (Stopped/Interrupted without Vedette's stop): rows are what its report holds
	gbEndFenced = "fenced" // the domain fence stopped it while it ran: its rows are discarded
)

// gbResult is what runGreenbone returns when it does not fail: the rows, what could not be cleaned up, how the task ended and, for
// gbEndByGVM, why.
type gbResult struct {
	rows     []GreenboneRow
	problems []string
	end      string
	reason   string
	unread   bool // gbEndByGVM: its report could not be read
	scanned  bool // the task was seen scanning
}

// gbProbePorts is the port list as the probe log row names it: the whole "T:…" list while it is short, else its
// start and the count, so the row (clipped at 300 characters by the scan module) never loses what follows.
func gbProbePorts(ports []int) string {
	r := gbPortRange(ports)
	if len(r) <= 60 {
		return r
	}
	cut := strings.LastIndexByte(r[:50], ',')
	return fmt.Sprintf("%s,… (%d ports)", r[:cut], len(ports))
}

// runGreenbone is one scan over GMP: Vedette's leftover tasks, targets and port lists removed first, the config of the scan's level,
// a port list of exactly the open ports, a target of exactly ip, a task, the probe log row, start, a poll every
// `poll` until gvmd ends it, then the report (QoD >= GreenboneMinQoD). At most limit: when it passes with the task running, the task
// is stopped and what it had found by then is read; a stop of the run (ctx) reads nothing. The task, its report, the target
// and the port list are deleted afterwards (stopped first when cut short), and what could not be is in the result's problems.
func (s *Service) runGreenbone(ctx context.Context, limit time.Duration, st ScanTarget, ip netip.Addr, ports []int, plog GreenboneProbeLog, poll time.Duration) (res gbResult, err error) {
	gctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	defer func() { // the cap, not a stop of the run, ended it and nothing could be read
		if err != nil && ctx.Err() == nil && gctx.Err() != nil && !errors.Is(err, errGBNoLog) {
			err = errGBCap
		}
	}()
	dctx, dcancel := context.WithTimeout(gctx, gbDialTimeout)
	conn, login, err := s.cfg.Greenbone.Dial(dctx)
	dcancel()
	if err != nil {
		return res, err
	}
	defer func() { _ = conn.Close() }()
	g := &gmpConn{conn: conn}
	if err := g.authenticate(gctx, login); err != nil {
		return res, err
	}
	if res.problems, err = g.leftovers(gctx, login.User); err != nil { // never a second task of Vedette's beside one still running
		return res, err
	}
	lv := levelOf(st.Mode)
	config, err := g.levelConfig(gctx, login.User, lv)
	if err != nil {
		return res, err
	}
	name := gbObjectPrefix + ip.String() + "-" + store.NewID("gb")
	portList, err := g.createPortList(gctx, name, ports)
	if err != nil {
		return res, err
	}
	task, target, running := "", "", false
	defer func() { res.problems = append(res.problems, s.gbCleanup(ctx, task, target, portList, running)...) }()
	if target, err = g.createTarget(gctx, name, ip.String(), portList); err != nil {
		return res, err
	}
	if task, err = g.createTask(gctx, name, target, config); err != nil {
		return res, err
	}
	if err := plog.RecordGreenboneProbe(gctx, GreenboneProbe{ID: store.NewID("pb"), IP: ip.String(), Fence: domainNote(st), PortList: gbProbePorts(ports),
		Config: lv.name + " (" + lv.text + ")", Note: gbNote}); err != nil { // LEGAL §3: logged before the task starts
		if gctx.Err() != nil {
			return res, gctx.Err()
		}
		s.cfg.Log.ErrorContext(ctx, "exposure: writing the Greenbone probe log failed", "target", st.Value, "error", err)
		return res, errGBNoLog
	}
	report, err := g.startTask(gctx, task)
	if err != nil {
		running = true // it may have started: stop it to be sure
		return res, err
	}
	running = true
	w := s.gbWait(gctx, g, st, ip, task, report, poll)
	if w.end != "" && w.end != gbEndFenced {
		running = false // gvmd ended it: no stop
	}
	res.scanned = w.scanned
	if w.err == nil {
		res.rows, res.end, res.reason, res.unread = w.rows, w.end, w.reason, w.unread
		return res, nil
	}
	if ctx.Err() != nil || gctx.Err() == nil {
		return res, w.err
	}
	// The cap. A task gvmd had just ended (finished, or ended without Vedette's stop), whose report read the cap cut: read it again over a
	// new session; it needs no stop.
	if w.end == gbEndDone || w.end == gbEndByGVM {
		rows, rerr := s.gbReadReport(ctx, report, ip)
		if rerr != nil {
			if w.end == gbEndByGVM && ctx.Err() == nil { // it ended without Vedette's stop: say so, claim no count
				res.end, res.reason, res.unread = w.end, w.reason, true
				return res, nil
			}
			return res, rerr
		}
		res.rows, res.end, res.reason = rows, w.end, w.reason
		return res, nil
	}
	// Else stop the task and read what it had found by then.
	p := s.gbPartial(ctx, task, report, ip, poll, w.scanned)
	if p.stopped {
		running = false
	}
	if p.err != nil {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		s.cfg.Log.ErrorContext(ctx, "exposure: reading what Greenbone found before the cap failed", "target", st.Value, "error", p.err)
		return res, errGBCap
	}
	res.rows, res.end = p.rows, p.end
	return res, nil
}

// gbWaited is how gbWait ended: end is "" when the task was not seen to end (err says why); scanned says it was seen scanning
// (Running or Processing, or a progress above 0).
type gbWaited struct {
	rows    []GreenboneRow
	end     string
	reason  string
	unread  bool
	scanned bool
	err     error
}

// gbScanning says a task poll shows it scanning (or done scanning).
func gbScanning(state string, progress int) bool {
	return state == "Running" || state == "Processing" || progress > 0
}

// gbWait polls the started task every `poll` until gvmd ends it, then reads its report. A task gvmd ended without Vedette's stop (Stopped or
// Interrupted: Vedette sent no stop) ends as gbEndByGVM with what its report holds; a refusal of the domain fence
// as gbEndFenced (the task still runs: gbCleanup stops it).
func (s *Service) gbWait(ctx context.Context, g *gmpConn, st ScanTarget, ip netip.Addr, task, report string, poll time.Duration) (w gbWaited) {
	checked := s.clock()
	for {
		// An address of a domain that is not the box's is checked again by the host's fence every gbFenceRecheck
		// while the task runs; the first answer that is not a yes stops the task (gbCleanup) and discards what it found.
		if f, ok := s.cfg.Greenbone.(GreenboneFence); ok && st.Domain != nil && s.clock().Sub(checked) >= gbFenceRecheck {
			checked = s.clock()
			if err := f.CheckDomainIP(ctx, *st.Domain, ip, FenceCheck{Disruptive: st.Mode.Disruptive, Recheck: true}); err != nil {
				if ctx.Err() != nil {
					w.err = ctx.Err()
					return w
				}
				s.cfg.Log.ErrorContext(ctx, "exposure: the domain fence stopped OpenVAS", "target", st.Value, "ip", ip, "error", err)
				w.end = gbEndFenced
				return w
			}
		}
		state, progress, err := g.taskStatus(ctx, task)
		if err != nil {
			w.err = err
			return w
		}
		w.scanned = w.scanned || gbScanning(state, progress)
		if progress >= 0 && progress <= 100 { // #830: gvmd's own percent of the task, read by this poll anyway
			reportOpenVAS(ctx, progress)
		}
		switch state {
		case gmpDone:
			w.end = gbEndDone
			w.rows, w.err = g.report(ctx, report, ip.String())
			return w
		case "Stopped", "Interrupted":
			// Not "by itself": a person may have stopped it in OpenVAS's own interface, or gvmd restarted
			w.end, w.reason = gbEndByGVM, "OpenVAS reports it as "+strings.ToLower(state)+"; Vedette did not stop it."
			rows, err := g.report(ctx, report, ip.String())
			if err != nil { // its report may be missing (Interrupted): the line says it ended; nothing is claimed
				if ctx.Err() != nil {
					w.err = ctx.Err()
					return w
				}
				s.cfg.Log.ErrorContext(ctx, "exposure: reading the report of a task OpenVAS ended failed", "target", st.Value, "error", err)
				w.unread = true
			}
			w.rows = rows
			return w
		}
		select {
		case <-ctx.Done():
			w.err = ctx.Err()
			return w
		case <-time.After(poll):
		}
	}
}

// gbStopped is how gbPartial ended.
type gbStopped struct {
	rows    []GreenboneRow
	end     string // gbEndDone, gbEndCap or gbEndQueued
	stopped bool   // gvmd ended the task
	err     error
}

// gbPartial is what follows the cap: over a new session (the scan's may be cut in the middle of an answer), stop the task,
// wait until gvmd says it ended (it writes what it found to its database when it stops, GSM manual 9.8; measured on gvmd
// 26.43: "Stopped" within a second), then read its report with the same filter as a finished one. A task that reached Done is done; one
// never seen scanning with no row is queued; else what it had found by then. When the budget passes while it is still
// stopping, the report is read once more over a new session. A stop of the run (ctx) ends it at once.
func (s *Service) gbPartial(ctx context.Context, task, report string, ip netip.Addr, poll time.Duration, scanned bool) (p gbStopped) {
	bctx, cancel := context.WithTimeout(ctx, gbStopBudget)
	defer cancel()
	conn, login, err := s.cfg.Greenbone.Dial(bctx)
	if err != nil {
		p.err = err
		return p
	}
	defer func() { _ = conn.Close() }()
	g := &gmpConn{conn: conn}
	if err := g.authenticate(bctx, login); err != nil {
		p.err = err
		return p
	}
	if _, err := g.do(bctx, "stop_task", `<stop_task task_id="`+task+`"/>`, gmpMaxAnswer, nil); err != nil {
		p.err = err
		return p
	}
	final := ""
wait:
	for {
		state, progress, err := g.taskStatus(bctx, task)
		if err != nil {
			if ctx.Err() != nil {
				p.err = ctx.Err()
				return p
			}
			if bctx.Err() != nil {
				break wait // still stopping at the end of the budget: read what it has
			}
			p.err = err
			return p
		}
		scanned = scanned || gbScanning(state, progress)
		if state == "Stopped" || state == gmpDone || state == "Interrupted" {
			final, p.stopped = state, true
			break wait
		}
		select {
		case <-bctx.Done():
			if ctx.Err() != nil {
				p.err = ctx.Err()
				return p
			}
			break wait
		case <-time.After(poll):
		}
	}
	if p.stopped {
		p.rows, p.err = g.report(bctx, report, ip.String())
	}
	if !p.stopped || (p.err != nil && ctx.Err() == nil && bctx.Err() != nil) { // the budget ran out: one more read, new session
		p.rows, p.err = s.gbReadReport(ctx, report, ip)
	}
	switch {
	case final == gmpDone && p.err == nil:
		p.end = gbEndDone
	case !scanned && len(p.rows) == 0:
		p.end, p.err = gbEndQueued, nil // nothing was scanned: no report to read is not a failure
	default:
		p.end = gbEndCap
	}
	return p
}

// gbReadReport reads a report over a new session, within one command's time.
func (s *Service) gbReadReport(ctx context.Context, report string, ip netip.Addr) ([]GreenboneRow, error) {
	ctx, cancel := context.WithTimeout(ctx, gbDialTimeout+gmpCmdTimeout)
	defer cancel()
	conn, login, err := s.cfg.Greenbone.Dial(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	g := &gmpConn{conn: conn}
	if err := g.authenticate(ctx, login); err != nil {
		return nil, err
	}
	return g.report(ctx, report, ip.String())
}

// gbCleanup stops (when it still runs) and deletes the scan's task, report, target and port list over a new session on its own short
// context: the scan's session may be cut in the middle of an answer (a stop, the cap), and gvmd must not keep scanning. Every failure
// is logged and returned; a task that is left is removed by the next scan before it starts.
func (s *Service) gbCleanup(ctx context.Context, task, target, ports string, running bool) []string {
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
	failed := g.cleanup(ctx, task, target, ports, running)
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
func (s *Service) withGreenboneVulns(ctx context.Context, snap *vulnSet) {
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

// ---- the weekly feed update ----

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
// not, and GreenboneSyncEvery after Greenbone was last turned on when no update ran since (turning it on loads the feed).
// ok is false when a stored time cannot be read. It may be in the past (due, not yet run); the page shows it as now.
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

// RunGreenboneSync is the body of the weekly feed-update job. While Greenbone is enabled and ready, once the update is
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
	if s.off || s.closed || s.feedSync || s.scanning() {
		s.runMu.Unlock()
		return nil
	}
	held := make(chan struct{})
	s.feedSync, s.feedSyncAt, s.syncDone = true, s.clock(), held
	s.runMu.Unlock()
	defer func() { // a scan that started meanwhile waited for this update (waitFeedSync)
		s.runMu.Lock()
		s.feedSync, s.syncDone = false, nil
		s.runMu.Unlock()
		close(held)
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

// errScanFeedSync is the 409 busy of a scan asked while the feed update holds the slot: the real bound, and when it
// started.
func (s *Service) errScanFeedSync(started time.Time) *APIError {
	return apiErr(409, "busy", "OpenVAS is loading its weekly feed update (started %s), which holds the box's scanner while it runs, at most %d minutes. Try the scan again after it.",
		s.momentText(started), int(gbSyncTimeout/time.Minute))
}

// waitSync waits, at most gbSyncStopWait, for a feed update that was just cancelled to end: the host must not pull or
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

// reportOpenVAS is the progress of the OpenVAS step (#830): the percent gvmd gives its task, which the wait loop polls anyway, and the latest end of the step (the cap's deadline plus gbStopBudget).
func reportOpenVAS(ctx context.Context, pct int) {
	u := vprogress.Update{Phase: vprogress.PhaseOpenVAS, Percent: float64(pct)}
	if d, ok := ctx.Deadline(); ok { // the cap context of runGreenbone starts per address: its end plus the stop and report read (#915)
		u.EndsBy = d.Add(gbStopBudget)
	}
	vprogress.Report(ctx, u)
}
