package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/knt048/vedette/core/auth"
	"github.com/knt048/vedette/core/jobs"
	"github.com/knt048/vedette/core/store"
	hostclient "github.com/knt048/vedette/host/client"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/notify"
)

// exposureTestConfig is a seam for the end-to-end box (cmd/vedette/e2eexposure_test.go, WP-30, #263): a test binary sets it to swap the
// prober, the resolver and the scan runner for loopback fakes. It is nil in the production binary, which keeps the real ones.
var exposureTestConfig func(*exposure.Config)

var (
	exposureMu       sync.Mutex
	exposureServices = map[*store.DB]*exposure.Service{}
)

// exposureService builds the exposure service once per database, so the handlers and the auto-detect job share it
// (and its one-detection-at-a-time lock). The box finds its public IP through three public services fixed in code;
// events go to deps.Bus. The scan itself is the scan module's runner (scanRunner) behind exposure's own switch:
// it needs only this module on, not the Vulnerability scans module.
func exposureService(d deps) *exposure.Service {
	exposureMu.Lock()
	defer exposureMu.Unlock()
	if s := exposureServices[d.DB]; s != nil {
		return s
	}
	prober, err := exposure.NewPublicServiceProber(nil, nil, 0)
	if err != nil { // the addresses are constants of the package: a programming error, caught at start-up
		panic("vedette: " + err.Error())
	}
	// "What the Internet sees" asks Shodan InternetDB, only on an administrator's click (no job).
	outside, err := exposure.NewInternetDB("", nil)
	if err != nil { // the address is a constant of the package
		panic("vedette: " + err.Error())
	}
	cfg := exposure.Config{DB: d.DB, Audit: d.Audit, Resolver: net.DefaultResolver, Prober: prober, Runner: scanRunner(d), Outside: outside, Log: d.Log, Clock: d.Clock}
	// A snapshot's day and the times in the API's messages are those of the organization's time zone (Settings › General)
	cfg.Zone = orgLocationAt(d)
	if d.Auth != nil { // The first scan of a target records the commitment only for an administrator with two-step sign-in
		cfg.TwoStep = exposureTwoStep(d.Auth)
	}
	if d.Inventory != nil && d.Findings != nil { // a nil service would only fail at the first read
		g := exposureGateway{inv: d.Inventory, fnd: d.Findings}
		if d.HostSocket != "" {
			g.state = hostclient.New(d.HostSocket)
		}
		cfg.Gateway, cfg.Appliances = g, g
	}
	if d.HostSocket != "" { // The domain fence's token comes from vedette-host, which holds the key; no host, no fence (nil)
		cfg.DomainFence = hostDomainFence{host: hostclient.New(d.HostSocket)}
	}
	if d.Bus != nil { // a nil *events.Bus inside the interface would not compare equal to nil
		cfg.Publisher = d.Bus
	}
	cfg.Runs = d.Runs // a scan is a run of the box's run manager: queued in the database, one at a time in its lane
	// Each target's scan schedule is a shared schedule (core/schedule, exposure.target:<id>): its ticker queues the scan as a run, inside
	// the scan window unless the schedule says otherwise. What a scan finds new (a newly open port, a new issue) goes to the admins' alert
	// channels through notify's system notice path, with a link to the target when the box knows its own address; newNotify is read at
	// send time.
	cfg.Schedules = d.Schedules
	cfg.Alert = exposureAlert(d)
	// S-EXP-2 (INV-19, INV-20): identified services are compared with exploited CVEs when a snapshot is read. cfg.Services is
	// the scan container's nmap -sV on the box's own verified public IP (sensor-active ScanExternal). The commitment sentence of
	// NoticeVersion 2026-11-14 (K-4) already names service identification, so wiring it leaves NoticeVersion alone (a second bump
	// would ask every customer again); PRIVACY flow 9, Settings -> Privacy and the nmap row of THIRD_PARTY_NOTICES say what is sent.
	gate := func(ctx context.Context, actor string, ip netip.Addr) (bool, error) {
		return exposureService(d).ScannableIP(ctx, actor, ip) // called at scan time, after this function returned
	}
	// A deep scan asks exposure's ModeNow right before its job leaves core, beside the gate.
	modeNow := func(ctx context.Context, actor, id string) (exposure.ScanMode, error) {
		return exposureService(d).ModeNow(ctx, actor, id) // called at scan time, after this function returned
	}
	cfg.Services = exposureServicesFor(d, gate, modeNow)
	// INV-23: the exploited CVEs matched on a port are checked with their safe nuclei templates by the scan container,
	// scope own_ip, each template in the scan module's probe log first. Named by the same commitment sentence (K-4).
	// A target whose testing terms are accepted gets the deep templates; ModeNow is read again right before each run.
	mode := func(ctx context.Context, actor, id string) (exposure.ScanMode, error) {
		return exposureService(d).ModeNow(ctx, actor, id)
	}
	cfg.Templates, cfg.Probes = exposureTemplatesFor(d, gate, mode), exposureProbeLog{d: d}
	clock := d.Clock
	if clock == nil {
		clock = time.Now
	}
	m := exposureMatcher{now: clock}
	m.vulns, m.catalogue, m.stamp = exposureFeeds(d)
	m.memo = &catalogueMemo{}
	if d.Inventory != nil {
		m.catalog = d.Inventory.KevKeysByCPE
	}
	cfg.Matcher = m
	cfg.Web = exposureWebFor(d) // INV-24: ZAP's passive baseline through vedette-host's zap.baseline
	// INV-25: OpenVAS (Greenbone CE) through vedette-host's greenbone.* commands, off until an administrator enables it.
	// DataDir is the disk preflight's filesystem. privacyFacts.GreenboneEnabled (flow 16) reads this same service (review r2).
	cfg.Greenbone, cfg.DataDir = exposureGreenboneFor(d), d.DataDir
	if exposureTestConfig != nil {
		exposureTestConfig(&cfg)
	}
	svc, err := exposure.NewService(cfg)
	if err != nil { // only a missing dependency: a programming error in serve
		panic("vedette: " + err.Error())
	}
	exposureServices[d.DB] = svc
	if d.Reg != nil { // INV-18: switching the module off stops the scan that runs (SYS-5); the registry's goroutine must not wait for it
		d.Reg.OnChange(func(id string, enabled bool) {
			if id == exposure.ModuleID {
				svc.ModuleSwitched(enabled)
			}
		})
	}
	return svc
}

// exposureAtStart gives every target its scan schedule (before the schedules' ticker starts), and starts OpenVAS again when an
// administrator had it enabled and the module is on: without it the first scan after a restart or an update of the box finds it "still
// starting" and skips it. The module switch does the same (exposure's ModuleSwitched).
func exposureAtStart(ctx context.Context, d deps) {
	svc := exposureService(d)
	// every target has its scan schedule before the schedules' ticker starts (targets stored before schedules were shared get the default)
	if err := svc.EnsureSchedules(ctx); err != nil {
		d.Log.ErrorContext(ctx, "exposure: the targets' scan schedules", "error", err)
	}
	if d.Reg == nil || d.Reg.Enabled(exposure.ModuleID) {
		svc.GreenboneAtStart(ctx)
	}
}

// exposureJobs is the Jobs func of the exposure entry in wiredModules.
func exposureJobs(d deps) []jobs.Job { return exposure.Jobs(exposureService(d)) }

// exposureTwoStep says how a user meets two-step sign-in for the first Scan now of a target: Vedette's own method, or "sso"
// for an account made by an SSO sign-in, whose MFA the identity provider owns (Vedette two-step cannot be turned on for it).
func exposureTwoStep(a *auth.Service) exposure.TwoStep {
	return func(ctx context.Context, userID string) (string, error) {
		u, err := a.GetUser(ctx, userID)
		if err != nil {
			return "", err
		}
		if u.TwofaMethod == "" && u.SSO {
			return "sso", nil
		}
		return u.TwofaMethod, nil
	}
}

// exposureAlert sends what a scan found new on a target through notify (an incident-kind notice). Without the notify module there is no
// channel to send to: the rows are on the target's page.
func exposureAlert(d deps) func(ctx context.Context, a exposure.Alert) error {
	return func(ctx context.Context, a exposure.Alert) error {
		sev := notify.Medium
		switch a.Severity {
		case exposure.AlertCritical:
			sev = notify.Critical
		case exposure.AlertHigh:
			sev = notify.High
		}
		clock := d.Clock
		if clock == nil {
			clock = time.Now
		}
		n := notify.Notice{ID: a.ID, Kind: notify.KindIncident, Severity: sev, Title: a.Title, What: a.Text, At: clock()}
		if d.BaseURL != nil {
			if base := strings.TrimRight(d.BaseURL(), "/"); base != "" {
				n.Link = base + "/exposure/" + url.PathEscape(a.TargetID)
			}
		}
		err := newNotify(&d).Publish(ctx, n)
		if errors.Is(err, notify.ErrModuleOff) {
			return nil
		}
		return err
	}
}
