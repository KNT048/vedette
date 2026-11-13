package core

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/knt048/vedette/host/api"
)

// Views of the OS endpoints in the shape of web/src/features/core/contract.ts (OsState, OsRun). The five
// operations that return an OsState have five generated Go types of the same shape; the handlers build one
// view and decode it into the type they return (asOAS), so the shape is written once.

type osPackageView struct {
	Name     string   `json:"name"`
	Current  string   `json:"current"`
	New      string   `json:"new"`
	Security bool     `json:"security"`
	CVEs     []string `json:"cves"`
}

type osInfoView struct {
	Distro      string    `json:"distro"`
	Name        string    `json:"name"`
	Release     string    `json:"release"`
	Kernel      string    `json:"kernel"`
	SupportEnd  string    `json:"support_end"`
	ExtendedEnd *string   `json:"extended_end"`
	BootedAt    time.Time `json:"booted_at"`
	LastCheck   time.Time `json:"last_check"`
	Mirrors     []string  `json:"mirrors"`
}

type releaseUpgradeView struct {
	To    string   `json:"to"`
	Steps []string `json:"steps"`
}

type osStateView struct {
	OS                *osInfoView         `json:"os"` // nil until the host has checked once (D-407)
	Pending           []osPackageView     `json:"pending"`
	RebootRequired    bool                `json:"reboot_required"`
	RebootReasons     []string            `json:"reboot_reasons"`
	RebootScheduledAt *time.Time          `json:"reboot_scheduled_at"`
	AutoSecurity      bool                `json:"auto_security"`
	Window            maintWindow         `json:"window"`
	ReleaseUpgrade    *releaseUpgradeView `json:"release_upgrade"`
	Busy              bool                `json:"busy"`
}

type osHealthView struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
}

type osRunResultView struct {
	Installed      int            `json:"installed"`
	Security       int            `json:"security"`
	Backup         string         `json:"backup"`
	Health         []osHealthView `json:"health"`
	RebootRequired bool           `json:"reboot_required"`
}

type osRunView struct {
	ID         string           `json:"id"`
	Scope      string           `json:"scope"`
	Status     string           `json:"status"` // running | done | failed
	Error      *string          `json:"error"`  // only a failed run: why, in words
	StartedAt  time.Time        `json:"started_at"`
	FinishedAt *time.Time       `json:"finished_at"`
	User       string           `json:"user"`
	Lines      []string         `json:"lines"`
	Result     *osRunResultView `json:"result"`
}

// asOAS decodes a view into the generated type of one operation (their decoders check every required field).
func asOAS[T any](v any) (*T, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("core: encode view: %w", err)
	}
	out := new(T)
	if err := json.Unmarshal(b, out); err != nil {
		return nil, fmt.Errorf("core: decode view: %w", err)
	}
	return out, nil
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// stateView puts what the host knows (hs) together with what core owns: the maintenance window, the guidance
// for a release upgrade and whether an install run is going. A host part with no last check (the empty one of a box
// that never checked) has os null and no release upgrade (D-407).
func stateView(hs api.OSState, win maintWindow, busy bool) osStateView {
	pending := make([]osPackageView, len(hs.Pending))
	for i, p := range hs.Pending {
		pending[i] = osPackageView{Name: p.Name, Current: p.Current, New: p.New, Security: p.Security, CVEs: nonNil(p.CVEs)}
	}
	win.Days = nonNil(win.Days)
	v := osStateView{
		Pending: pending, RebootRequired: hs.RebootRequired, RebootReasons: nonNil(hs.RebootReasons),
		RebootScheduledAt: hs.RebootScheduledAt, AutoSecurity: hs.AutoSecurity, Window: win, Busy: busy,
	}
	if !hs.OS.LastCheck.IsZero() {
		v.OS = &osInfoView{
			Distro: hs.OS.Distro, Name: hs.OS.Name, Release: hs.OS.Release, Kernel: hs.OS.Kernel, SupportEnd: hs.OS.SupportEnd,
			ExtendedEnd: hs.OS.ExtendedEnd, BootedAt: hs.OS.BootedAt, LastCheck: hs.OS.LastCheck, Mirrors: nonNil(hs.OS.Mirrors),
		}
		v.ReleaseUpgrade = releaseUpgrade(hs.OS.Distro, hs.OS.Release)
	}
	return v
}

// releaseUpgrade is guidance only: Vedette never runs a release upgrade (D-53). The host supports Ubuntu 24.04
// and 26.04 and Debian 13; only 24.04 has a newer supported release to point at.
func releaseUpgrade(distro, release string) *releaseUpgradeView {
	if distro == "ubuntu" && release == "24.04" {
		return &releaseUpgradeView{To: "Ubuntu 26.04 LTS", Steps: []string{
			"Take a snapshot of the machine, or at least download the Vedette backup under Settings, Data.",
			"Install every pending update on this page first and reboot.",
			"Open a console or SSH session on the box (not this web page) and run: sudo do-release-upgrade",
			"Answer the prompts, let it restart, then check that this page shows the new release and that the health check is green.",
		}}
	}
	return nil
}
