package main

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/knt048/vedette/core/store"
	"github.com/knt048/vedette/modules/exposure"
	"github.com/knt048/vedette/modules/feeds"
	"github.com/knt048/vedette/modules/findings"
	"github.com/knt048/vedette/modules/notify"
)

// Sizes of the texts of a vulnerability notice. notify accepts up to 4000 characters; a message is read on a phone,
// so the adapter stays well under that. The KEV texts come from a feed on the internet: data, not instructions.
const (
	noticeProductMax = 120
	noticeReasonsMax = 400
	noticeActionMax  = 600
)

// notifyFindings implements notify.FindingDirectory (S-ALERT-1): one finding as findings.View reads it now. The status name, its
// meaning and the reasons are the ones the finding page shows (findings.StatusName, StatusMeaning, View.ReasonsLine); the brief of the
// CVE (feeds.Brief) adds, when the CVE is on an exploited list, the product name and the action the list requires, and the inventory the device names through notifyDevices. findings and
// feeds are read through deps at call time: notify is built before them (see buildServices).
type notifyFindings struct{ d *deps }

func (n notifyFindings) Finding(ctx context.Context, id string) (notify.FindingInfo, bool, error) {
	if n.d.Findings == nil {
		return notify.FindingInfo{}, false, nil
	}
	v, err := n.d.Findings.View(ctx, id)
	if errors.Is(err, findings.ErrNotFound) { // deleted between the event and now (the device went away)
		return notify.FindingInfo{}, false, nil
	}
	if err != nil {
		return notify.FindingInfo{}, false, err
	}
	if v.Device.Ignored { // a person ignored the device: nothing about it is sent (the urgency pass tells no rise of it either)
		return notify.FindingInfo{}, false, nil
	}
	f := v.Finding
	var product, action string // the brief of the CVE: its product in plain words and the action its exploited list requires
	if fs, err := feedsService(*n.d); err == nil {
		b, ok, err := fs.Store().Brief(ctx, f.CVE)
		if err != nil {
			return notify.FindingInfo{}, false, err
		}
		if ok && len(b.Lists) > 0 {
			product = b.Display
			for _, l := range b.Lists {
				if action = l.RequiredAction; action != "" {
					break
				}
			}
		}
	}
	info := notify.FindingInfo{CVE: plainText(f.CVE, 40), Severity: noticeSeverity(v), Open: f.Open(), Layer: f.Urgency, Exploited: f.Exploited(),
		Status: findings.StatusName(f.Urgency), Meaning: findings.StatusMeaning(f.Urgency),
		Reasons: plainText(v.ReasonsLine(), noticeReasonsMax), Verification: plainText(v.VerificationLine(), noticeReasonsMax)}
	info.Product = cmp.Or(plainText(product, noticeProductMax), plainText(lineName(v), noticeProductMax), "A product on your network")
	info.Action = noticeAction(v, action)
	if n.d.Inventory == nil {
		return info, true, nil // no device name: notify sends nothing for a finding that matched no device
	}
	name, ok, err := notifyDevices{n.d.Inventory}.DeviceName(ctx, f.AssetID)
	if err != nil {
		return notify.FindingInfo{}, false, err
	}
	if ok && name != "" {
		info.Devices = []string{plainText(name, 120)}
	}
	// A device nobody approved yet is marked the way the finding is in the app: "Device not added yet", also when it has no name
	if refs, err := n.d.Inventory.DeviceRefs(ctx, []string{f.AssetID}); err == nil {
		if r, found := refs[f.AssetID]; found && !r.Approved && !r.Ignored {
			label := plainText(name, 100)
			if label == "" && r.IP != "" && r.IP != "—" {
				label = plainText(r.IP, 100)
			}
			if label == "" {
				label = "a device"
			}
			info.Devices = []string{label + " (device not added yet)"}
			info.Note = "The device is not added yet: open the finding to add it or ignore it."
		}
	}
	return info, true, nil
}

// noticeAction is the "What to do first" of a finding's notice: the fix the finding page shows when it names a release to install
// ("Update VMware ESXi from 8.0.3 to 8.0 U3j."), else the action the CVE's exploited list requires (CISA's text), else the finding's own
// steps. The fix comes first: it is the one step that ends the finding, the list's action is the same for every CVE on the list.
func noticeAction(v findings.View, listAction string) string {
	fx := v.Finding.Fix
	if findings.FixWords(fx, v.FixProduct(), "") != "" {
		return plainText(v.FixText(), noticeActionMax)
	}
	return cmp.Or(plainText(listAction, noticeActionMax),
		"Open the finding in Vedette and follow its steps: update the software, or limit who can reach the device.")
}

// noticeSeverity is the severity class of a notice: the band of the CVE's score as the finding page shows it, medium while the CVE has no
// score.
func noticeSeverity(v findings.View) notify.Severity {
	if v.Severity == nil {
		return notify.Medium
	}
	switch findings.SeverityBand(*v.Severity) {
	case "critical":
		return notify.Critical
	case "high":
		return notify.High
	case "medium":
		return notify.Medium
	case "low":
		return notify.Low
	}
	return notify.Info
}

// lineName names the product a finding is on: the device's software line as the Devices page shows it, else the catalogue's name of the
// finding's product; "" when neither is known.
func lineName(v findings.View) string {
	if v.Line != nil && strings.TrimSpace(v.Line.Display) != "" {
		return v.Line.Display
	}
	if p, ok := findings.ProductOf(v.Finding); ok {
		return p.Display
	}
	return ""
}

// notifySignals implements notify.SignalDirectory over feeds' signals and the findings' table: the CVEs a source reports as exploited
// that no device has a finding for.
type notifySignals struct{ d *deps }

// unmatchedChunk is how many CVEs one read of the facts takes.
const unmatchedChunk = 500

func (n notifySignals) UnmatchedExploited(ctx context.Context, since time.Time) (int, error) {
	if n.d.DB == nil {
		return 0, nil
	}
	q := n.d.DB.Reader()
	rows, err := q.QueryContext(ctx, `SELECT DISTINCT s.cve FROM feeds_signal s
WHERE s.kind = 'exploited' AND s.qualifies = 1 AND s.stored_at >= ? AND NOT EXISTS (SELECT 1 FROM fnd_finding f WHERE f.cve = s.cve)`,
		store.FormatTS(since))
	if err != nil {
		return 0, err
	}
	var cves []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			_ = rows.Close()
			return 0, err
		}
		cves = append(cves, c)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil || len(cves) == 0 {
		return 0, err
	}
	// The urgency reader drops the sources that are switched off, and marks what came with a source's first load: a first load is not news.
	// Every candidate is read (in chunks), so what the filter drops can never hide a CVE behind a cap.
	count := 0
	reader := feeds.NewUrgencyReader(q)
	for chunk := range slices.Chunk(cves, unmatchedChunk) {
		facts, err := reader.Facts(ctx, chunk)
		if err != nil {
			return 0, err
		}
		for _, c := range chunk {
			for _, g := range facts[c].Signals {
				if g.Kind == findings.SignalExploited && g.Qualifies && !g.FirstLoad && !g.StoredAt.Before(since) {
					count++
					break
				}
			}
		}
	}
	return count, nil
}

// notifyUpdates is the daily summary's count of new findings with no sign of exploitation (notify SummarySources.Updates): the
// findings first seen in [from, to) that are open now at "update recommended", and the devices they are on. One read on
// fnd_finding_state_urgency_ix.
func notifyUpdates(d *deps) func(ctx context.Context, from, to time.Time) (int, int, error) {
	return func(ctx context.Context, from, to time.Time) (found, devices int, err error) {
		if d.DB == nil {
			return 0, 0, nil
		}
		err = d.DB.Reader().QueryRowContext(ctx, `SELECT count(*), count(DISTINCT asset_id) FROM fnd_finding
WHERE state = 'open' AND urgency = ? AND first_seen >= ? AND first_seen < ?`, findings.UrgencyUpdate, store.FormatTS(from), store.FormatTS(to)).Scan(&found, &devices)
		return found, devices, err
	}
}

// notifyExposureNews is the daily summary's count of what external scans found new that did not alert (notify SummarySources.Exposure,
// exposure NewSince); nothing while the exposure module is off. The exposure service is read when asked (it is built after notify).
func notifyExposureNews(d *deps) func(ctx context.Context, from, to time.Time) (int, int, error) {
	return func(ctx context.Context, from, to time.Time) (int, int, error) {
		if d.DB == nil || d.Reg != nil && !d.Reg.Enabled(exposure.ModuleID) {
			return 0, 0, nil
		}
		return exposureService(*d).NewSince(ctx, from, to)
	}
}

// plainText makes feed text safe to show: control characters and line breaks become spaces, invisible format characters
// (Unicode Cf) go, runs of spaces collapse, and the result is cut to max characters. Adapters render it as text, never as markup.
func plainText(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r) || r == utf8.RuneError:
			return ' '
		case unicode.Is(unicode.Cf, r): // invisible format characters: bidi overrides (U+202E), zero-width ones
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > limit {
		return strings.TrimSpace(string(r[:limit-1])) + "…"
	}
	return s
}
