package findings

import (
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func suspected() Finding {
	f, _ := NewFinding(Match{CVE: "CVE-2022-27593", SoftwareDisplay: "Photo Station", Basis: BasisProduct, Confidence: ConfProduct, Severity: SeverityHigh,
		Evidence: Evidence{Summary: "s"}}, t0)
	return f
}

func scanEvidence() Evidence {
	return Evidence{Summary: "matched", Template: "CVE-2022-27593", Request: "GET /photo/", Response: "200", CheckedAt: t0.Add(time.Hour)}
}

func TestNewFinding(t *testing.T) {
	t.Parallel()
	f, h := NewFinding(Match{Basis: BasisVersion, Confidence: ConfVersion, Severity: SeverityCritical, SoftwareDisplay: "X"}, t0)
	if f.Status != StatusSuspected || f.Basis != BasisVersion || f.Evidence == nil || !f.Evidence.CheckedAt.Equal(t0) || f.Validate() != nil {
		t.Fatalf("finding = %+v err=%v", f, f.Validate())
	}
	if h.Action != "created" || h.User != SystemUser || h.Note != "Matched version of X" || !h.TS.Equal(t0) {
		t.Fatalf("history = %+v", h)
	}
	if _, h := NewFinding(Match{Basis: BasisProduct, SoftwareDisplay: "Photo Station"}, t0); h.Note != "Matched product Photo Station" {
		t.Fatalf("note = %q", h.Note)
	}
}

func TestFinding_Apply(t *testing.T) {
	t.Parallel()
	closed := func(s Status) Finding { f := suspected(); f.Status = s; return f }
	tests := []struct {
		name   string
		from   Finding
		action Action
		note   string
		want   Status
		hist   string
		err    *APIError
	}{
		{"patched from suspected", suspected(), ActionPatched, "", StatusPatched, "patched", nil},
		{"mitigated with note", suspected(), ActionMitigated, "  firewall rule  ", StatusMitigated, "mitigated", nil},
		{"patched from false_positive", closed(StatusFalsePositive), ActionPatched, "", StatusPatched, "patched", nil},
		{"false_positive with note", suspected(), ActionFalsePositive, "not our build", StatusFalsePositive, "false_positive", nil},
		{"not_relevant with note", suspected(), ActionNotRelevant, "lab only", StatusNotRelevant, "not_relevant", nil},
		{"false_positive no note", suspected(), ActionFalsePositive, "", "", "", ErrNoteRequired},
		{"false_positive short note", suspected(), ActionFalsePositive, " ab ", "", "", ErrNoteRequired},
		{"not_relevant blank note", suspected(), ActionNotRelevant, "     ", "", "", ErrNoteRequired},
		{"note exactly 3 runes", suspected(), ActionNotRelevant, "ngu", StatusNotRelevant, "not_relevant", nil},
		{"note 500 runes", suspected(), ActionPatched, strings.Repeat("é", 500), StatusPatched, "patched", nil},
		{"note 501 runes", suspected(), ActionPatched, strings.Repeat("é", 501), "", "", ErrNoteTooLong},
		{"too long beats required", suspected(), ActionFalsePositive, strings.Repeat("x", 501), "", "", ErrNoteTooLong},
		{"bad action", suspected(), Action("close"), "", "", "", ErrBadAction},
		{"empty action", suspected(), Action(""), "", "", "", ErrBadAction},
		{"reopen open suspected", suspected(), ActionReopen, "", "", "", ErrAlreadyOpen},
		{"reopen open confirmed", closed(StatusConfirmed), ActionReopen, "", "", "", ErrAlreadyOpen},
		{"reopen closed product basis", closed(StatusPatched), ActionReopen, "back", StatusSuspected, "reopened", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, h, err := tt.from.Apply(tt.action, tt.note, "ann@example.com", t0)
			if tt.err != nil {
				var ae *APIError
				if !errors.Is(err, tt.err) || !errors.As(err, &ae) || ae != tt.err {
					t.Fatalf("err = %v, want %v", err, tt.err)
				}
				if got != tt.from || h != (HistoryEntry{}) {
					t.Fatalf("state changed on error: %+v %+v", got, h)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Status != tt.want || h.Action != tt.hist || h.User != "ann@example.com" || !h.TS.Equal(t0) {
				t.Fatalf("status %s history %+v", got.Status, h)
			}
			if got.Validate() != nil {
				t.Fatalf("invalid result: %v", got.Validate())
			}
		})
	}
}

func TestFinding_Apply_ResolvedFields(t *testing.T) {
	t.Parallel()
	f, _, err := suspected().Apply(ActionPatched, " updated to 6.1.2 ", "ann", t0)
	if err != nil || f.ResolvedBy != "ann" || !f.ResolvedAt.Equal(t0) || f.ResolutionNote != "updated to 6.1.2" {
		t.Fatalf("%+v %v", f, err)
	}
	r, h, err := f.Apply(ActionReopen, "", "bob", t0.Add(time.Hour))
	if err != nil || r.ResolvedBy != "" || !r.ResolvedAt.IsZero() || r.ResolutionNote != "" || r.Status != StatusSuspected || h.Note != "" {
		t.Fatalf("%+v %+v %v", r, h, err)
	}
}

func TestFinding_Apply_ReopenScanBasisIsConfirmed(t *testing.T) {
	t.Parallel()
	out, err := suspected().ConfirmFromScan(scanEvidence(), t0)
	if err != nil {
		t.Fatal(err)
	}
	closed, _, _ := out.Finding.Apply(ActionPatched, "", "ann", t0)
	r, _, err := closed.Apply(ActionReopen, "", "ann", t0)
	if err != nil || r.Status != StatusConfirmed || r.Validate() != nil {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestFinding_ConfirmFromScan(t *testing.T) {
	t.Parallel()
	ev := scanEvidence()
	tests := []struct {
		name   string
		from   Status
		want   Status
		hist   string // "" = no row
		notify bool
	}{
		{"suspected", StatusSuspected, StatusConfirmed, "confirmed", true},
		{"confirmed again", StatusConfirmed, StatusConfirmed, "rescanned", false},
		{"false_positive stays", StatusFalsePositive, StatusFalsePositive, "rescanned", true},
		{"not_relevant stays", StatusNotRelevant, StatusNotRelevant, "rescanned", true},
		{"patched is reopened", StatusPatched, StatusConfirmed, "reopened", true},
		{"mitigated is reopened", StatusMitigated, StatusConfirmed, "reopened", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := suspected()
			f.Status = tt.from
			if tt.from == StatusConfirmed {
				f.Basis, f.Evidence = BasisScan, &Evidence{Template: "old", CheckedAt: t0}
				f.Confidence = 0.97
			}
			if tt.from == StatusPatched {
				f.ResolvedBy, f.ResolvedAt, f.ResolutionNote = "ann", t0, "done"
			}
			out, err := f.ConfirmFromScan(ev, t0.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if out.Finding.Status != tt.want || out.Notify != tt.notify {
				t.Fatalf("status %s notify %v", out.Finding.Status, out.Notify)
			}
			if len(out.History) != 1 || out.History[0].Action != tt.hist || out.History[0].User != SystemUser {
				t.Fatalf("history = %+v", out.History)
			}
			g := out.Finding
			if g.Basis != BasisScan || g.Confidence < ConfScan || g.Evidence.Template != ev.Template || g.ResolvedBy != "" || !g.ResolvedAt.IsZero() || g.Validate() != nil {
				t.Fatalf("finding = %+v err=%v", g, g.Validate())
			}
		})
	}
}

func TestFinding_ConfirmFromScan_KeepsHigherConfidence(t *testing.T) {
	t.Parallel()
	f := suspected()
	f.Confidence = 0.99
	out, _ := f.ConfirmFromScan(scanEvidence(), t0)
	if out.Finding.Confidence != 0.99 {
		t.Fatalf("confidence lowered to %v", out.Finding.Confidence)
	}
}

func TestFinding_ConfirmFromScan_RejectsBadEvidence(t *testing.T) {
	t.Parallel()
	good := scanEvidence()
	mk := func(edit func(*Evidence)) Evidence { e := good; edit(&e); return e }
	for name, ev := range map[string]Evidence{
		"no template":   mk(func(e *Evidence) { e.Template = "" }),
		"no time":       mk(func(e *Evidence) { e.CheckedAt = time.Time{} }),
		"huge template": mk(func(e *Evidence) { e.Template = strings.Repeat("x", maxTemplate+1) }),
	} {
		f := suspected()
		out, err := f.ConfirmFromScan(ev, t0)
		if !errors.Is(err, ErrInvalidEvidence) || out.Finding != f || len(out.History) != 0 {
			t.Errorf("%s: err=%v out=%+v", name, err, out)
		}
	}
}

func TestFinding_ApplyMatch(t *testing.T) {
	t.Parallel()
	ver := Match{Basis: BasisVersion, Confidence: ConfVersion, Evidence: Evidence{Summary: "v"}}
	f := suspected()
	up := f.ApplyMatch(ver)
	if up.Basis != BasisVersion || up.Confidence != ConfVersion || up.Evidence.Summary != "v" || up.Status != StatusSuspected {
		t.Fatalf("upgrade failed: %+v", up)
	}
	if down := up.ApplyMatch(Match{Basis: BasisProduct, Confidence: ConfProduct}); down.Basis != BasisVersion {
		t.Fatalf("basis went down: %+v", down)
	}
	closed, _, _ := f.Apply(ActionPatched, "", "ann", t0)
	if got := closed.ApplyMatch(ver); got != closed {
		t.Fatalf("closed finding changed by a match: %+v", got)
	}
	scan, _ := f.ConfirmFromScan(scanEvidence(), t0)
	if got := scan.Finding.ApplyMatch(ver); got != scan.Finding {
		t.Fatalf("scan basis overwritten: %+v", got)
	}
}

func TestFinding_Validate(t *testing.T) {
	t.Parallel()
	ok := suspected()
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	conf := func(f Finding) Finding {
		f.Status, f.Basis, f.Evidence = StatusConfirmed, BasisScan, &Evidence{Template: "t", CheckedAt: t0}
		return f
	}
	bad := map[string]Finding{
		"unknown status":          func() Finding { f := ok; f.Status = "open"; return f }(),
		"unknown basis":           func() Finding { f := ok; f.Basis = "guess"; return f }(),
		"confidence high":         func() Finding { f := ok; f.Confidence = 1.01; return f }(),
		"confidence negative":     func() Finding { f := ok; f.Confidence = -0.1; return f }(),
		"confidence NaN":          func() Finding { f := ok; f.Confidence = nan(); return f }(),
		"confirmed by version":    func() Finding { f := conf(ok); f.Basis = BasisVersion; return f }(),
		"confirmed no evidence":   func() Finding { f := conf(ok); f.Evidence = nil; return f }(),
		"confirmed no template":   func() Finding { f := conf(ok); f.Evidence = &Evidence{CheckedAt: t0}; return f }(),
		"confirmed no checked_at": func() Finding { f := conf(ok); f.Evidence = &Evidence{Template: "t"}; return f }(),
		"suspected by scan":       func() Finding { f := ok; f.Basis = BasisScan; return f }(),
	}
	for name, f := range bad {
		if f.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := conf(ok).Validate(); err != nil {
		t.Fatalf("valid confirmed rejected: %v", err)
	}
}

func nan() float64 { var z float64; return z / z }

func FuzzApply(f *testing.F) {
	f.Add("patched", "note", "ann")
	f.Add("reopen", "", "")
	f.Add("false_positive", "ctl\x00end", "ann")
	f.Fuzz(func(t *testing.T, action, note, user string) {
		start := suspected()
		got, h, err := start.Apply(Action(action), note, user, t0)
		if err != nil {
			var ae *APIError
			if !errors.As(err, &ae) || got != start {
				t.Fatalf("bad error or state changed: %v %+v", err, got)
			}
			return
		}
		if got.Validate() != nil || h.Action == "" {
			t.Fatalf("invalid result %+v %+v", got, h)
		}
		if _, _, err := got.Apply(Action(action), note, user, t0); err != nil && !errors.Is(err, ErrAlreadyOpen) {
			t.Fatalf("second apply: %v", err)
		}
	})
}

func TestFinding_ConfirmFromScan_ClosedByPersonNotifiesOncePerTemplate(t *testing.T) {
	t.Parallel()
	closed, _, _ := suspected().Apply(ActionFalsePositive, "lab box", "ann", t0)
	first, err := closed.ConfirmFromScan(scanEvidence(), t0)
	if err != nil || !first.Notify || first.Finding.Status != StatusFalsePositive || first.Finding.Validate() != nil {
		t.Fatalf("first: %+v err=%v", first, err)
	}
	later := scanEvidence()
	later.CheckedAt = later.CheckedAt.Add(24 * time.Hour)
	again, err := first.Finding.ConfirmFromScan(later, t0)
	if err != nil || again.Notify || len(again.History) != 0 || again.Finding != first.Finding {
		t.Fatalf("same template must stay quiet: %+v err=%v", again, err)
	}
	other := later
	other.Template = "another-template"
	third, err := first.Finding.ConfirmFromScan(other, t0)
	if err != nil || !third.Notify || third.Finding.Status != StatusFalsePositive {
		t.Fatalf("new template must notify: %+v err=%v", third, err)
	}
	// a person can still reopen it, and it comes back confirmed with the scan evidence
	re, _, err := first.Finding.Apply(ActionReopen, "", "ann", t0)
	if err != nil || re.Status != StatusConfirmed || re.Validate() != nil {
		t.Fatalf("reopen: %+v err=%v", re, err)
	}
}

func TestFinding_ConfirmFromScan_TruncatesLargeEvidence(t *testing.T) {
	t.Parallel()
	ev := scanEvidence()
	ev.Response = strings.Repeat("é", maxEvidenceField) // 2 bytes per rune, cut must not split one
	ev.Request = strings.Repeat("x", maxEvidenceField+1)
	ev.Summary = strings.Repeat("y", 10)
	out, err := suspected().ConfirmFromScan(ev, t0)
	if err != nil || out.Finding.Status != StatusConfirmed {
		t.Fatalf("large evidence lost the confirmation: %+v err=%v", out, err)
	}
	e := out.Finding.Evidence
	for name, s := range map[string]string{"response": e.Response, "request": e.Request} {
		if len(s) > maxEvidenceField || !strings.HasSuffix(s, truncMarker) || !utf8.ValidString(s) {
			t.Errorf("%s: len %d valid=%v", name, len(s), utf8.ValidString(s))
		}
	}
	if e.Summary != ev.Summary {
		t.Error("small field changed")
	}
}

func TestFinding_Apply_NoteLengthIsUTF16LikeTheGUI(t *testing.T) {
	t.Parallel()
	// JS: "😀".length === 2, so 250 emoji are exactly 500 units and 251 are too long.
	if _, _, err := suspected().Apply(ActionPatched, strings.Repeat("😀", 250), "u", t0); err != nil {
		t.Fatalf("250 emoji: %v", err)
	}
	if _, _, err := suspected().Apply(ActionPatched, strings.Repeat("😀", 251), "u", t0); !errors.Is(err, ErrNoteTooLong) {
		t.Fatalf("251 emoji: %v", err)
	}
	// one emoji is 2 units: below the 3-unit minimum, two are enough
	if _, _, err := suspected().Apply(ActionFalsePositive, "😀", "u", t0); !errors.Is(err, ErrNoteRequired) {
		t.Fatalf("1 emoji: %v", err)
	}
	if _, _, err := suspected().Apply(ActionFalsePositive, "😀😀", "u", t0); err != nil {
		t.Fatalf("2 emoji: %v", err)
	}
	// JS trims U+FEFF and U+00A0 but not U+0085
	if _, _, err := suspected().Apply(ActionFalsePositive, "\uFEFF\u00A0ab\u00A0", "u", t0); !errors.Is(err, ErrNoteRequired) {
		t.Fatalf("padded 2-char note: %v", err)
	}
	if _, _, err := suspected().Apply(ActionFalsePositive, "\u0085ab", "u", t0); err != nil {
		t.Fatalf("U+0085 counts as a character in JS: %v", err)
	}
}

func TestContract_PRE2_ScanEvidenceMustBeText(t *testing.T) {
	t.Parallel()
	f, _ := NewFinding(Match{Basis: BasisProduct, SoftwareDisplay: "X"}, t0)
	for name, edit := range map[string]func(*Evidence){
		"nul template": func(e *Evidence) { e.Template = "a\x00b" },
		"bad template": func(e *Evidence) { e.Template = "a\xffb" },
		"nul summary":  func(e *Evidence) { e.Summary = "a\x00b" },
		"bad summary":  func(e *Evidence) { e.Summary = "\xc3\x28" },
		"nul request":  func(e *Evidence) { e.Request = "GET\x00/" },
		"bad response": func(e *Evidence) { e.Response = "\xff" },
	} {
		ev := scanEvidence()
		edit(&ev)
		out, err := f.ConfirmFromScan(ev, t0)
		if !errors.Is(err, ErrInvalidEvidence) || out.Finding.Status != StatusSuspected || len(out.History) != 0 {
			t.Errorf("%s: err=%v out=%+v", name, err, out)
		}
	}
}
