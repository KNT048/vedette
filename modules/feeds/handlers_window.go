package feeds

import (
	"context"
	"database/sql"

	"github.com/knt048/vedette/core/api/oas"
	"github.com/knt048/vedette/core/audit"
)

// ---------- S-FEED-4: the reporting window (window.go)

func windowView(w Window) (every bool, at oas.NilDateTime, by oas.NilString) {
	at, by = oas.NilDateTime{Null: true}, oas.NilString{Null: true}
	if !w.Since.IsZero() {
		at, by = oas.NewNilDateTime(w.Since), oas.NewNilString(w.By)
	}
	return w.EveryAge, at, by
}

// FeedsGetFeedsWindow implements GET /feeds/window: which CVEs the box reports.
func (h *FeedHandlers) FeedsGetFeedsWindow(ctx context.Context) (*oas.FeedsGetFeedsWindowOK, error) {
	w, err := h.s.st.Window(ctx, h.s.now())
	if err != nil {
		return nil, err
	}
	every, at, by := windowView(w)
	return &oas.FeedsGetFeedsWindowOK{EveryAge: every, WindowDays: windowDays, ChangedAt: at, ChangedBy: by}, nil
}

// FeedsPutFeedsWindow implements PUT /feeds/window (admin): report CVEs of every age, or the window (the default). A change is audited
// and makes findings match again at once: switched off, the older CVEs are outside the window from now on (their open findings close
// as outside_window) and the pull job's prune drops them from the data at its next check; switched on, the next catalogue pulls read
// NVD's whole set and the CVE Program's whole list once more and keep every record (everyAgeOwed, recordsEveryAge).
func (h *FeedHandlers) FeedsPutFeedsWindow(ctx context.Context, req *oas.FeedsPutFeedsWindowReq) (*oas.FeedsPutFeedsWindowOK, error) {
	if err := h.s.ready(ctx); err != nil {
		return nil, err
	}
	p, err := actor(ctx)
	if err != nil {
		return nil, err
	}
	now := h.s.now()
	changed := false
	err = h.s.DB.Write(ctx, func(tx *sql.Tx) error {
		cur, err := windowOf(ctx, tx, now)
		if err != nil {
			return err
		}
		if changed = cur.EveryAge != req.EveryAge; !changed {
			return nil
		}
		if err := saveWindow(ctx, tx, req.EveryAge, p.Email, now); err != nil {
			return err
		}
		detail := "off: CVEs of the last 12 months, and older ones exploited in the wild or with a new public exploit"
		if req.EveryAge {
			detail = "on: CVEs of every age"
		}
		return h.s.Audit.Append(ctx, tx, audit.Entry{User: p.Email, Action: "feeds.report_window", Target: "CVEs of every age", Detail: detail})
	})
	if err != nil {
		return nil, err
	}
	if changed { // findings' match pass reads the window again (the CVEs it sets aside, the findings it closes or opens)
		h.s.publish(ctx, EventRangesUpdated, RangesUpdatedEvent{CVEs: []string{}, Catalogue: true})
	}
	w, err := h.s.st.Window(ctx, now)
	if err != nil {
		return nil, err
	}
	every, at, by := windowView(w)
	return &oas.FeedsPutFeedsWindowOK{EveryAge: every, WindowDays: windowDays, ChangedAt: at, ChangedBy: by}, nil
}
