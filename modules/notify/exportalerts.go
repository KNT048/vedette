package notify

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/knt048/vedette/core/store"
)

// alertRow is one line of the "alerts" log source (core INV-13, GET /core/logs/export): one delivery attempt. It carries what the History
// screen shows. It leaves out `message` (the whole message as sent, kept for a resend) and `recipient` (the address of an approver): a
// download is for the auditor, and a message can name a person or a device in full.
type alertRow struct {
	ID      string  `json:"id"`
	Kind    string  `json:"kind"`
	RefID   string  `json:"ref_id"`
	Channel string  `json:"channel"`
	To      string  `json:"to"`
	At      string  `json:"at"`
	OK      bool    `json:"ok"`
	Error   *string `json:"error"`
	What    string  `json:"what"`
	Link    string  `json:"link"`
}

// ExportAlerts is the "alerts" source of GET /core/logs/export: the delivery log (notify_send) from through to, both ends inclusive, oldest
// first, one JSON object per line; a zero time is open. Not a hash chain. A link is cut to its path without query or fragment, and
// the path of an approval link (/approve/<token>) to "/approve/…": nothing that works as a credential is written (the stored link is the
// in-app page, never a token, but the file does not rely on that). A destination that is a URL is cut to scheme://host.
func (s *Service) ExportAlerts(ctx context.Context, from, to time.Time, w io.Writer) error {
	lo, hi := "", ""
	if !from.IsZero() {
		lo = store.FormatTS(from)
	}
	if !to.IsZero() {
		hi = store.FormatTS(to)
	}
	rows, err := s.cfg.DB.Reader().QueryContext(ctx, `SELECT id, kind, ref_id, channel, "to", at, ok, error, what, link FROM notify_send
		WHERE (? = '' OR at >= ?) AND (? = '' OR at <= ?) ORDER BY at, id`, lo, lo, hi, hi)
	if err != nil {
		return fmt.Errorf("notify: export alerts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	enc := json.NewEncoder(w)
	for rows.Next() {
		var a alertRow
		var e sql.NullString
		if err := rows.Scan(&a.ID, &a.Kind, &a.RefID, &a.Channel, &a.To, &a.At, &a.OK, &e, &a.What, &a.Link); err != nil {
			return fmt.Errorf("notify: export alerts: %w", err)
		}
		if e.Valid {
			a.Error = &e.String
		}
		a.To, a.Link = hostOnly(a.To), pathOnly(a.Link)
		if err := enc.Encode(a); err != nil { // one object and a newline
			return err
		}
	}
	return rows.Err()
}

// hostOnly cuts a URL to scheme://host (userinfo, path, query and fragment go); text that is not a URL stays.
func hostOnly(s string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return strings.SplitN(s, "://", 2)[0] + "://…"
	}
	return u.Scheme + "://" + u.Host
}

// pathOnly cuts a link to its path: no scheme, host, query or fragment, and nothing after /approve/.
func pathOnly(s string) string {
	p := s
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return ""
		}
		p = u.Path
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if i := strings.Index(p, "/approve/"); i >= 0 {
		p = p[:i] + "/approve/…"
	}
	return p
}
