package notify

import (
	"context"
	"time"
	"unicode/utf8"

	"github.com/kiennt048/vedette/modules/notify/channel"
)

// SendRecord is one delivery attempt (contract.ts SendRecord, table notify_send).
type SendRecord struct {
	ID      string
	Channel channel.Type
	To      string
	At      time.Time
	OK      bool
	Error   string // short and secret-free (the adapters guarantee it); empty when OK
}

const maxRecordError = 300

// Deliver makes one attempt through s and always returns its record (INV-6:
// there is no attempt without a record). Now is the injected clock. Whether to
// try at all (min_severity, quiet hours, grouping) is decided before, by Decide
// and Group.
func Deliver(ctx context.Context, id string, s channel.Sender, m channel.Message, now func() time.Time) SendRecord {
	rec := SendRecord{ID: id, Channel: s.Type(), To: s.Dest()}
	r, err := s.Send(ctx, m)
	rec.At = now()
	if r.To != "" {
		rec.To = r.To
	}
	if err != nil {
		msg := err.Error()
		if utf8.RuneCountInString(msg) > maxRecordError {
			msg = string([]rune(msg)[:maxRecordError-1]) + "…"
		}
		rec.Error = msg
		return rec
	}
	rec.OK = true
	return rec
}
