package findings

import (
	"context"
	"time"
)

// mark is a person's handling or reopen of one finding as the finding page sends it (POST /findings/handle with its id, POST
// /findings/{id}/reopen), read back in the older read model: action is a Resolution or "reopen".
func (s *Service) mark(ctx context.Context, id, action, note, user string) (Record, error) {
	if action == "reopen" {
		if _, err := s.Reopen(ctx, id, note, user); err != nil {
			return Record{}, err
		}
		return s.Get(ctx, id)
	}
	if _, _, err := s.HandleConfirmed(ctx, []string{id}, Resolution(action), note, time.Time{}, user); err != nil { // after a still_reported answer, if any
		return Record{}, err
	}
	return s.Get(ctx, id)
}
