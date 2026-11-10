package response

import "time"

// The limits of chat decisions (D-135 (7), (8)): a table of its own, so a flood of links or block list pulls cannot eat it and a flood of
// chat cannot eat theirs; an identity that is on an approver list is never turned away because the table is full; and what a stranger can
// make the box log is bounded (one line per window per identity, and a budget for all identities together).

const chatNoteBudget = 60 // refusal lines of strangers per minute for all identities together

// chatEntry is what the table knows of one identity: its attempts of the last minute, and whether it was ever seen on an approver list.
type chatEntry struct {
	times  []time.Time
	listed bool
}

// chatNote is the window of one identity's refusal lines: when it began and how many refusals it held back.
type chatNote struct {
	start  time.Time
	hidden int
}

// chatAllow counts one attempt of the identity. It reports ok=false when the identity has used its attempts of the last minute, and
// full=true when the table is full and the identity is new: the caller then finds out whether it is on a list and calls again with force.
// A forced attempt is let in and the oldest identity that was never listed is forgotten to make room (if all are listed the table grows
// past its size by the number of listed approvers, which is small).
func (s *Service) chatAllow(key string, force bool) (ok, full bool) {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	now := s.now()
	e := s.chatTimes[key]
	if e == nil {
		if len(s.chatTimes) >= s.chatMax {
			for k, x := range s.chatTimes {
				if len(x.times) == 0 || now.Sub(x.times[len(x.times)-1]) >= time.Minute {
					delete(s.chatTimes, k)
				}
			}
		}
		if len(s.chatTimes) >= s.chatMax {
			if !force {
				return false, true
			}
			var oldest string
			var at time.Time
			for k, x := range s.chatTimes {
				if !x.listed && (oldest == "" || x.times[len(x.times)-1].Before(at)) {
					oldest, at = k, x.times[len(x.times)-1]
				}
			}
			if oldest != "" {
				delete(s.chatTimes, oldest)
			}
		}
		e = &chatEntry{}
		s.chatTimes[key] = e
	}
	keep := e.times[:0]
	for _, t := range e.times {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	e.times = keep
	if len(keep) >= chatPerMin {
		return false, false
	}
	e.times = append(e.times, now)
	return true, false
}

// chatMarkListed remembers that the identity is on an approver list: when the table is full it is the last to be forgotten.
func (s *Service) chatMarkListed(key string) {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	if e := s.chatTimes[key]; e != nil {
		e.listed = true
	}
}

// chatNoteDue says whether a refusal of the identity (kind says which) should be logged now, and how many it held back since its last
// line. The first refusal of a window is logged; the rest are counted and the count goes into the next window's line. The lines of
// all identities together are bounded by chatNoteBudget a minute.
func (s *Service) chatNoteDue(key string) (log bool, hidden int) {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	now := s.now()
	n := s.chatNotes[key]
	if n != nil && now.Sub(n.start) < time.Minute {
		n.hidden++
		return false, 0
	}
	if now.Sub(s.chatNoteWin) >= time.Minute {
		s.chatNoteWin, s.chatNoteN = now, 0
	}
	if n == nil {
		if len(s.chatNotes) >= s.chatMax {
			for k, x := range s.chatNotes {
				if now.Sub(x.start) >= time.Minute && x.hidden == 0 {
					delete(s.chatNotes, k)
				}
			}
			if len(s.chatNotes) >= s.chatMax {
				return false, 0
			}
		}
		n = &chatNote{}
		s.chatNotes[key] = n
	}
	if s.chatNoteN >= chatNoteBudget {
		n.hidden++
		return false, 0
	}
	s.chatNoteN++
	hidden = n.hidden
	n.start, n.hidden = now, 0
	return true, hidden
}

// chatFullDue says whether "chat rate table full" is due in the log (once a minute).
func (s *Service) chatFullDue() bool {
	s.limitMu.Lock()
	defer s.limitMu.Unlock()
	if now := s.now(); now.Sub(s.chatFullAt) >= time.Minute {
		s.chatFullAt = now
		return true
	}
	return false
}
