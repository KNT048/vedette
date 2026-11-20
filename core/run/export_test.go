package run

// OnEnded sets the hook called after a run's end is recorded. Call it before Start.
func OnEnded(m *Manager, fn func(id string)) { m.ended = fn }
