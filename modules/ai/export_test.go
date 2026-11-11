package ai

// HoldHookTest takes the one place for a hook test and returns the function that gives it back, so a test can make the next one wait.
func (s *Service) HoldHookTest() (release func()) {
	s.testSlot <- struct{}{}
	return func() { <-s.testSlot }
}
