package ai

import "context"

// HoldHookTest takes the one place for a hook test and returns the function that gives it back, so a test can make the next one wait.
func (s *Service) HoldHookTest() (release func()) {
	s.testSlot <- struct{}{}
	return func() { <-s.testSlot }
}

// MemoryLinesForCall returns the memory lines a call of the job would send (after the hooks) and the ids left out.
func (s *Service) MemoryLinesForCall(ctx context.Context, job Job) (sent string, left []string, err error) {
	mc, err := s.memoryForCall(ctx, s.Hooks(), job)
	return mc.block.Text, mc.left, err
}
