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

// WaitIndexed waits until every document that was handed to the indexer is read.
func (s *Service) WaitIndexed() { s.indexing.Wait() }

// HoldIndexer takes the one place of the indexer and returns the function that gives it back, so a test can keep a document waiting.
func (s *Service) HoldIndexer() (release func()) {
	s.indexSlot <- struct{}{}
	return func() { <-s.indexSlot }
}

// KnowledgeForCall returns the text of the pieces a call of the job would carry for the search text (after the hooks), the pieces
// used ("<document id>:<number>") and the ones a hook kept out.
func (s *Service) KnowledgeForCall(ctx context.Context, job Job, query string) (sent string, used, left []string, err error) {
	kc, err := s.knowledgeForCall(ctx, s.Hooks(), job, query)
	return kc.block.Text, kc.refs, kc.left, err
}
