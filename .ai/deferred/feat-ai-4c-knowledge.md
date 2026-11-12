# Deferred: feat/ai-4c-knowledge (WP-25 slice 4c)

- [x] PDF support: Done in feat/ai-4c-pdf (child process via core/pdftext, D-264).
- [x] The story and GUI texts: Done in feat/ai-4c-pdf (mock, picker, ai.json). Seeded demo document `office-network-diagram.pdf` stays; the e2e-real fixme text is the e2e owner's (see feat-ai-4c-pdf.md).
- [ ] Asking the box (slice 5, `ask-my-data`) will call `RunJob` and gets the documents for free; give it a `KnowledgeQuery` (the question is already the default).
- [ ] 2026-11-12 — the 400 `no_index_profile` message ('Choose which AI profile builds the index...') in modules/ai/knowledge.go, docs/API_CONVENTIONS.md and the ai mock still says the profile builds the index (D-209: it builds nothing); reword with the next ai contract change — ở đâu: modules/ai/knowledge.go:269, web/src/features/ai/harness-mocks.ts:162.
