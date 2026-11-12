# Deferred: feat/ai-4c-knowledge (WP-25 slice 4c)

- [ ] GUI wording (Kiên's mock): the Knowledge tab still says "Choose which AI profile builds the index" and warns that a cloud profile "leaves your network", but the index is built on the box with FTS5 and the profile builds nothing (D-209). Reword (and decide whether the profile selector stays) when embeddings come; changing it now is a new story.
- [x] PDF support: Done in feat/ai-4c-pdf (child process via core/pdftext, D-264).
- [x] The story and GUI texts: Done in feat/ai-4c-pdf (mock, picker, ai.json). Seeded demo document `office-network-diagram.pdf` stays; the e2e-real fixme text is the e2e owner's (see feat-ai-4c-pdf.md).
- [ ] Asking the box (slice 5, `ask-my-data`) will call `RunJob` and gets the documents for free; give it a `KnowledgeQuery` (the question is already the default).
