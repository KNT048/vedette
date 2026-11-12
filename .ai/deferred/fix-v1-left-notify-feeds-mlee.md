# Deferred — fix/v1-left-notify-feeds-mlee

- [ ] 2026-11-13 — the GUI mock CSV parser (`web/src/features/feeds/parsers.ts` `parseCsvLines`) has no unclosed-quote recovery: a quote never closed swallows the rest of the sample into one record, while the Go parser flags that record and re-reads the rest with quotes literal — vì sao để sau: mock-only difference on a malformed sample, no story depends on it — ở đâu: web/src/features/feeds/parsers.ts
