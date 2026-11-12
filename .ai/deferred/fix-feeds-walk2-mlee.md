# Deferred — fix/feeds-walk2-mlee

- [ ] 2026-11-12 — CSV samples in the parse test still number data rows after the header and comments, not lines of the pasted sample (plain lists now use line numbers, walk 2) — vì sao để sau: needs line tracking in parseCSV including its unclosed-quote recovery path — ở đâu: modules/feeds/extract.go parseCSV — owner: feeds
