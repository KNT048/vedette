# Deferred: feat/ai-4c-pdf

- [ ] A PDF that is password-protected, damaged or too complex still shows as "Ready, 0 chunks" in the Knowledge list; the reason (the password sentence) is only in the audit row `ai.knowledge.failed`, because the file is read in the background indexer, not in the upload request (the existing deferred line about showing the reason in the list covers it). Needs an optional field in the list (contract change, Kiên's GUI).
- [ ] PDF fuzz seeds / a PDF sample set for the Go readers: the PDF is read in the child (`core/pdftext` tests already hold the hostile set); nothing fuzzes `pdfText` mapping in `modules/ai`. Add if a reviewer asks.
- [ ] `web/e2e-real/ai.global.spec.ts` fixme text may still mention PDF as unsupported; e2e-real owner.
