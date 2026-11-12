# Deferred: fix/core-walk3 (G12)
- [ ] 2026-11-12 Updates page (container-only): a failed update check is not shown as "failed" because UpdatesState has no field for it (only last_check). Needs an API field (e.g. last_check_error) in contract.ts, openapi and core/updates_check.go. Today the page says "never read" + the likely cause.
- [ ] 2026-11-12 Form errors that are toast-only in Response forms and Ask/Reports/AI forms were left to their own agents/owners (G12 line 5); core forms (connections, users add, general) now place server errors under the field.
