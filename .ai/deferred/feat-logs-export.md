# Deferred — feat/logs-export (S-CORE-6, D-132)

- [ ] Content type of the download: the generated response encoder (D-60) always sends `application/octet-stream`; API_CONVENTIONS §7 wants `text/csv; charset=utf-8` and `application/json`. Same for `/core/audit/export`. Needs a hook in `core/server` (an `Exchange` content-type override applied after the encoder) — lead
