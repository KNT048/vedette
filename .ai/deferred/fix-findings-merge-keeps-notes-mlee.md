# Deferred from fix/findings-merge-keeps-notes-mlee (AI-Mlee, 2026-11-14)

- [ ] LOW (review of #722 OnAssetMerged): when a CVE is on both merged rows, the dropped finding's `mit_applied` / `mit_ai_output` rows (mitigation tables, keyed by finding id) stay orphaned, as they already do after `OnAssetDeleted`; and a notify incident opened for the dropped finding keeps a `/findings/<id>` link that now 404s. Fix with the general "finding deleted" cleanup (mitigation + notify listen to a findings delete event), not merge-only.
