# Deferred: fix/multi-products-old-rows-close (D-506)

- [ ] notify: alert when Vedette reopens a finding by itself (`findings.finding.status_changed` with `reason: matches_again`), so a D-506 or D-530 close that NVD later contradicts is not silent (today notify only alerts on `confirmed`, `modules/notify/events.go`). Needs a story criterion in S-ALERT-1 first; notify is Mlee's module.
