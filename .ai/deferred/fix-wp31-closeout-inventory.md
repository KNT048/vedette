# Deferred: fix/wp31-closeout-inventory (WP-31 close-out, D-296)

- [ ] 2026-11-12 — The passive sensor's `printable` (modules/sensor-passive/capture/decode.go) lets variation selectors through while the inventory strips them; aligning the sensor on `observe.Ignorable` would make source and sink agree — vì sao để sau: harmless now (inventory strips) — ở đâu: modules/sensor-passive/capture/decode.go printable
