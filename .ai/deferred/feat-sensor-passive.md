# Deferred: feat/sensor-passive (WP-11)

- [ ] Live AF_PACKET capture (`afpacket_linux.go`) is compiled and source-audited only; verify by effect on the lab VM: socket opens with only CAP_NET_RAW, `tx_packets` of the card does not change, frames arrive, stops on module off.
- [ ] Fingerbank (INV-10): not in this WP; needs BYOK key, default off, PRIVACY.md row. DHCP vendor class (opt 60) and client id (opt 61) are parsed but not yet used; Fingerbank is their consumer.
- [ ] `PATCH /inventory/sensors/{id}` (CONTRACT INV-9) has no operation in contract.ts/OpenAPI/mock; `Service.SetInterface` is ready. When the host module (Box network, `PUT /core/network/span`) lands, call it and decide whether the route is still needed; fix CONTRACT.md accordingly.
- [ ] Host stand-in `netHost` (cmd/vedette/sensorpassive.go): replace with the host module (interfaces, SPAN extract switches, exclusion filters). Until then no interface is chosen and the capture idles.
- [ ] `logs` module (Emily): implement `MetadataSink`, consume SPAN metadata (S-LOG-4); default sink drops it.
- [ ] Event bus: `sensor.status.changed` and `sensor.span.metadata_batch` are not published (no bus in main yet); wire when events.Bus is built in serve.
- [ ] IPv6 is not read (ARP/DHCPv4/mDNS-v4/SSDP-v4/flows IPv4 only); IPv6 NDP, DHCPv6, mDNS over IPv6 need their own story.
- [ ] TLS SNI is read from the first segment only (no TCP reassembly); a ClientHello split over segments is missed.
- [ ] Remote sensor (mTLS transport, `/sensor/v1/events`) is a separate WP; `SubmitBatch` is its in-process half.
- [ ] CI fuzz time for INV-4 (60 s per parser) is not wired in CI yet; local runs were 35 s each.

- [ ] Capture runs inside the main vedette process, so the API process would need CAP_NET_RAW. Before release, run capture in the sensor container (D-55: host network, CAP_NET_RAW only) and talk to the core over the sensor protocol; keep the main process unprivileged.
- [ ] Drop counters (`new_macs_dropped`, `excluded`, `malformed_*` ...) are only logged every 5 minutes when they change; show them on the Sensors card once contract.ts has a field.
- [ ] LLDP cannot be excluded by IP rules (no IP in the frame); add MAC exclusions to the SPAN filter model (contract.ts SpanFilter) if admins need it.
- [ ] The set of reported devices (`deviceBook`) is in memory: after a process restart a device the inventory already has must pass the two-frame rule and the budgets again. Seeding it from the inventory needs a new `core/observe` interface (e.g. "which of these MACs exist"); decide with the lead.
- [ ] The inventory's `cleanText` (modules/inventory/validate.go) refuses only C0 controls and DEL; it accepts C1, bidi and invisible format characters from any source. sensor-passive filters them itself (INV-3); the inventory should do the same at its boundary (own WP, lead's module).
