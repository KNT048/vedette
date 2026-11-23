# features/honeypot

Stories: S-HP-1, S-HP-2. The page has: KPIs (Trap IPs listening, hits today, hits in 7 days), tabs Overview, Trap IPs, Services, Tokens, Hits (`?tab=`).
A **Trap IP** is one profile: a name (NetBIOS host name), an address, a preset (`presets.ts` = `modules/honeypot/presets.go`), the vendor for the MAC prefix, its own services; each Trap IP answers only its own services (the host closes other ports). The list shows where it sits (B2): the MAC and vendor the scanner reads from the MAC, the open services, which card the macvlan link `vdh…` is on, the last hit, the inventory device that holds the address (a link). Form errors sit under the exact field.
Scan detection: one source touching ≥ 2 Trap IPs within 1 minute = one `scan` hit (the "Scan detection" card names the Trap IPs the scan touched); the hit table has a Trap IP column.
Vedette's own scanner (the box 192.168.10.250) is always excluded and shown plainly on the page; "Test trap" creates a hit labelled "test" on the first Trap IP that has that service, not counted in the figures, no alert sent.
Mock tables: `hp_config`, `hp_trap_ips` (the core network mock reads them with `peek`), `hp_hits` (`kind` service|token|scan, `source_ip`, `token_id`, `trap_ip`, `trap_hostname`; the response module reads them with `peek`), `hp_tokens`. Each hit has a Respond link to `/response`. Reads `assetsStore` (checks for a duplicate IP/name, looks up the source device).
Slot provided: `device.panels` (props `{ assetId }`). Consumes no slot.
Permissions: add/edit/enable/disable/delete a Trap IP = admin; Test trap, Test scan, Test token = operator; view = viewer.
