# Deferred from fix/devices-page-b7 (B7, D-471)

- [ ] M5-186 part 2: a Mac's model "Mac14,2" (mDNS TXT `model=`) should type the device as Computer. The model comes from sensor-passive (`capture/engine.go` mDNS TXT); the rule belongs there (Apple model prefixes Mac/MacBook/iMac/Macmini → pc). Outside B7's files; owner: whoever takes item 25 (device types) or sensor-passive.
- [ ] D-471: "attach to a device" (or give a name) for a product-only row ("Microsoft Office (no device)"): needs moving manual software between devices and a name edit on PATCH /inventory/devices/{id}. Needs its own story criterion.
- [ ] D-464 rollout: the device detail page (/devices/:id) still uses stacked sections, not the tab frame (plan §3 lists it under B7). Do it with item 9's "packages in their own tab".
- [ ] Report mocks (`web/src/features/reports/pdpl.ts`, `weekly.ts`) still name devices by hostname/IP; the backend reports use `deviceLabel` (D-471 rule). Mock-only drift.
