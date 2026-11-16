# features/scanning

Settings › Scanning (#850, D-627). Story: S-SCAN-4 (one safety block, one engine list), S-INV-1 (scope, Scan the LAN now, Check this
device now), S-CORE-1 (engine switches).

- API (core, always on): `GET /scanning`, `PATCH /scanning/engines/{id}`, `PUT /scanning/safety`, `POST /scanning/engines/nmap-discovery/run`.
  `contract.ts` and the first `mocks.ts` came with the backend (AI-Trưởng, #857); the page, `api.ts` and the mocks after that are the UI's.
- Mock: the block is inventory's settings store; OpenVAS is the exposure mock's flag; `running[]` adds the LAN vulnerability checks
  (scan mock) and the public scan (exposure mock).
- Slots it fills: `shell.status` (indicator), `devices.actions` (`DevicesActions`: Scan selected, Scan the LAN now), `device.actions`
  (`DeviceActions`: Check this device now, Run vulnerability checks now from features/scan `VulnChecksButton`).
- For other pages: `ScanNow.tsx` `ScanNowButton` (`targets={[id]}`, `targets={ids}`, `targets="lan"`, or `onStart/running/progress`
  for another job) and `ScansRunningIndicator` (shell slot `shell.status`); `Fixes.tsx` `ScopeDialog`/`ScopeButton` (ranges + commitment)
  and `TurnOnModule`; `places.ts` `runPlace` (where a run is seen).
- Tabs: `?tab=engines|safety|history|probes`; `#<engine id>` opens that card's settings; `#engine-<id>-switch` focuses its switch.
  History and the probe log are the scan module's (features/scan).
