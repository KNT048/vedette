# features/scanning

Settings › Scanning. Story: S-SCAN-4 (one safety block, one engine list), S-INV-1 (scope, Scan the LAN now, Check this
device now), S-CORE-1 (engine switches).

- API (core, always on): `GET /scanning`, `PATCH /scanning/engines/{id}`, `PUT /scanning/safety`, `POST /scanning/engines/nmap-discovery/run`,
  `GET /runs`, `GET /runs/{id}`, `POST /runs/{id}/stop|resume`.
  `contract.ts` and the first `mocks.ts` came with the backend (#857); the page, `api.ts` and the mocks after that are the UI's.
- Mock: the block is inventory's settings store; OpenVAS is the exposure mock's flag; `running[]` adds the LAN vulnerability checks
  (scan mock) and the public scan (exposure mock). `GET /runs` lists `runsStore` and, under their own ids, the runs the engines' mocks
  hold (a person's discovery run, the vulnerability checks, the public scan, the LAN history), so every "Open the run" opens.
- Slots it fills: `shell.status` (indicator), `devices.actions` (`DevicesActions`: Scan selected, Scan the LAN now), `device.actions`
  (`DeviceActions`: Check this device now, and the vulnerability check from features/scan `VulnChecksButton`, named by what it checks from `vulnCount.ts`).
- For other pages: `ScanNow.tsx` `ScanNowButton` (`targets={[id]}`, `targets={ids}`, `targets="lan"`, or `onStart/running/progress`
  for another job) and `ScansRunningIndicator` (shell slot `shell.status`); `Fixes.tsx` `ScopeDialog`/`ScopeButton` (ranges + commitment)
  and `TurnOnModule`; `places.ts` `runHref` (every run opens on `/runs/<id>`, `RunPage.tsx`), `runsHref` (the Runs tab, filtered) and
  `isHere` (a link to the page being shown is said as text).
- Tabs: `?tab=engines|safety|runs|probes`; `#<engine id>` opens that card's settings; `#engine-<id>-switch` focuses its switch.
  Runs (`RunsTab.tsx`, `runs.q|kind|status|device|page` in the URL) lists every run; under it the vulnerability checks' results and
  rescans and the probe log are the scan module's (features/scan). The old `?tab=history` links land on Runs (`job=`/`run=` on the run).
