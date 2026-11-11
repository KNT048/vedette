# Scan — Change Impact Map

## Modifying: `scan.Service.StartRun(ctx, targets, trigger)` và bộ chọn `Targets()`
- **SPA** (`/scans`, `RunsTab`, Devices → "Scan"), **core/jobs** (lịch), `OnNewKEV`. Đổi điều kiện chọn mục tiêu đổi số gói/request rời hộp: sửa CONTRACT + test INV-1…3.

## Modifying: gọi `inventory.InScope/ScanPolicy` và `exposure.CheckScannable`
- **inventory**, **exposure**: đây là hai rào SYS-7. Nới ở một phía mà không sửa phía kia ⇒ lỗ hổng phạm vi.

## Modifying: `findings.ConfirmFromScan(…)` và sự kiện `scan.finding.confirmed`
- **findings** (tạo/xác nhận finding), **notify** (qua finding). Đổi `Evidence` làm hỏng bằng chứng hiển thị (S-SCAN-3).

## Modifying: `feeds.vuln.new_kev` (trường `has_template`)
- Nguồn kích hoạt quét lại. Đổi tên/trường ⇒ mất S-SCAN-2 mà không có lỗi.

## Modifying: nhật ký `scan_probe` / danh mục `scan_probes`
- **core** (`/core/logs/export`), **SPA** Probes. Giảm thời gian giữ dưới 90 ngày phá S-SCAN-4.

## Disabling this module
- Mất trang Scans và nút quét; không xác nhận mới; không tự quét lại sau KEV mới.
- `scan-credentialed` không chạy được (phụ thuộc); `findings` chỉ còn `suspected`; `reports` bỏ mục quét.
- Cấu hình, lịch sử, probe log, sự kiện quét lại giữ.

## Modifying: `scan.Engine` (S1, D-125)
- Seam of the scanner: the worker of the `scan` container over the sensor protocol, a fake in tests. `Ready` decides `can_scan` and the 503 `scanner_unavailable` (INV-2). **S5:** `cmd/vedette/scan.go` `scanEngine` wires the Dispatcher of **sensor-active** (`sensoractive.Scanner{Ready, RunNuclei}`) when `d.SensorDispatcher` exists, with `scan.Config.Pack` = the committed index of **content/nucleipack** (the same pack as the `scan-base` image, D-146). `Run` takes a `scan.Job` (argv job with paths, the same templates by id, the pack version and sha256) and returns a `nucleiout.Outcome` (`Results` already parsed fail closed by the Dispatcher, and `HostErrors`: timeouts per target counted by the worker from nuclei's error log, which is how INV-6 sees a device that answered some templates and then went quiet, D-165; `nucleiargv.fixedFlags` carries `-elog /dev/stderr` for it, and the sensor protocol is at proto 3); an error wrapping `scan.ErrEngineDown` (the worker gone or not ready, another pack, a pack that failed its integrity check) stops the run with that message. A change to the seam is a change on both sides of the sensor protocol: check `modules/sensor-active` `NucleiRequest`.

## Modifying: `content/nucleipack` (S5)
- The index core plans with. Written only by `make scan-pack` (with `index.source`, from `deploy/containers/pins.env`), never by hand; `TestTheCommittedIndexIsThePinnedPack` holds it to the pins (source version, source sha256, pack version) and to its own label. Raising a pin without `make scan-pack` and a commit of `content/nucleipack` makes that test fail; if core and the image still drift, the Dispatcher refuses every job as `pack_mismatch` and the run stops saying so.

## Modifying: `scan_setting` / `Service.SaveConfig` (S1)
- **SPA** Schedule and safety tab, **jobs** of S4 (window, schedule, auto rescan, rate, exclusions). INV-5 is checked twice: in `Settings.validate` (with the mock's words) and by the CHECKs of `0001_scan_setting.sql`.

## Modifying: the ports `Inventory.Devices/VulnScanPolicy`, `Findings`, `External` (S3)
- **inventory** (`VulnScanPolicy`, D-126; `consent` in `targets.go` is the one place that folds it with `approved` and the scan exclusions), **findings** (`List`, `ConfirmFromScan` only; INV-8: a no-match never reaches findings, D-133 (5); adding a call there would let "no match reported" change a finding), **exposure** (`Targets`, listed only: not scanned yet). Adapters in `cmd/vedette/scan.go`. Loosening `consent` widens what leaves the box (SYS-7): change CONTRACT INV-1 and its tests with it.

## Modifying: the jobs `rescan`, `schedule`, `retention` and `scan_event` (S4)
- **feeds** (`feeds.vuln.new_kev`, subscribed in `cmd/vedette/wiring.go` after inventory's rematch, so the new entry's findings exist when the job looks), **inventory** (`VulnScanPolicy` with `explicit=false`: these runs nobody picks never touch fragile, unclassified or hand-declared devices, D-126 (2)), **SPA** Auto rescan tab (`GET /scans/events`). `RescanEvent.result=clear` means only "no match reported" (D-133 (5)) and changes no finding; `pick_only` and `stopped` (D-145 (7)) say what was not scanned; a new result value is a GUI-first contract change. **core** (`OrgTimeZone` through `orgLocationAt` in `cmd/vedette`): the window and the slots are in the organization zone (#164 review H1); without it they fall back to UTC. A change to `slotOK`/`slotWindowEnd` must change the mock's `nextRun` with it (the GUI shows `next_run`). `retention` is `Housekeeping` (D-160): it keeps its hourly timer while the module is off and must stay a pure delete past the retention; any other work in it needs the flag removed or the job split. Shortening `retention` below 90 days for probes breaks S-SCAN-4.

## Modifying: `KEVFeed` and the catch-up (S4b)
- **feeds** (`Store.NewKEVSince` over `feeds_vuln.kev_announced_at`, through `cmd/vedette/scan.go` `scanKEV`; nothing while feeds is off). The catch-up decides which missed entries are rescanned: the 7-day limit, the template check and the page size are its bounds; widening them makes more automated runs. The batch of a pass is one run: changing its caps (templates, devices) changes how much one automated run touches.

## Modifying: `nucleiargv`, `nucleiout`, `pack` (S2)
- Shared with the worker of the `scan` container (D-125): a change to the argv grammar or the job limits is a sensor-protocol change (proto number, worker, `docs/specs/sensor-protocol.md` §9). `nucleiout` is the trust boundary for what devices answered: keep it fail-closed and fuzzed.
