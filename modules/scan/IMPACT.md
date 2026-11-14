# Scan — Change Impact Map

## Modifying: `scan.Service.StartRun(ctx, targets, trigger)` và bộ chọn `Targets()`
- **SPA** (`/scans`, `RunsTab`, `TargetPicker`, Devices → "Scan"), **core/jobs** (lịch), `OnNewKEV`. Đổi điều kiện chọn mục tiêu đổi số gói/request rời hộp: sửa CONTRACT + test INV-1…3.
- `scan.Inventory.VulnScanPolicies` (D-472) là `inventory.VulnScanPolicies` qua adapter `cmd/vedette` (chia lô `inventory.MaxPolicyBatch`); đổi luật D-126 ở `inventory.decideVuln` thì cả hai đường (một thiết bị và theo lô) đổi cùng nhau. Thêm/bớt trường của `ScanTarget` ⇒ `contract.ts` + `api/openapi.json` + ogen.
- `ScanTarget.box` (D-470): `scan.Device.Box` từ `is_box` của inventory (`cmd/vedette/scan.go`); `TargetPicker` đọc nó cho dòng "pick it to scan" và lý do không tick khi Select all; đổi nó phải sửa `contract.ts` + `api/openapi.json` + ogen cùng lúc.

## Modifying: `scan.Identifier`, `IdentRow`, `ScanRun.identification` (D-501, INV-13)
- **sensor-active** (`IdentifyDevice`, mã `Why`), adapter `scanIdentify` ở `cmd/vedette/scan.go`; **SPA** `RunsTab` (`Identification` trong hộp thoại kết quả), `contract.ts` `IdentReason`/`RunIdentRow`, mock `IDENT_NOTE`/`identOne` (cùng câu với `identNote`), `api/openapi.json` + ogen. Đổi một lý do hay câu: sửa cả bốn chỗ cùng commit.

## Modifying: `slotOK`, `NextRun`, `lastSlot`, `RunSchedule` (lượt lịch đầu, D-504 (6))
- "Chưa lượt lịch nào" = không dòng `scan_run` nào `trigger = schedule` (`firstPending`, W3-9; trước đây là `sched_last` trống, sai khi một mốc bỏ lỡ hay không có gì để quét đã được ghi): đổi luật này đổi cả `next_run` của `GET /scans/config` (`view`), `RunSchedule`, mock `nextRun` (`web/src/features/scan/mocks.ts`, `first` = chưa có run `schedule`, cùng luật) và `TestContract_POST3_NextRun`; dòng `scan_run` không bao giờ bị xoá, nên lượt đầu không quay lại; khôi phục một bản sao lưu trước lượt lịch đầu làm hộp chạy lượt đầu ở cửa sổ kế tiếp.

## Modifying: `identNote` (thêm `os_no_patch_level`, D-504)
- Mã lý do do sensor-active trả (`WhyOSNoPatch`); thêm/đổi mã thì đổi `IdentReason` của `contract.ts`, OpenAPI và `core/api/oas` (sinh), ghi chú của mock và nhãn `scan.ident.*`.

## Modifying: gọi `inventory.InScope/ScanPolicy` và `exposure.CheckScannable`
- **inventory**, **exposure**: đây là hai rào SYS-7. Nới ở một phía mà không sửa phía kia ⇒ lỗ hổng phạm vi.

## Modifying: `findings.ConfirmFromScan(…)` và sự kiện `scan.finding.confirmed`
- **findings** (tạo/xác nhận finding), **notify** (qua finding). Đổi `Evidence` làm hỏng bằng chứng hiển thị (S-SCAN-3).

## Modifying: `feeds.vuln.new_kev` (trường `has_template`)
- Nguồn kích hoạt quét lại. Đổi tên/trường ⇒ mất S-SCAN-2 mà không có lỗi.

## Modifying: nhật ký `scan_probe` / danh mục `scan_probes`
- **core** (`/core/logs/export`), **SPA** Probes. Giảm thời gian giữ dưới 90 ngày phá S-SCAN-4.

## Modifying: máy quét bề mặt ngoài (`modules/scan/surface`, `cmd/vedette` `scanRunner`; INV-12, D-229)
- **exposure** (`POST …/scan`, ảnh chụp, `Content`, `ScannableIP` quyết địa chỉ nào được quét cổng: D-57 (7)), **response** (trigger `new_port` nghe `exposure.snapshot.created`), **reports**. Đổi danh sách cổng, dấu hiệu trang quản trị hay luật chọn tên làm đổi ảnh chụp và so sánh ngày (cổng/trang "mới" hay "mất" giả). Đổi nơi gửi (CT, proxy, User-Agent) là đổi luồng dữ liệu ra: PRIVACY luồng 9 + Settings → Privacy cùng commit. Nới luật địa chỉ (`exposure.IsPublicIPv4`) hay quét cổng một địa chỉ mà `ScannableIP` không cho là phá SYS-7 và LEGAL §3. `RecordExternalProbes` ghi vào `scan_probe` (INV-7): đổi bảng hay thời hạn giữ phải giữ các dòng `run_id` NULL của nó.
- **sensor-active** (D-514): danh sách 98 cổng nằm ở gói lá `modules/scan/commonports` (không import gì; binary sensor link nó qua `nmapargv`) và cũng là `-p` của mẫu nmap `external` (`-sV` trên IP công khai của hộp cho exposure). Thêm/bớt cổng đổi cả mẫu đó: `nmapargv` `TestExternalPortsAreTheSurfaceList`, độ dài `sa_probe.flags` (≤ 1000), số "on N TCP ports" của exposure.
- (D-522, N5) `commonports.MaxBelievableOpen` (40): trên ngưỡng này exposure bỏ nhận dạng dịch vụ và mẫu (kết quả quét bề mặt) và sensor-active bỏ các dòng -sV (`ErrAnswersEverywhere`). Đổi số đổi cả hai.
- (D-522, N1, INV-14) `endpoints()` đọc tiền tố `ssl/` mà sensor-active ghi cho `tunnel="ssl"`: đổi cách đặt tên ở parser (sensor-active INV-18) phải sửa cả đây.

## Disabling this module
- "Scan now" của External exposure trả 409 `module_off`; ảnh chụp cũ giữ nguyên.
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
- D-261: a dropped event keeps its `scan_event` row with an `expired_*` result (the CHECK was rebuilt in `0005`; a new result needs a new migration). `ConfigView.ScheduleBlockedReason` and `engine_busy` in `GET /scans/runs` are read by the SPA scan tabs (`SafetyTab`, `RunsTab`); renaming them is a contract.ts change first.
- **feeds** (`feeds.vuln.new_kev`, subscribed in `cmd/vedette/wiring.go` after inventory's rematch, so the new entry's findings exist when the job looks), **inventory** (`VulnScanPolicy` with `explicit=false`: these runs nobody picks never touch fragile, unclassified or hand-declared devices, D-126 (2)), **SPA** Auto rescan tab (`GET /scans/events`). `RescanEvent.result=clear` means only "no match reported" (D-133 (5)) and changes no finding; `pick_only` and `stopped` (D-145 (7)) say what was not scanned; a new result value is a GUI-first contract change. **core** (`OrgTimeZone` through `orgLocationAt` in `cmd/vedette`): the window and the slots are in the organization zone (#164 review H1); without it they fall back to UTC. A change to `slotOK`/`slotWindowEnd` must change the mock's `nextRun` with it (the GUI shows `next_run`). `retention` is `Housekeeping` (D-160): it keeps its hourly timer while the module is off and must stay a pure delete past the retention; any other work in it needs the flag removed or the job split. Shortening `retention` below 90 days for probes breaks S-SCAN-4.

## Modifying: `KEVFeed` and the catch-up (S4b)
- **feeds** (`Store.NewKEVSince` over `feeds_vuln.kev_announced_at`, through `cmd/vedette/scan.go` `scanKEV`; nothing while feeds is off). The catch-up decides which missed entries are rescanned: the 7-day limit, the template check and the page size are its bounds; widening them makes more automated runs. The batch of a pass is one run: changing its caps (templates, devices) changes how much one automated run touches.

## Modifying: `nucleiargv`, `nucleiout`, `pack` (S2)
- D-528 step 2: `scripts/scanpack/reviewed.tsv` alone decides the KEV set (`noTickReason`); `readOnlyGET`, `getVerbRE` and `stateNameRE` only sort the review queue. Adding a line to reviewed.tsv puts a non-GET check into every LAN scan and own-IP check of a matched device: read the requests, not the name, and record who and when. A nuclei-templates bump that changes a reviewed file stops `make scan-pack` (stale review) until it is read again. `docs/research/kev-review-queue.md` is written by `make scan-pack`; the scan page (`web/src/locales/en/scan.json` description and `never.*`) and THIRD_PARTY_NOTICES say what the rule allows: loosening it means changing them.
- D-528: `pack.NoChangeText`, `ChangeInRequest`, `ThirdPartyURL`, `MethodOK`, `NeverTags` and `scripts/scanpack` `changeReason`, `denylist` (and, since step 2, `reviewed.tsv`) decide which templates may be in the pack at all; the worker runs `NoChangeText` on every template of every job. Making `NoChangeText` stricter without rebuilding the pack makes the worker refuse whole jobs (`invalid_job`): change the rule, rebuild (`SCAN_PACK_VERSION`), and keep the builder requiring it. Loosening a rule or emptying the denylist puts password-reset and write templates back into the LAN scan.
- D-520 (3): the index carries `own_ip` per template (decided by `scripts/scanpack` `ownIPSafe` from the template file: read-only GET/HEAD requests only); `pack.Parse` refuses an `own_ip` entry that is not an http GET/HEAD check or carries a refused tag; the worker re-reads the file with `pack.OwnIPText`, which also passes every request target and raw header through `pack.RequestPayloadOK` (no injection-shaped payload, review round 2 M1). The mark is in the pack's SHA-256 label. The Makefile rebuilds the pack when `modules/scan/pack` changes. Changing the rule changes the pack (`SCAN_PACK_VERSION`, the committed `content/nucleipack/index.json`) and the PRIVACY flow 9 sentence. The LAN scope ignores the field.
- D-520: `nucleiargv` has a second scope, `own_ip` (one public IPv4 through `core/localnet.Public`, rate fixed at `OwnIPRate`, `-etags` with `OwnIPForbiddenTags`), told apart from the LAN line by its `-etags` only; `Validate` reads the scope from the flags, never from the target. A change to either shape is a sensor-protocol change and moves sensor-active INV-17 with it.
- Shared with the worker of the `scan` container (D-125): a change to the argv grammar or the job limits is a sensor-protocol change (proto number, worker, `docs/specs/sensor-protocol.md` §9). The set of target addresses is `core/localnet.Addr` (RFC 1918 + 100.64/10, D-461), shared with `nmapargv`, the inventory scope and setup; widening it without a wire change keeps the proto (§10: an older worker refuses the new targets as `invalid_job`). `nucleiout` is the trust boundary for what devices answered: keep it fail-closed and fuzzed. Its fixtures are real lines of the pinned nuclei (lab VM, 2026-11-12, `docs/lab/2026-11-12-podman-nuclei.md`): v3.11.1 writes `host` as the bare address with `port` apart, read by `targetOf`; bumping `NUCLEI_VERSION` means recording them again.
