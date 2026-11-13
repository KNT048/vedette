# Honeypot — Change Impact Map

> Mã Go đã có (WP-14, package `modules/honeypot`). Chữ ký thật: `Service.Hits(ctx, HitFilter) ([]Hit, error)` (mỗi hàng có `IsTest`, `SourceIP()`), `Service.Overview(ctx)`, `Service.TrapIPs/AddTrapIP/EditTrapIP/SetTrapIPEnabled/DeleteTrapIP` (D-466, thay `SetConfig`, `SetTrap`, `AddDecoy…`); cổng vào: `Inventory`, `Host`, `Logs` (tuỳ chọn), `Publisher`. Khác DATA_MODEL 4.7: `src_asset_id` không lưu (tra theo IP lúc đọc, INV-8), mật khẩu token ở `core_secret`, bảng `hp_trap_ips` (migration 0003 thay `hp_trap`, `hp_decoys` và IP phụ trong `hp_config`), `hp_ignored_day`, cột `conn_key`, `conn_count` (migration 0002: số kết nối trong cửa sổ 10 phút của hit).

## Modifying: `Hits(ctx, HitFilter) ([]Hit, error)` — 3 người gọi
- **response** (`engine`: sự kiện trigger `honeypot`): đọc `source_ip`, `kind`, `label`; đổi tên trường/kiểu → trigger vỡ, quy tắc đang chạy khô/chạy thật ngừng khớp. Phải giữ `is_test` để loại hit thử.
- **ai** (công cụ chỉ-đọc `ask-my-data`): đổi cột → câu trả lời sai chứ không lỗi.
- **Hit** có thêm `trap_ip`, `trap_hostname` (D-466, W1-13: cột Trap IP của bảng hit; trước chỉ có ở `HitDetail`). Người đọc đi qua JSON không vỡ.
- **core/logs export** (`/core/logs/export?categories=honeypot`, D-132): `Service.ExportHits` đọc thẳng cột của `hp_hits` (`hitCols`, `events` là JSON, không `conn_key`), đăng ký ở `cmd/vedette/logexport.go`; đổi cột → file tải về thay đổi, kiểm tra offline hash không ảnh hưởng (hit không có hash chain).

## Modifying: `Service.Tokens(ctx)`, `MaskTokens`, `GET /honeypot/tokens` (D-189, L14)
- **web/features/honeypot** (`Tokens.tsx`, mock + MSW): in `Tokens.tsx` the viewer sees what the API sends (`password: ••••••••xxxx`); the mock masks for a viewer exactly as the handler does. `Tokens(ctx)` returns the full password for internal callers (`token()`, tests); only the handler masks, by the role of the principal (operator, admin: full). A new reader of `Tokens` that leaves the module must go through `MaskTokens` unless it is operator-only. The `hits` export (`ExportHits`) and the `ai` read tools never carry the password.

## Modifying: `Service.Disable`, `Service.EnsureOff` (D-189, L11)
- **cmd/vedette** (`honeypotEnsureOff` → `moduleWiring.EnsureOff` → `modreg.OffGuard`): called at start with the module off and after each switch-off, retried with backoff until nil; the run loop's own `Disable` on cancel stays (same lock as `Apply`, `applyMu`). `Disable` returning nil now means the host confirmed; an error keeps the host status at "turning off". Changing `EnsureOff` to return nil early leaves traps listening after a failed teardown.

## Modifying: event `honeypot.hit.created` (`HitEventData`) — 3 người nhận
- **notify** (`modules/notify/events.go` `hitEvent`): nội dung cảnh báo (IP nguồn, thiết bị nguồn, 1 giờ sự kiện). Đọc thêm `kind`, `decoy`, `src_asset_id`, `src_name` (W1-13): `kind=scan` → **một** incident High mỗi nguồn (đích `scan`), còn lại Critical; thiết bị nguồn có tên thì incident ghi nó (cột Device). Đổi tên `kind`/`src_name` → quét thành Critical lặp theo nhãn, incident mất thiết bị.
- **response**: nguồn trigger `honeypot` (D-50; nối từ #304, D-286): `modules/response/events.go` `honeypotEvent` đọc `id, ts, kind, src_ip, decoy, src_asset_id` qua JSON; đổi tên/nghĩa một trường làm quy tắc honeypot im lặng (test `TestHoneypotHitEvent`, `cmd/vedette` `TestResponseHoneypotHitFiresTheRule`).
- **logs/siem**: kênh `honeypot` chuyển tiếp SIEM (S-LOG-3).

## Modifying: `Overview(ctx)`, `TrapIPs(ctx)` và các lệnh Trap IP (D-466) — GUI + host
- **web/features/honeypot**: `HpOverview` là hợp đồng; đổi → sinh lại OpenAPI + sửa mock.
- **host**: lệnh `decoy_ip.add/set_ports/remove` và `container.start/stop` (service `honeypot`) nhận IP đã kiểm, `oui` của vendor và `ports` của dịch vụ (host-api 6.6, D-466); đổi định dạng → Trap IP không dựng được, `conflict`/`failed`; bỏ `ports` → mọi địa chỉ trả lời mọi dịch vụ (W1-14 quay lại). Cổng `Host.AddDecoyIP(ctx, ip, DecoySpec)` đổi ở D-466: bộ chuyển, `notAnAppliance` và `fakeHost` đổi cùng lượt. Bộ chuyển `Host` ở `cmd/vedette/honeypothost.go` (D-161; CONTRACT "Bộ chuyển `Host` phía `core`") so với `decoys` của `GET /v1/state/net` và chỉ gửi phần khác: `syncIPs` gọi `AddDecoyIP` cho mọi IP ở mỗi `Apply`, gửi thẳng thì 32 decoy chạm trần 10 lệnh ghi/phút của host. Đổi chữ ký `Host` (như `StartContainer(ctx, restart)` ở D-161) phải đổi bộ chuyển, `notAnAppliance` và `fakeHost` của test cùng lượt.

## Modifying: mạng của container (namespace `vedette-hp`, D-102)
- **host** (unit Quadlet, `decoy_ip.*`): container vào namespace do host sở hữu (`Network=ns:/run/netns/vedette-hp`), MAC mỗi IP do host sinh, chặn đi ra bằng nft trong namespace, `DropCapability=ALL` nhờ `ip_unprivileged_port_start=0`. Đổi sang network macvlan của Podman hay một container mỗi IP là trái D-102 (một IP mỗi lần gắn, phải khởi động lại); thêm chân `vedette-int` mở lại đường tới `core` mà D-89 đã bỏ.
- **WP-08** (image honeypot): OpenCanary phải chạy được không capability nào trên cổng thấp (dựa vào sysctl của namespace), và không cần mạng ra. Image phải có `/vedette` (binary tĩnh, 0755): `HealthCmd=["/vedette","honeypot","healthcheck"]` (dạng exec, D-137) đọc cổng từ `opencanary.conf`, nên khoá `<dịch vụ>.enabled` và `<dịch vụ>.port` của `RenderConfig` là hợp đồng với nó (test `TestFirstTrapPortReadsWhatRenderConfigWrites`). **Adapter host của honeypot (WP-08; `cmd/vedette/honeypot.go` hiện `notAnAppliance`) phải gọi `container.start` với `restart: true` mỗi khi `opencanary.conf` đổi**: health check đọc tệp trên đĩa, còn OpenCanary chỉ đọc nó lúc khởi động và `container.start` không làm gì với container đang khoẻ nếu không có `restart`.

## Modifying: hai thư mục dùng chung dưới `-honeypot-dir` (`config/`: `opencanary.conf`, `honeytokens.json`; `log/`: `opencanary.jsonl`)
- **WP-08 (container honeypot)**: `config/` gắn **chỉ đọc**, `log/` gắn ghi được (đúng chủ sở hữu/quyền cho người dùng của container); từ D-318 `log/` là volume tmpfs 64 MiB / 1024 tệp (`vedette-hp-log`), đổi nó là đổi `host/ops/quadlet.go` và DEPLOYMENT §6.1; `opencanary.conf` trỏ tới đường dẫn tuyệt đối của log, nên `log/` phải gắn ở **cùng đường dẫn** trong container (hoặc đổi `Config.LogDir`). Đổi tên tệp, dạng dòng log hoặc cờ xoay (`RotatingFileHandler` 10 MiB × 3) → hit không vào hoặc log phình. Golden test `testdata/opencanary.golden.json`.
- **cmd/vedette**: cờ `-honeypot-dir` là thư mục cha; hai thư mục con tên cố định `config`, `log` (`HoneypotConfigDir`, `HoneypotLogDir`).

## Modifying: `Service.DecoyIPs(ctx) []netip.Addr` — 1 người gọi
- **inventory** (qua `inventory.Config.BoxOwnedIPs`, nối ở `cmd/vedette/inventory.go`, đọc lúc cần vì honeypot dựng sau kho): quan sát có IP trong danh sách không tạo/cập nhật thiết bị, `ProtectedIPs` (nên `sensor-active`) liệt kê chúng. Đổi ý nghĩa (IP đã giao cho host ở `Apply` gần nhất, đọc từ `hp_config.applied`) → thiết bị ma xuất hiện trong kho (bẫy tự gây `conflict`) hoặc `sensor-active` quét IP bẫy. Rỗng khi host không phải appliance.

## Modifying: `Service.TrapConflicts()`, `Stats()` — chưa có GUI
- Lý do IP bị loại (thiết bị, IP hộp, ngoài LAN, host từ chối, quá 32) lên GUI qua `Overview.Problem` (IP phụ) và `Decoy.Reason` (decoy thêm, D-383); danh sách đủ và bộ đếm (`Implausible`, `Suppressed`, `NotRegular`, `SkippedBytes`) chỉ ở đây và ở log (đổi GUI là story mới).
- `Trap.state`/`Decoy.state` `listening` đọc `hostCache.placed` (T8): đổi nghĩa `placed` (IP host đã xác nhận ở lần `Apply` gần nhất) làm GUI nói "Listening" cho IP host không giữ, hoặc "failed" cho decoy đang nghe.

## Modifying: `Config.BoxURL`, token loại `url` (D-465)
- **cmd/vedette** (`honeypot.go`): `BoxURL` = `deps.BaseURL` (Box address của Settings → Box network). Bỏ nối = token URL mang IP hộp của kho trên 8443 (không theo Box address người dùng đặt). GUI/mock (`honeypot/mocks.ts`) dùng `boxAddress()` của `mocks/network.ts`; 409 `no_box_address` trùng câu.

## Disabling this module
- Trang Honeypot, panel bẫy trên trang thiết bị trống ("module đang tắt").
- `response`: trigger `honeypot` và các mẫu `tpl-trap-*`, `tpl-sweep-vlan` không còn sự kiện; quy tắc giữ nguyên, không lỗi.
- `notify`: không còn cảnh báo chạm bẫy. `logs/siem`: kênh `honeypot` không có bản ghi.
- Container `honeypot` dừng, IP phụ gỡ. `hp_*` giữ nguyên, bật lại thấy lại lịch sử.

- **`Host` tuỳ chọn `DecoyLinks(ctx) map[netip.Addr]DecoyLink`** (S-HP-1, D-466 B2; thay `DecoyMACs`): `cmd/vedette/honeypothost.go` đọc từ cùng lần `state/net` với `held` (MAC, link `vdh<8 hex>`, card quản trị); bỏ đi thì GUI không hiện MAC/hãng/link, không gì khác đổi. **`Host` tuỳ chọn `KeepsPorts(ctx) bool`** (`portKeeper`): false → Trap IP đang nghe ghi chú host cũ và `open_services` = mọi dịch vụ đang chạy.
- **content/oui** (bảng D-83, dữ liệu): module đọc nó để ra `mac_vendor`; đổi bảng → hãng hiện khác (test `TestVendorOUIsBelongToTheVendor` giữ OUI của vendor đúng hãng).
- `Trap.state`/`TrapIP.state` có thêm `starting|stopping|failed`: GUI (`TrapStateChip`), mock (`features/honeypot/mocks.ts`) và `api/openapi.json` phải đổi cùng lượt.

## Modifying: `Service.OpenURLToken(ctx, URLTokenOpen)`, `ValidURLTokenID`, `UnknownSource` (D-507) — 1 người gọi
- **cmd/vedette** (`honeytoken.go`, nối trong `topHandler` ở `/t/{id}`): mọi `/t/<x>` trả cùng `404 page not found`; đổi câu trả lời theo việc token có tồn tại hay không là lộ token cho người dò. Đổi dạng id (`AddToken`: 10 ký tự `a-z0-9`) phải đổi `ValidURLTokenID` cùng lúc, nếu không token mới không bao giờ bắn. Giới hạn mỗi địa chỉ: `server.AddrLimiter` (`core/server/publimit.go`), chỉ hỏi qua `URLTokenOpen.RepeatOK` cho lần mở lặp lại; hỏi trước khi biết token là cho id bịa làm im liên kết thật (review M1). Chính hộp: `machineAddrs` + `appliance` (`honeyTokenSources`). **response** nhận `src_ip` không phải IP (`unknown (container-only port proxy)`) và bỏ qua hit đó. Hit đi qua `upsert`/`newIngest` của `ingest.go`: đổi chữ ký của chúng phải sửa `urltoken.go`.
- **notify** (`hitEvent`): hit `kind=token` có tiêu đề "<ip> opened the URL token <tên>" (đọc tiền tố `URL token `/`File token ` của `label`, `tokenLabel`); đổi `tokenLabel` làm tiêu đề quay về "used".

## Modifying: `Service.PollTouches`, `Host` tuỳ chọn `Touches(ctx) ([]Touch, error)` (B2 review M2)
- **cmd/vedette** (`honeypotHost.Touches` → host `GET /v1/state/hp-touches`): vòng `Run` gọi mỗi `touchEvery` (15 s), 4 lần đọc/phút trong 60 của host. Bỏ đi thì quét SYN (mặc định của nmap) không còn thành cảnh báo quét; chỉ còn quét bằng kết nối thật.

## Modifying: `HitDetail(ctx, id)`, `SourceConnected(ctx, src, at, window)` (D-509) — người gọi: `cmd/vedette` `responseIncidents`
- Respond trên sự cố bẫy (`response`) đọc nguồn từ `HitDetail` (`SrcIP`, `SrcAssetID`, `IsTest`, `Kind`) và, với hit `scan`, hỏi `SourceConnected`: có hit `service` thật (không thử) của cùng `src_ip` trong `at ± window` không. Chỉ đọc. Đổi `kind`/`src_ip`/`ts` của hit `service` hay để luồng tạo `scan` cũng tạo hit `service` từ lần thử chưa bắt tay ⇒ response coi nguồn giả được là đã xác nhận (rủi ro chặn nhầm máy vô tội); trả lỗi ⇒ response trả lỗi (không đưa gì).
- **Loại thiết bị (D-511)**: đọc `content/devicetypes` (gói lá, chỉ thư viện chuẩn). Gợi ý preset so loại hành xử như (`ActsAs`): máy ảo hành xử như server, DVR như nvr.
