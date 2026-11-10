# Honeypot — Change Impact Map

> Mã Go đã có (WP-14, package `modules/honeypot`). Chữ ký thật: `Service.Hits(ctx, HitFilter) ([]Hit, error)` (mỗi hàng có `IsTest`, `SourceIP()`), `Service.Overview(ctx)`, `Service.SetConfig(ctx, actor, ip, hostname)`; cổng vào: `Inventory`, `Host`, `Logs` (tuỳ chọn), `Publisher`. Khác DATA_MODEL 4.7: `src_asset_id` không lưu (tra theo IP lúc đọc, INV-8), mật khẩu token ở `core_secret`, bảng thêm `hp_trap`, `hp_ignored_day`, cột `conn_key`, `conn_count` (migration 0002: số kết nối trong cửa sổ 10 phút của hit).

## Modifying: `Hits(ctx, HitFilter) ([]Hit, error)` — 3 người gọi
- **response** (`engine`: sự kiện trigger `honeypot`): đọc `source_ip`, `kind`, `label`; đổi tên trường/kiểu → trigger vỡ, quy tắc đang chạy khô/chạy thật ngừng khớp. Phải giữ `is_test` để loại hit thử.
- **ai** (công cụ chỉ-đọc `ask-my-data`): đổi cột → câu trả lời sai chứ không lỗi.
- **core/logs export** (`/core/logs/export?categories=honeypot`, D-132): `Service.ExportHits` đọc thẳng cột của `hp_hits` (`hitCols`, `events` là JSON, không `conn_key`), đăng ký ở `cmd/vedette/logexport.go`; đổi cột → file tải về thay đổi, kiểm tra offline hash không ảnh hưởng (hit không có hash chain).

## Modifying: event `honeypot.hit.created` (`HitEventData`) — 3 người nhận
- **notify**: nội dung cảnh báo (IP nguồn, thiết bị nguồn, 1 giờ sự kiện).
- **response**: nguồn trigger (D-50).
- **logs/siem**: kênh `honeypot` chuyển tiếp SIEM (S-LOG-3).

## Modifying: `Overview(ctx)`, `SetConfig(ctx, ip, hostname)` — GUI + host
- **web/features/honeypot**: `HpOverview` là hợp đồng; đổi → sinh lại OpenAPI + sửa mock.
- **host**: lệnh `decoy_ip.add/remove` và `container.start/stop` (service `honeypot`) nhận IP đã kiểm; đổi định dạng → IP phụ không dựng được, bẫy `conflict`/`off`. Bộ chuyển `Host` ở `cmd/vedette/honeypot.go` (việc của `core`, CONTRACT "Bộ chuyển `Host` phía `core`") phải so với `decoys` của `GET /v1/state/net` và chỉ gửi phần khác: `syncIPs` gọi `AddDecoyIP` cho mọi IP ở mỗi `Apply`, gửi thẳng thì 32 decoy chạm trần 10 lệnh ghi/phút của host.

## Modifying: mạng của container (namespace `vedette-hp`, D-102)
- **host** (unit Quadlet, `decoy_ip.*`): container vào namespace do host sở hữu (`Network=ns:/run/netns/vedette-hp`), MAC mỗi IP do host sinh, chặn đi ra bằng nft trong namespace, `DropCapability=ALL` nhờ `ip_unprivileged_port_start=0`. Đổi sang network macvlan của Podman hay một container mỗi IP là trái D-102 (một IP mỗi lần gắn, phải khởi động lại); thêm chân `vedette-int` mở lại đường tới `core` mà D-89 đã bỏ.
- **WP-08** (image honeypot): OpenCanary phải chạy được không capability nào trên cổng thấp (dựa vào sysctl của namespace), và không cần mạng ra.

## Modifying: hai thư mục dùng chung dưới `-honeypot-dir` (`config/`: `opencanary.conf`, `honeytokens.json`; `log/`: `opencanary.jsonl`)
- **WP-08 (container honeypot)**: `config/` gắn **chỉ đọc**, `log/` gắn ghi được (đúng chủ sở hữu/quyền cho người dùng của container; hạn mức ổ đĩa của `log/`); `opencanary.conf` trỏ tới đường dẫn tuyệt đối của log, nên `log/` phải gắn ở **cùng đường dẫn** trong container (hoặc đổi `Config.LogDir`). Đổi tên tệp, dạng dòng log hoặc cờ xoay (`RotatingFileHandler` 10 MiB × 3) → hit không vào hoặc log phình. Golden test `testdata/opencanary.golden.json`.
- **cmd/vedette**: cờ `-honeypot-dir` là thư mục cha; hai thư mục con tên cố định `config`, `log` (`HoneypotConfigDir`, `HoneypotLogDir`).

## Modifying: `Service.DecoyIPs(ctx) []netip.Addr` — 1 người gọi
- **inventory** (qua `inventory.Config.BoxOwnedIPs`, nối ở `cmd/vedette/inventory.go`, đọc lúc cần vì honeypot dựng sau kho): quan sát có IP trong danh sách không tạo/cập nhật thiết bị, `ProtectedIPs` (nên `sensor-active`) liệt kê chúng. Đổi ý nghĩa (IP đã giao cho host ở `Apply` gần nhất, đọc từ `hp_config.applied`) → thiết bị ma xuất hiện trong kho (bẫy tự gây `conflict`) hoặc `sensor-active` quét IP bẫy. Rỗng khi host không phải appliance.

## Modifying: `Service.TrapConflicts()`, `Stats()` — chưa có GUI
- Lý do IP bị loại (thiết bị, IP hộp, ngoài LAN, host từ chối, quá 32) và bộ đếm (`Implausible`, `Suppressed`, `NotRegular`, `SkippedBytes`) chỉ ở đây và ở log: GUI chưa có trường (đổi GUI là story mới).

## Disabling this module
- Trang Honeypot, panel bẫy trên trang thiết bị trống ("module đang tắt").
- `response`: trigger `honeypot` và các mẫu `tpl-trap-*`, `tpl-sweep-vlan` không còn sự kiện; quy tắc giữ nguyên, không lỗi.
- `notify`: không còn cảnh báo chạm bẫy. `logs/siem`: kênh `honeypot` không có bản ghi.
- Container `honeypot` dừng, IP phụ gỡ. `hp_*` giữ nguyên, bật lại thấy lại lịch sử.
