# Honeypot — Change Impact Map

> Mã Go đã có (WP-14, package `modules/honeypot`). Chữ ký thật: `Service.Hits(ctx, HitFilter) ([]Hit, error)` (mỗi hàng có `IsTest`, `SourceIP()`), `Service.Overview(ctx)`, `Service.SetConfig(ctx, actor, ip, hostname)`; cổng vào: `Inventory`, `Host`, `Logs` (tuỳ chọn), `Publisher`. Khác DATA_MODEL 4.7: `src_asset_id` không lưu (tra theo IP lúc đọc, INV-8), mật khẩu token ở `core_secret`, bảng thêm `hp_trap`, `hp_ignored_day`, cột `conn_key`.

## Modifying: `Hits(ctx, HitFilter) ([]Hit, error)` — 3 người gọi
- **response** (`engine`: sự kiện trigger `honeypot`): đọc `source_ip`, `kind`, `label`; đổi tên trường/kiểu → trigger vỡ, quy tắc đang chạy khô/chạy thật ngừng khớp. Phải giữ `is_test` để loại hit thử.
- **ai** (công cụ chỉ-đọc `ask-my-data`): đổi cột → câu trả lời sai chứ không lỗi.
- **core/logs export** (`/core/logs/export?categories=honeypot`): đổi trường → file tải về thay đổi, kiểm tra offline hash không ảnh hưởng (hit không có hash chain).

## Modifying: event `honeypot.hit.created` (`HitEventData`) — 3 người nhận
- **notify**: nội dung cảnh báo (IP nguồn, thiết bị nguồn, 1 giờ sự kiện).
- **response**: nguồn trigger (D-50).
- **logs/siem**: kênh `honeypot` chuyển tiếp SIEM (S-LOG-3).

## Modifying: `Overview(ctx)`, `SetConfig(ctx, ip, hostname)` — GUI + host
- **web/features/honeypot**: `HpOverview` là hợp đồng; đổi → sinh lại OpenAPI + sửa mock.
- **host**: lệnh `decoy_ip.add/remove` và `container.start/stop` (service `honeypot`) nhận IP đã kiểm; đổi định dạng → IP phụ không dựng được, bẫy `conflict`/`off`.

## Modifying: tệp trên volume dùng chung (`opencanary.conf`, `honeytokens.json`, `opencanary.jsonl`)
- **WP-08 (container honeypot)**: đổi tên tệp hoặc dạng dòng log → hit không vào, `opencanary.conf` không được đọc. Golden test `testdata/opencanary.golden.json`.

## Modifying: `DecoyIPs(ctx) []netip.Addr` (chưa có người gọi)
- **inventory/sensor-passive** (đề xuất, xem câu hỏi mở 2): nếu có người gọi, đổi → thiết bị ma xuất hiện trong kho.

## Disabling this module
- Trang Honeypot, panel bẫy trên trang thiết bị trống ("module đang tắt").
- `response`: trigger `honeypot` và các mẫu `tpl-trap-*`, `tpl-sweep-vlan` không còn sự kiện; quy tắc giữ nguyên, không lỗi.
- `notify`: không còn cảnh báo chạm bẫy. `logs/siem`: kênh `honeypot` không có bản ghi.
- Container `honeypot` dừng, IP phụ gỡ. `hp_*` giữ nguyên, bật lại thấy lại lịch sử.
