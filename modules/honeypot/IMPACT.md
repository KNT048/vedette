# Honeypot — Change Impact Map

> Chưa có mã Go; các chữ ký dưới đây là kế hoạch (package `modules/honeypot`), chốt khi viết backend M5. Người gọi suy ra từ GUI mock và các hợp đồng module khác.

## Modifying: `Hits(ctx, HitFilter) ([]Hit, error)` — 3 người gọi
- **response** (`engine`: sự kiện trigger `honeypot`): đọc `source_ip`, `kind`, `label`; đổi tên trường/kiểu → trigger vỡ, quy tắc đang chạy khô/chạy thật ngừng khớp. Phải giữ `is_test` để loại hit thử.
- **ai** (công cụ chỉ-đọc `ask-my-data`): đổi cột → câu trả lời sai chứ không lỗi.
- **core/logs export** (`/core/logs/export?categories=honeypot`): đổi trường → file tải về thay đổi, kiểm tra offline hash không ảnh hưởng (hit không có hash chain).

## Modifying: `Subscribe(HitEvent)` / event `honeypot.hit` — 3 người nhận
- **notify**: nội dung cảnh báo (IP nguồn, thiết bị nguồn, 1 giờ sự kiện).
- **response**: nguồn trigger (D-50).
- **logs/siem**: kênh `honeypot` chuyển tiếp SIEM (S-LOG-3).

## Modifying: `Overview(ctx)`, `SetConfig(ctx, ip, hostname)` — GUI + host
- **web/features/honeypot**: `HpOverview` là hợp đồng; đổi → sinh lại OpenAPI + sửa mock.
- **host**: lệnh `net.decoy_ip.set/remove` nhận IP đã kiểm; đổi định dạng → IP phụ không dựng được, bẫy `conflict`/`off`.

## Modifying: `DecoyIPs(ctx) []netip.Addr`
- **inventory/sensor-passive** (đề xuất, xem câu hỏi mở 2): nếu có người gọi, đổi → thiết bị ma xuất hiện trong kho.

## Disabling this module
- Trang Honeypot, panel bẫy trên trang thiết bị trống ("module đang tắt").
- `response`: trigger `honeypot` và các mẫu `tpl-trap-*`, `tpl-sweep-vlan` không còn sự kiện; quy tắc giữ nguyên, không lỗi.
- `notify`: không còn cảnh báo chạm bẫy. `logs/siem`: kênh `honeypot` không có bản ghi.
- Container `honeypot` dừng, IP phụ gỡ. `hp_*` giữ nguyên, bật lại thấy lại lịch sử.
