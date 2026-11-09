# Logs — Change Impact Map

> Chưa có mã Go; chữ ký là kế hoạch (package `modules/logs`), chốt ở M5.

## Modifying: `IocHits(ctx, since time.Time, minConf float64) ([]IocHit, error)` — 3 người gọi
- **response** (sự kiện trigger `ioc_connection`; quy tắc chỉ tự hành động khi độ tin cậy cao): đổi tên/đơn vị `confidence` (0..1 ↔ 0..100; trigger field `confidence` của response là 0..100) → ngưỡng `gte 80` sai. Đổi `seen_via` → mất ngữ cảnh SPAN/syslog.
- **notify** (cảnh báo kết nối xấu): đổi trường → nội dung tin sai.
- **ai** (`ask-my-data`, `log-investigate` qua công cụ chỉ-đọc).

## Modifying: `Digest(ctx) (Digest, error)` — 2 người gọi
- **GUI logs** và **ai** (`log-digest` tóm tắt digest). Đổi cấu trúc `new/spikes/bad_connections` → sinh lại OpenAPI, sửa mock, sửa prompt skill.

## Modifying: `SiemForward(ctx, Event) error` — 4 nguồn sự kiện
- **core** (finding), **incident/alert**, **honeypot**, **logs** (bad_conn): đổi enum `SiemEvent` hoặc định dạng CEF/JSON → SIEM của khách phân tích sai; cần ghi vào CONTRACT và thông báo khách.

## Modifying: `Sources` CRUD / `SourceKind` (`KIND_IDS`)
- **web/features/logs** (`catalog.ts` bắt buộc có mục cho mỗi mã; `logs.test.tsx` kiểm). Thêm loại: thêm parser + mục catalog + test, không phải sửa chỗ khác.

## Modifying: `Retention(days)`
- **core/logs export** (`/core/logs/export?categories=device_logs,known_bad`): phạm vi dữ liệu xuất giảm theo lưu giữ. **core/data purge** phải xoá `logs_*`.

## Disabling this module
- Trang Logs, mục Cài đặt → SIEM, panel AI digest trong `logs.panels` trống/"đang tắt".
- `response`: trigger `ioc_connection`, `log_threshold`; mẫu `tpl-ioc-*`, `tpl-vpn-ban`, `tpl-ssh-acl`, `tpl-iot-shut` không có sự kiện. `notify`: mất cảnh báo kết nối xấu. `ai`: mất `log-digest`/`log-investigate`.
- Cổng 514/6514 đóng; thiết bị đang gửi syslog bị từ chối kết nối. `logs_*` giữ nguyên.
