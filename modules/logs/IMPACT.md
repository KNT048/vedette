# Logs — Change Impact Map

> WP-24 L1 có mã: `Service` (nguồn, sự kiện, lưu giữ, `Ingest`, `Purge`, `ExportDeviceLogs`), `LogsHandlers`, `Jobs`. Phần còn lại là kế hoạch, chốt theo từng lát.

## Modifying: `logs.Service.Ingest(ctx, []Line) (IngestResult, error)` (L1) — người gọi: listener (L2), sau này `sensorlink` (L6)
- Duy nhất đường vào của dòng log. Ghi **một** giao dịch trên `logs.db` mỗi lô (≤ `MaxBatch`), không bao giờ ghi cơ sở chính (INV-12): đổi sang ghi cơ sở chính là đưa lại rủi ro người ghi bị đói (#159/#160). Dòng của nguồn chưa khai bị bỏ và đếm (FORBID-5). Khi tổng byte vượt `MaxEventBytes`, `Ingest` khởi động một lượt `Purge` nền (gộp, không chờ): lượt đó ghi audit vào cơ sở chính (người ghi của core) nên dùng chung với mọi thứ khác; đổi trần hay mức 90% là đổi dung lượng đĩa tối đa của hộp. `Line.At` bị kẹp vào [bây giờ − lưu giữ, bây giờ]: listener không thể ghi dòng cũ hơn lưu giữ. Đổi `Line`/`IngestResult` = sửa listener. Đổi `sanitizeLine` đổi nội dung lưu và xuất (`device_logs`).

## Modifying: `logs.Service` (nguồn, `Events`, `SetRetention`, `Purge`), `logs.LogsHandlers`, `logs.Jobs`
- **web/features/logs** (mock là hợp đồng): mã lỗi `bad_kind|bad_name|bad_ip|bad_proto|bad_port|duplicate|not_found|bad_window|bad_days` và thông báo của mock; giới hạn mà `contract.ts` nói được bị bộ kiểm sinh trả `invalid` trước (D-73). Danh mục loại nguồn và giao thức cho phép là **một dữ liệu**: `content/logs/kinds.json`, `web/src/features/logs/catalog.ts` phải khớp (`kinds.parity.test.ts`).
- **cmd/vedette**: `logsService` (dùng chung bởi handler, job, xuất log), `logsInventory` (`DevicesOfKind(inventory.Kinds)`: một loại thiết bị mới ngoài `Kinds` thì không được đặt tên trong danh sách nguồn), `logsBox` (đọc `inventory.Settings` và `HostNet`), mở `logs.db` cạnh `vedette.db` trong `run` và `newStackWith`.
- **core/logexport**: nguồn `device_logs` đăng ký ở `registerLogSources`; đổi tên cột của `logs_events` là đổi tệp xuất. `device_logs` có trần riêng `ExportMaxBytes` (32 MiB) và dòng đánh dấu `id: "cut"` ở cuối; đổi trần của core (128 MiB) xuống dưới trần này sẽ làm nguồn này lại gây 413.
- **core (Kiên)**: `POST /core/data/purge` xoá `logs.db` từ danh sách tên tệp dữ liệu module của `cmd/vedette` (D-151); bản sao lưu không chứa nó. **Migration của `logs.db` phải chỉ thêm** (D-151): thêm cột/bảng/chỉ mục, không bao giờ DROP/RENAME/DELETE/UPDATE; `TestVolumeMigrationsAreAddOnly` chặn.

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
