# Core — Change Impact Map

Interface Go dự kiến (`core/…`). Mọi module gọi `core`; đổi chữ ký ở đây ảnh hưởng toàn bộ.

## Modifying: `module.Registry` — `Enabled(id) bool`, `Enable(ctx,id,withDeps)`, `Disable(ctx,id) (affected []string)`
- **Mọi module có phụ thuộc tuỳ chọn** (`feeds→inventory`, `inventory→notify`, `mitigation→ai/notify`, `scan→exposure`…): gọi `Enabled` trước khi dùng. Đổi ngữ nghĩa ⇒ sai chế độ suy giảm.
- **SPA** (`web/src/lib/modules.ts`, `ModulesSection`): đọc `GET /modules`, nút tắt hiện `affected`.

## Modifying: `module.Module` — `ID, Init, Routes, Jobs, Migrations, Enable, Disable, Health`
- **Mọi `modules/<id>/module.go`**: thêm/bớt phương thức = sửa tất cả module.

## Modifying: `audit.Append(ctx, Entry{User,Action,Target,Detail})`
- **Mọi handler ghi** (INV-2). Đổi lỗi trả về (không còn rollback) vi phạm SYS-3.
- **`/core/audit`, `/core/logs/export`**: đọc cột `group` = phần trước dấu chấm của `action`; đổi quy ước đặt tên action phá bộ lọc nhóm.

## Modifying: `secrets.Seal/Open/Last4`
- **feeds** (secret feed riêng), **notify** (token, SMTP, session Zalo cá nhân), **scan-credentialed** (khoá SSH), **sensor-active** (SNMP), **ai/response/agent-intake/auth-oidc** (nhóm B). Đổi định dạng khoá ⇒ cần migration giải/mã lại; mất khoá file ⇒ mọi kênh/feed có bí mật hỏng.

## Modifying: `exec.Run(ctx, bin, argv, opts)`
- **sensor-active** (nmap), **scan** (nuclei nếu tiến trình), **scan-credentialed** (gọi container greenbone qua `vedette-host`), **honeypot** (OpenCanary, nhóm B). Mở allowlist là thay đổi bảo mật: cần sửa CONTRACT + test.

## Modifying: `jobs.Schedule(name, spec, fn)`
- **feeds** (kéo theo lịch từng feed), **scan** (lịch, quét lại), **sensor-active** (cửa sổ khám phá), **exposure** (hết hạn IP), **notify** (gộp tin, im lặng). Job của module tắt bị gỡ ngay.

## Modifying: `events.Publish/Subscribe` và tên sự kiện
- **feeds→(inventory, scan, notify)**, **inventory→(mitigation, notify, sensor-active)**, **scan→mitigation**, **mitigation→notify**. Đổi tên sự kiện làm người nhận im lặng, không lỗi biên dịch: mỗi sự kiện có test hợp đồng ở bên phát.

## Modifying: `logexport.Register(category, Source)`
- **notify** (`alerts`), **scan** (`scan_probes`), **inventory** (`device_logs` nếu có), **ai/response/honeypot/logs** (nhóm B).

## Modifying: `hostclient` (socket `vedette-host`)
- **core** (OS, sao lưu, cập nhật image), **host** (mạng/SPAN, nhóm B), **sensor-passive** (đọc trạng thái SPAN), **scan-credentialed** (khởi động container greenbone).

## Disabling this module
Không thể (tier core). Gỡ `core` = không còn binary.
