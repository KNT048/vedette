# Scan-credentialed Contract

> Tier: optional · Story: S-SCAN-5 · Last verified: 2026-11-09 (docs-first, chưa có code)

Nguồn hành vi: `web/src/features/scan/CredentialedTab.tsx`, `/scans/credentialed*` trong `scan/contract.ts` và `scan/mocks.ts`. GUI mới có quản lý tài khoản và thử kết nối; chưa có nút chạy quét hay xem kết quả.

## Invariants
- **INV-1**: Chỉ quét máy trong phạm vi `inventory` (đã xác nhận, không nằm trong loại trừ) và đã duyệt; `selectable=false` → 400 `out_of_scope`. Mọi kết nối của container greenbone chỉ tới `host:port` của tài khoản đã lưu (SYS-7). `TestContract_INV1_OnlyStoredTargets`
- **INV-2**: Chỉ cho máy có `device_kind ∈ {server, nas, web}` (400 `not_server`); mỗi tài sản một tài khoản (409 `exists`, muốn đổi khoá phải xoá rồi thêm lại).
- **INV-3**: `username` khớp `^[a-z_][a-z0-9_-]{0,31}$` (400 `bad_username`); `port ∈ 1..65535` (400 `bad_port`); `private_key` ≤ 16 384 ký tự và đúng định dạng khoá riêng (400 `bad_key`).
- **INV-4**: Khoá riêng SSH là bí mật: lưu bằng `core/secrets` (AES-256-GCM), API chỉ trả `key_last4`, không log, không vào export/backup/log xuất (SYS-4). Xoá tài khoản xoá khoá.
- **INV-5**: `POST …/test`: timeout 5 giây; kết quả `{ok, ts, message}` lưu vào `last_test`, thông điệp không chứa khoá hay phần riêng của khoá.
- **INV-6**: Greenbone chạy trong container riêng, không sửa, không nhúng vào binary (GPL/AGPL, legal.md); chỉ tắt/bật khi module bật, image ký cosign do `vedette-host` kéo.
- **INV-7**: Tôn trọng cửa sổ giờ, tốc độ và loại trừ của `scan`/`inventory`; dùng chung nút "Stop now" của lượt quét.
- **INV-8**: Kết quả Greenbone là dữ liệu không tin cậy (SYS-6): parser fail-closed, giới hạn kích thước; chỉ đi vào hệ thống qua `findings` với `basis` hợp lệ.
- **INV-9**: Mọi lần thêm/xoá/thử/quét ghi `core_audit` (`scan.credentialed.add|remove|test`), không có bí mật.

## Preconditions / Postconditions
- **PRE-1** (`POST /scans/credentialed`): `admin`, INV-1…4. **POST-1**: `CredTarget {id, asset_id, label, host, port, username, key_last4, last_test:null}` (201); khoá nằm trong `core/secrets`.
- **PRE-2** (`POST …/{id}/test`): `operator`, tài khoản tồn tại (404). **POST-2**: INV-5.
- **PRE-3** (`DELETE …/{id}`): `admin`. **POST-3**: 204; tài khoản và khoá biến mất; kết quả cũ giữ.
- **PRE-4** (`GET /scans/credentialed`): `viewer`. **POST-4**: `{items, enabled}`; `enabled` phản ánh trạng thái module và container.

## Forbidden
- **FORBID-1**: Trả hoặc log khoá riêng; lưu khoá dạng rõ.
- **FORBID-2**: Dùng tài khoản cho máy ngoài phạm vi, hoặc máy không phải server/nas/web.
- **FORBID-3**: Nhúng hay sửa Greenbone; ship GPL/AGPL trong lõi.
- **FORBID-4**: Chạy lệnh trên máy đích ngoài những gì Greenbone thực hiện; không ghi gì lên máy đích.
- **FORBID-5**: Dùng quyền root/sudo tài khoản; khuyến nghị tài khoản chỉ đọc (hiển thị trong giao diện).

## Dependencies
- **DEPENDS ON**: `core` (secrets, audit, hostclient), `inventory`, `scan`.
- **DEPENDED ON BY**: không (tiêu thụ bởi `findings` qua sự kiện).

## Endpoints owned (role tối thiểu)
| Route | Vai |
|---|---|
| `GET /scans/credentialed` | viewer |
| `POST /scans/credentialed/{id}/test` | operator |
| `POST /scans/credentialed`, `DELETE /scans/credentialed/{id}` | admin |

## Tables owned (`scancred_`)
`scancred_target` (tài khoản; khoá nằm ở `core_secret`), `scancred_run` (lượt quét), `scancred_result`.

## Events
- **Phát**: `scancred.run.finished {run_id, findings}`, `scancred.finding.reported {asset_id, cve}` (đề xuất).
- **Nhận**: `scan.run.stopped` (nút Stop now), `inventory.asset.deleted` (xoá tài khoản), `core.module.disabled`.

## Behaviour khi tắt
Không route `/scans/credentialed*` (tab hiện "off" qua `enabled:false` ở bản GUI), container greenbone dừng, không kết nối SSH. Tài khoản và khoá mã hoá giữ nguyên.

## Story và quyết định
S-SCAN-5. D-17 giấy phép minh bạch; D-55 container `greenbone` tuỳ chọn.

## Không khớp / câu hỏi mở
- `contract.ts` ghi "khoá riêng không bao giờ được lưu"; không thể đăng nhập SSH nếu không giữ khoá. Hợp đồng này lưu bằng `core/secrets` (SYS-4); cần sửa chữ trong GUI.
- Chưa có endpoint chạy quét hoặc xem kết quả credentialed; chưa rõ nó dùng `POST /scans/runs` (id `cred:<id>`?) hay endpoint riêng.
- Kéo feed NVT của Greenbone là luồng dữ liệu ra mới: chưa có trong `PRIVACY.md` (legal.md bắt buộc cập nhật cùng commit).
- `MODULES.md` ghi bảng `scan_*`, trùng tiền tố với `scan`; đề xuất `scancred_`.
- `basis` của finding từ credentialed chưa định nghĩa.
