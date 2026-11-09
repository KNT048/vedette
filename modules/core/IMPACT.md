# Core — Change Impact Map

Interface Go (`core/…`). Mọi module gọi `core`; đổi chữ ký ở đây ảnh hưởng toàn bộ. Đã có code (WP-03): `core/store`, `core/secrets`, `core/chain`, `core/audit`, `core/exec`; các mục còn lại là dự kiến.

## Modifying: `module.Registry` — `Enabled(id) bool`, `Enable(ctx,id,withDeps)`, `Disable(ctx,id) (affected []string)`
- **Mọi module có phụ thuộc tuỳ chọn** (`feeds→inventory`, `inventory→notify`, `mitigation→ai/notify`, `scan→exposure`…): gọi `Enabled` trước khi dùng. Đổi ngữ nghĩa ⇒ sai chế độ suy giảm.
- **SPA** (`web/src/lib/modules.ts`, `ModulesSection`): đọc `GET /modules`, nút tắt hiện `affected`.

## Modifying: `module.Module` — `ID, Init, Routes, Jobs, Migrations, Enable, Disable, Health`
- **Mọi `modules/<id>/module.go`**: thêm/bớt phương thức = sửa tất cả module.

## Modifying: `store` — `Open(ctx, path, log) (*DB, error)` (log không được nil; tạo file DB 0600, từ chối file có quyền group/other; reader mở `mode=ro`), `(*DB).Write(ctx, fn func(*sql.Tx) error) error`, `(*DB).Reader() *sql.DB`, `(*DB).Check(ctx) error`, `(*DB).Close() error`, `Migrate(ctx, db, module string, fsys fs.FS) error`, `NewID(prefix) string`, `FormatTS(time.Time) string`; `store/storetest`: `New(t)`, `NewMigrated(t, module, dir)`, `AssertMigrationsUsePrefix(t, module, fsys, prefix, base ...Migration)` (kiểm bằng hiệu ứng: áp `base` rồi migration của module, so `sqlite_master` và checksum từng bảng cũ); `store/coredb` (sqlc, `make generate`)
- **Mọi module**: mọi ghi đi qua `Write` (một writer, `BEGIN IMMEDIATE`); handler đọc dùng `Reader()` (query_only). Gọi `Write` lồng nhau trên cùng goroutine = deadlock (một kết nối ghi).
- **Mọi `modules/<id>/migrations/sqlite/`**: `Migrate` từ chối file có phần Down, bảng version `core_migration_<id>` (gạch ngang → gạch dưới); id module khớp `^[a-z][a-z0-9-]{0,31}$`. Module test gọi `AssertMigrationsUsePrefix` với `tables_prefix`.
- **Mọi nơi sinh ID/thời gian lưu DB**: `NewID` (`<prefix>-<26 base32 thường>`, prefix sai = panic), `FormatTS` (UTC, ms, `Z`). Đổi định dạng phá regex `id` của API và `CHECK` ts trong migration.
- **Truy vấn core**: sinh bởi sqlc từ `core/store/queries/*.sql` + migration; sửa bảng core thì chạy `make generate` (`generate-check` nằm trong `verify-go`).

## Modifying: `chain` — `Genesis`, `Canon(v) ([]byte, error)`, `HashCanonical(prev, map[string]any) (string, error)`, `NewVerifier(anchor) *Verifier` (`Add`, `Result`), `Result{OK, Count, BrokenAt, EntryID}`
- **`core_audit`, `ai_activity` (module ai), `resp_log` (module response)**: ONE formula (D-57 (14)): `hash = SHA-256(prev_hash + "\n" + canon(entry))`, entry = every column except `hash` and `seq`, `prev_hash` inside the entry (`HashCanonical` adds it), NULL column = `null`, keys sorted by code point (byte order). `HashPositional` was removed: resp_log uses the same call. Đổi byte nào = chuỗi cũ không verify được (DATA_MODEL §6 rule 9): phải thêm `canon_version`, không đổi tại chỗ. `TestChainVectors` kiểm bốn phần của `modules/core/testdata/chain_vectors.json` (dùng chung với phía TS; không sửa tay).

## Modifying: `audit.Append(ctx, Entry{User,Action,Target,Detail})` — thực tế: `audit.New(clock) *Log`, `(*Log).Append(ctx, tx *sql.Tx, Entry) error`, `audit.Verify(ctx, *sql.DB) (chain.Result, error)` (một read transaction = một snapshot; truyền `db.Reader()`), `audit.ErrInvalid`
- **`detail` rỗng** lưu NULL và được băm là `"detail":null`; hàng có `detail` là chuỗi rỗng (không do `Append` tạo) băm `"detail":""`.
- **`core_audit` còn trigger `BEFORE INSERT` chặn chèn trùng `id`/`hash`/`seq`** (REPLACE, INSERT OR REPLACE, UPSERT không lách được trigger DELETE/UPDATE).
- **`core_audit` bị trigger chặn UPDATE/DELETE**: đường prune retention (chưa làm) phải tự bỏ/tạo lại trigger trong cùng giao dịch và ghi `core_chain_anchor`.
- **Mọi handler ghi** (INV-2). Đổi lỗi trả về (không còn rollback) vi phạm SYS-3.
- **`/core/audit`, `/core/logs/export`**: đọc cột `group` = phần trước dấu chấm của `action`; đổi quy ước đặt tên action phá bộ lọc nhóm.

## Modifying: `secrets.Seal/Open/Last4` — thực tế: `secrets.New(key) (*Store, error)`, `GenerateKeyFile(path)`, `LoadKeyFile(path) ([]byte, error)` (từ chối symlink/FIFO), `(*Store).Seal(ctx, tx, purpose, plaintext, keepLast4) (id, last4, err)`, `Open(ctx, coredb.DBTX, id, purpose) ([]byte, error)`, `Replace(ctx, tx, id, purpose, plaintext, keepLast4) (last4, err)`, `Delete(ctx, tx, id) error`, kiểu `Value` (`NewValue`, `Reveal`; in/log/JSON đều ra `[redacted]`), `ErrNotFound`, `ErrDecrypt`, `ErrInvalid`
- **Không có hàm `Last4` riêng**: `last4` trả về từ `Seal`/`Replace` và nằm ở cột `core_secret.last4` (NULL khi bí mật < 8 ký tự hoặc `keepLast4=false`). AAD = `id|purpose`: đổi `purpose` của một bí mật đã lưu = không mở được nữa.
- **feeds** (secret feed riêng), **notify** (token, SMTP, session Zalo cá nhân), **scan-credentialed** (khoá SSH), **sensor-active** (SNMP), **ai/response/agent-intake/auth-oidc** (nhóm B). Đổi định dạng khoá ⇒ cần migration giải/mã lại; mất khoá file ⇒ mọi kênh/feed có bí mật hỏng.

## Modifying: `exec.Run(ctx, bin, argv, opts)` — thực tế: `exec.NewRunner(log, ...Binary) (*Runner, error)` (log không được nil), `(*Runner).Run(ctx, name string, args []string, stdin io.Reader) (Result, error)`, `Binary{Name, Path, Validate, MaxOutput}`, `Result{Stdout, Stderr, ExitCode, Truncated, Duration}`, `*ExitError`, `ErrNotAllowed/ErrNoDeadline/ErrBadArgs/ErrUnsupportedOS`
- **Không có registry toàn cục**: mỗi module dựng `Runner` riêng với allowlist của mình (`Validate` bắt buộc). `ctx` không có deadline = `ErrNoDeadline`; hết hạn = giết cả process group và trả `context.DeadlineExceeded`. Sau khi lệnh kết thúc (kể cả thoát bình thường) cả process group bị SIGKILL; Linux thêm `Pdeathsig`; con gọi `setsid` thoát được (nâng cấp: cgroup/systemd scope). Môi trường con chỉ có `PATH` và `LANG=C`; không truyền được biến môi trường.
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
