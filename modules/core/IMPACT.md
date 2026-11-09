# Core — Change Impact Map

Interface Go (`core/…`). Mọi module gọi `core`; đổi chữ ký ở đây ảnh hưởng toàn bộ. Đã có code: `core/store`, `core/secrets`, `core/chain`, `core/audit`, `core/exec` (WP-03); `core/apierr`, `core/server`, `core/modreg`, `core/jobs`, `modules/manifests.go` (WP-04a); các mục còn lại là dự kiến.

## Modifying: `modreg.Registry` (WP-04a, `core/modreg`) — thực tế: `modreg.Load(fs.FS) ([]Manifest, error)`, `modreg.New(ctx, Config{DB, Audit, Manifests, Version, Clock, Log}) (*Registry, error)`, `(*Registry).Enabled(id) bool`, `List() []State{ID, Tier, Depends, Enabled, EnabledAt}`, `Enable(ctx, tx, actor, id, withDeps) (Change, error)`, `Disable(ctx, tx, actor, id) (Change, error)`, `Publish(Change)`, `OnChange(func(id string, enabled bool))`, `Change{Enabled, Affected}`, `ErrManifest`
- **Không có hàm `Enable(ctx,id,withDeps)` một mình**: `Enable/Disable` chạy trong transaction của người gọi (ghi `core_module` + `core_audit` `module.enable|disable` cùng tx, `actor` = email), trả `Change`. **Chỉ gọi `Publish(Change)` SAU khi tx commit** (cập nhật cache + gọi `OnChange`); tx rollback thì bỏ `Change`, cache không đổi. Quyết định bật/tắt đọc `core_module` trong tx (dưới khoá ghi), không đọc cache. `Publish` bỏ qua Change cũ hơn Change đã áp (thứ tự commit).
- **`Enabled(id)`**: id không có manifest (module chưa có trong bản build, ví dụ `findings` tới WP-21) = tắt; `kind: component` (`host`) = có mặt, không có công tắc, không có hàng `core_module`; tier `core` luôn bật. `Enable`/`Disable` module lõi → 400 `core_module`; id lạ hoặc component → 404 `not_found`; thiếu phụ thuộc → 409 `missing_dependencies` + `missing[]` (đủ cả phụ thuộc bắc cầu, phụ thuộc trước) và không đổi gì, trừ khi `withDeps`.
- **Manifest**: `Load` đọc `<thư mục>/MANIFEST.yaml` (bỏ thư mục bắt đầu bằng `_`), kiểm id = tên thư mục, tier ∈ core/standard/optional, depends tồn tại và không phải component, không vòng, đúng một module `tier: core` (component không tính), `default:` nhận true/false/on/off (thiếu = bật cho core, tắt cho còn lại). Khởi động chèn hàng thiếu từ `default` (`ON CONFLICT DO NOTHING`, không ghi đè lựa chọn của quản trị viên) và sửa hàng `core` bị tắt.
- **Mọi module có phụ thuộc tuỳ chọn** (`feeds→inventory`, `inventory→notify`, `findings→notify`, `mitigation→ai`, `scan→exposure`…): gọi `Enabled` trước khi dùng. Đổi ngữ nghĩa ⇒ sai chế độ suy giảm.
- **`core/server`** (cổng module: route của module tắt = 404 y như route lạ) và **`core/jobs`** (`ModuleChanged` qua `OnChange`) đọc `Enabled`; **SPA** (`web/src/lib/modules.ts`, `ModulesSection`): đọc `GET /modules`, nút tắt hiện `affected`.
- **`core_module`, `core_job_run`** (migration `0002_core_module.sql`): bảng mới của core; `core_module.version` ghi `Config.Version` lúc chèn hàng.

## Modifying: `server` (WP-04a, `core/server`) — `server.New(Config{API oas.Handler, Auth Authenticator, Modules ModuleGate, Log, MaxBody}) (http.Handler, error)`, `Prefix = "/api/v1"`, `Authenticator{Authenticate(*http.Request) (Principal, error); CheckCSRF(*http.Request, Principal) error}`, `ErrNoSession`, `Principal{ID, Email, Role}`, `PrincipalFrom(ctx)`, `WithPrincipal`, `RequestIDFrom(ctx)`, `ModuleOf(routes.Operation) string`, `Fallback{oas.UnimplementedHandler; Log}` (có `NewError`), `servertest.Auth/Gate/StandardUsers` (đồ giả cho test)
- **Thứ tự lớp**: recover panic → request id (luôn sinh mới, bỏ id của client) → header bảo mật (CSP, nosniff, no-referrer, `Cache-Control: no-store`) → trần thân 1 MiB (413 `too_large`) → tra route bằng `FindPath` → cổng module (404, trước cả xác thực) → `Authenticate` (401) → vai từ `routes.Operations` (403, 401 trước 403) → CSRF cho POST/PUT/PATCH/DELETE đã xác thực (403 `csrf_invalid`; POST công khai được miễn) → ogen. Vai/cổng/CSRF không nằm trong handler.
- **WP-04b** (`core/auth`) cài `Authenticator`; ogen vẫn đòi cookie `vedette_session` có mặt trước khi gọi `HandleSession` (chỉ xác nhận principal đã có trong ctx).
- **Module handler** chỉ trả `*apierr.Error` cho lỗi nghiệp vụ; lỗi khác → 500 `internal`, ghi log kèm request id, không trả nội dung. Handler ghi lấy actor từ `server.PrincipalFrom(ctx)`.
- **Ánh xạ route → module** (`modules.go`): mặc định thẻ ogen, đè theo tiền tố đường dẫn (`/findings`, `/scans`, `/core/oidc|sso`, `/core/mcp`, `/install|intake|inventory/agents`, `/inventory/sensors`, `/core/network`, `/auth|me|modules|setup`). Thêm tiền tố đè = đổi cổng 404 của cả nhóm đường dẫn; test `TestEveryOperationMapsToAModuleWithAManifest` bắt module không có manifest (ngoại lệ có chủ ý: `findings`).
- **Composite handler** ở `cmd/vedette/handler.go`: `server.Fallback` + struct handler của từng module cùng độ sâu; hai module cài cùng một operation = lỗi biên dịch (ambiguous selector). Thêm module = nhúng struct handler của nó vào đó.

## Modifying: `apierr` (WP-04a, `core/apierr`) — `New(status, code, message) *Error`, `(*Error).With(key, value)`, `Error{Status, Code, Message, Extra}`, `Unauthenticated/Forbidden/CSRFInvalid/NotFound/Invalid(msg)/TooLarge/NotImplemented/Internal`, `As(err)`, `Write(w, *Error)`, hằng `Code*`
- **Mọi handler của mọi module**: cách DUY NHẤT dựng lỗi API; `code` phải có trong API_CONVENTIONS §3.3 (test `TestCodesAreCatalogued` kiểm các mã khai trong package; mã mới `csrf_invalid`, `not_implemented`, `internal` chưa có trong bảng). `message` tiếng Anh, không chứa chi tiết nội bộ. `Extra` nằm cạnh `code`/`message`.

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

## Modifying: `jobs` (WP-04a, `core/jobs`) — thực tế: `jobs.New(log, gate Gate, clock, ...Option) *Scheduler` (`Gate` = `Enabled(id) bool`; `WithRecorder(Recorder)`), `(*Scheduler).Add(Job{Module, Name, Every, Run func(ctx) error}) error`, `Run(ctx)` (chặn tới khi ctx xong và mọi job đã dừng), `ModuleChanged(id, enabled)` (nối với `modreg.Registry.OnChange`), `jobs.NewHistory(db) *History` (`Record`, `Recent`), `KeepRuns = 200`, `ErrInvalid`, `ErrStopped`
- **Không có `Schedule(name, spec, fn)` kiểu cron**: lịch là `Every` (khoảng nghỉ giữa hai lần chạy, tính từ lúc lần trước kết thúc); job chạy ngay khi module bật (lúc khởi động hoặc khi vừa bật) rồi mỗi `Every`. Một job không bao giờ chạy chồng chính nó; panic được bắt, ghi log kèm stack, tính là `error`.
- **Module tắt ⇒ `ModuleChanged` huỷ ctx của lần chạy đang diễn ra trước khi trả về** và job nằm im tới khi module bật lại; lần chạy bị huỷ ghi `cancelled`. Tắt scheduler (ctx của `Run`) huỷ job đang chạy, chờ chúng xong, vẫn ghi lịch sử (ctx ghi tách khỏi huỷ, 5 s). `ModuleChanged` đọc trạng thái từ `Gate`, không tin tham số `enabled`.
- **Job phải tôn trọng `ctx`**: nếu không, `Run` chờ nó mãi lúc tắt. Lỗi lưu tối đa 1000 ký tự.
- **`core_job_run`** (lần chạy xong, không có "running"): giữ 200 dòng mới nhất mỗi (module, job), prune cùng giao dịch với insert.
- **feeds** (kéo theo lịch từng feed), **scan** (lịch, quét lại), **sensor-active** (cửa sổ khám phá), **exposure** (hết hạn IP), **notify** (gộp tin, im lặng). Job của module tắt bị gỡ ngay.

## Modifying: `events.Publish/Subscribe` và tên sự kiện
- **feeds→(inventory, scan, notify)**, **inventory→(findings, notify, sensor-active)**, **scan→findings** (`scan.finding.confirmed`), **findings→(notify, response)** (`findings.finding.created|status_changed`; D-57 (6)). Đổi tên sự kiện làm người nhận im lặng, không lỗi biên dịch: mỗi sự kiện có test hợp đồng ở bên phát.

## Modifying: `logexport.Register(category, Source)`
- **notify** (`alerts`), **scan** (`scan_probes`), **inventory** (`device_logs` nếu có), **ai/response/honeypot/logs** (nhóm B).

## Modifying: `hostclient` (socket `vedette-host`)
- **core** (OS, sao lưu, cập nhật image), **host** (mạng/SPAN, nhóm B), **sensor-passive** (đọc trạng thái SPAN), **scan-credentialed** (khởi động container greenbone).

## Disabling this module
Không thể (tier core). Gỡ `core` = không còn binary.
