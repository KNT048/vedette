# Deferred — giao thức sensor (SP-0…SP-6; D-109…D-116)

Một tệp cho cả chuỗi lát (tên do lead đặt; SP-0 ở nhánh `docs/sensor-protocol`, SP-1…SP-6 ở các nhánh `feat/…`). Kế hoạch gốc: `docs/specs/sensor-protocol.md` §13, D-109…D-116.

## Bản đồ lát (mỗi lát một PR)

- [ ] 2026-11-10 — SP-0 docs-first: D-109…D-116, `sensor-protocol.md` viết lại thành hồ sơ appliance, ARCHITECTURE §2/§6/TB-9/A2/A4, DEPLOYMENT §2.2/§2.4/§6.1/§7/§12, host-api §15/§18, host CONTRACT INV-11/INV-17, CONTRACT/IMPACT/MANIFEST của `sensor-passive` và `sensor-active`, update-manifest `bundled`, tiêu chí S-INV-1 — vì sao để sau: chờ review và merge — ở đâu: nhánh `docs/sensor-protocol`
- [x] 2026-11-10 — SP-1 `core/pki` (`ca.go`, `issue.go`, `creds.go`) + `core/sensorlink` (`server.go`, `client.go`, `limits.go`, `errors.go`) + migration `core_sensor_cert`, chưa nối module; thêm một INV cho liên kết sensor vào `modules/core/CONTRACT.md` (vai, trần, kiểm serial mỗi request) — vì sao để sau: SP-0 chỉ tài liệu và không được sửa `modules/core/*` — ở đâu: `docs/specs/sensor-protocol.md` §3–§5, §7, §9; D-109, D-110 — **Done** (nhánh `feat/sensor-link`; migration `0007_core_sensor_cert`, INV-24; chưa merge)
- [ ] 2026-11-10 — SP-2 seam `Prober` + gói lá `modules/sensor-active/nmapargv` (`flagsFor`, `buildNmapArgs`, `ValidateNmapArgs`, `FuzzValidateNmapArgs`), refactor thuần, song song SP-1 — vì sao để sau: lát mã — ở đâu: `modules/sensor-active/CONTRACT.md` "Seam `Prober` và worker"; D-113 (1)(3)
- [ ] 2026-11-10 — SP-3 bộ điều phối `modules/sensor-active/{dispatch.go,worker/}` + `cmd/vedette-sensor/active.go` (cần SP-1, SP-2) — vì sao để sau: lát mã — ở đâu: `sensor-protocol.md` §6.4–§6.5; D-113 (4)(5)(6)
- [ ] 2026-11-10 — SP-4 tách `modules/sensor-passive/capture/`, handler nửa `core`, `cmd/vedette-sensor/passive.go`, `Status`/`SpanStats` từ heartbeat, hạn mức phía `core` (`budget_exhausted`) (cần SP-1) — vì sao để sau: lát mã — ở đâu: `modules/sensor-passive/CONTRACT.md` "Tách đôi"; D-111 (2), D-112, D-114 (1)
- [ ] 2026-11-10 — SP-5 `deploy/containers/{sensor,scan-base}/Containerfile`, test `go list -deps` của `cmd/vedette-sensor`, compose profile `dev` (`core` + `sensor-replay` + `scan` nmap giả; CI kiểm một thiết bị xuất hiện), cờ `-sensor-listen`/`-sensor-creds` của `core`, `ProtectedIPs`/honeypot/conn đổi sang nguồn địa chỉ của hộp, gỡ job `capture` và nmap cục bộ khỏi `core` sản xuất (cần SP-3, SP-4) — vì sao để sau: lát mã — ở đâu: `DEPLOYMENT.md` §6.2; D-114 (2)(5)
- [ ] 2026-11-10 — SP-6 `vedette-host`: mẫu unit `sensor`/`scan` (`User`, không `UserNS`, `NET_RAW`, volume khoá), `127.0.0.1:8444` và `--group-add` của `core`, unit `.volume`, khoá `sensor_uid`/`sensor_gid` của `host.conf`, `container.pull scan` chạy `podman build` argv cố định từ Containerfile hằng; chốt cách unit `scan` ghim image dựng tại chỗ (không có digest registry) và cách `container.start`/`rollback` kiểm nó (cần lát host 3-6, 3-7) — vì sao để sau: lát mã, phụ thuộc host — ở đâu: `docs/specs/host-api.md` §18 (đoạn cuối); host CONTRACT INV-17

## Rủi ro (cổng lab: VM Ubuntu 24.04, Ubuntu 26.04, Debian 13; không bao giờ trên mạng thật)

- [ ] 2026-11-10 — Podman cấp `NET_RAW` vào tập ambient cho `User=` không root trên Podman 4.9 và 5.x (AF_PACKET mở được, `nmap --privileged -sS` chạy được); không được thì đường lùi UID 0 + `NET_RAW`, vẫn không `UserNS` — vì sao để sau: cần Linux + Podman thật — ở đâu: D-114 (3), `DEPLOYMENT.md` §2.2, §6.1
- [ ] 2026-11-10 — nmap `-O` có thể cần thêm `NET_ADMIN` ngoài `NET_RAW`; nếu cần, quyết lại (D-114 cấm `NET_ADMIN`) thay vì cấp ngầm — vì sao để sau: cần lab — ở đâu: D-114 (3), sensor-active INV-4
- [ ] 2026-11-10 — netavark chuyển tiếp tới `127.0.0.1:8444` cho tiến trình ở namespace mạng của host (có thể cần `route_localnet`) — vì sao để sau: cần lab — ở đâu: `DEPLOYMENT.md` §7.3
- [ ] 2026-11-10 — `.volume` với `User=`/`Group=` trên Podman 4.9 (chủ thư mục volume thật sự là `core_uid:sensor_gid`) — vì sao để sau: cần lab — ở đâu: `DEPLOYMENT.md` §6.1, `host-api.md` §18
- [ ] 2026-11-10 — `NoNewPrivileges=true` cùng ambient capability (ambient giữ được qua `execve` của `vedette-sensor` và của `/usr/bin/nmap`; nmap không được có file capability hay setuid vì chúng xoá ambient) — vì sao để sau: cần lab — ở đâu: D-114 (3)
- [ ] 2026-11-10 — dựng `scan` cần kho gói Debian: hộp không tới được mirror thì không có quét chủ động, và Health của `sensor-active` phải nói rõ (`unavailable`, thông điệp về bản dựng) — vì sao để sau: SP-6 — ở đâu: D-113 (7), sensor-active INV-6
- [ ] 2026-11-10 — `core` khởi động lại giữa lúc quét bỏ lô đang chạy (theo thiết kế); lab kiểm lease 60 s giết nmap, không còn tiến trình mồ côi — vì sao để sau: cần lab — ở đâu: D-113 (4), `sensor-protocol.md` §11
- [ ] 2026-11-10 — `sensor` bị chiếm vẫn giả được quan sát hợp lý (cố hữu): chặn bởi hạn mức phía `core`, trần 32 dòng của inventory, `approved=false`, duyệt D-51; ghi nhận, không có cách sửa trong hồ sơ appliance — vì sao để sau: rủi ro chấp nhận, cần kien OK để Dropped — ở đâu: `sensor-protocol.md` §11

## Để sau (ngoài chuỗi SP)

- [ ] 2026-11-10 — sensor đặt ở máy khác: bootstrap kiểu kubelet, bind LAN, thu hồi có giao diện, danh tính theo sensor — vì sao để sau: không có story (D-24, D-57 (18)) — ở đâu: D-115, `sensor-protocol.md` phụ lục A
- [ ] 2026-11-10 — metadata SPAN và `logs.batch` trên dây, nơi khớp IOC, cùng syslog 514 và `NET_BIND_SERVICE` cho `sensor` — vì sao để sau: module `logs` chưa xây — ở đâu: D-112 (7), `sensor-protocol.md` §12 câu 4–5
- [ ] 2026-11-10 — hàng đợi đĩa có trần cho sensor (thay "không WAL") — vì sao để sau: chỉ cần khi sensor đi xa — ở đâu: D-112 (6)
- [ ] 2026-11-10 — job nuclei cho module `scan` (loại job mới trên kênh `jobs`, tăng proto) — vì sao để sau: module `scan` chưa xây — ở đâu: D-113, `DEPLOYMENT.md` §2.4
- [ ] 2026-11-10 — SNMP qua worker `scan` — vì sao để sau: D-84 (3), cần story và màn hình — ở đâu: sensor-active INV-10
- [ ] 2026-11-10 — giao diện thu hồi chứng chỉ sensor — vì sao để sau: không story; thu hồi hiện là xoay vòng + hạn 7 ngày — ở đâu: D-110 (5)
- [ ] 2026-11-10 — phân tích XML nmap ở worker (đường nâng cấp bị bỏ ở D-113) — vì sao để sau: thêm schema `core` phải kiểm lại — ở đâu: D-113

## Phát hiện khi viết SP-0 (lệch kế hoạch ↔ repo)

- [ ] 2026-11-10 — `internal/release/testdata/release/release-manifest.json` vẫn có `bundled: [{service: scan, name: nmap}]`; là vector thử nghiệm của mã (không sửa ở lát docs), đổi khi sinh lại vector ở lát chạm `internal/release` hoặc SP-6 — vì sao để sau: SP-0 không sửa mã/test — ở đâu: `internal/release/testdata/release/release-manifest.json:2`
- [ ] 2026-11-10 — `PRIVACY.md` luồng 6 + Settings → Privacy: bản dựng `scan` tải nmap từ kho Debian (`deb.debian.org`) **trong container**, cả trên hộp Ubuntu; mirror nội bộ của apt trên host không áp cho bước này; sửa cùng PR SP-6 (`rules/legal.md`) — vì sao để sau: SP-0 không được sửa `PRIVACY.md`/`web/` — ở đâu: `PRIVACY.md:12`, host CONTRACT INV-11
- [ ] 2026-11-10 — `THIRD_PARTY_NOTICES.md` dòng nmap ("installed from the OS repository by the installer") và `docs/LEGAL.md` dòng nmap ("installer cài từ repo OS") đổi thành "cài từ kho gói OS vào image `scan` do `vedette-host` dựng trên hộp" cùng PR SP-6 — vì sao để sau: đổi khi có mã dựng — ở đâu: `THIRD_PARTY_NOTICES.md:77`, `docs/LEGAL.md:10`
- [ ] 2026-11-10 — hoàn tác riêng `core` khi proto khác nhau để `sensor`/`scan` ở `426`: đường hoàn tác của `core` phải hoàn tác cả hai container — vì sao để sau: thuộc luồng cập nhật của `core` — ở đâu: `sensor-protocol.md` §10
- [ ] 2026-11-10 — đoạn "Unit Quadlet (D-105)" của `host-api.md` §18 vẫn ghi `sensor`: `NET_RAW` + `NET_BIND_SERVICE`; đoạn mới cuối §18 thay phần đó (để merge với `feat/host-awaiting` dễ); gộp chữ khi cả hai nhánh đã vào `main` — vì sao để sau: tránh xung đột với nhánh đang sửa §18 — ở đâu: `docs/specs/host-api.md` §18
- [ ] 2026-11-10 — dòng "Move nmap … into the `scan` container" của `.ai/deferred/feat-sensor-active.md` và dòng "Remote sensor …"/"Capture runs inside the main vedette process …" của `.ai/deferred/feat-sensor-passive.md` nay được SP-3/SP-4/SP-5 ở tệp này lo; đánh dấu Moved ở các tệp đó lúc dọn cuối phiên của chúng (luật deferred-work: không ghi vào tệp của phiên khác) — vì sao để sau: không phải tệp của phiên này — ở đâu: `.ai/deferred/feat-sensor-active.md`, `.ai/deferred/feat-sensor-passive.md`

## Phát hiện khi viết SP-1 (lệch kế hoạch ↔ mã)

- [ ] 2026-11-10 — SP-5 nối: `cmd/vedette` gọi `pki.Open` (một lần mỗi `secrets.Store`) rồi `Authority.Start(ctx, <creds>)` **trước khi nghe**, sau đó việc hằng ngày gọi `Authority.Renew` (hàm việc, chưa ai gọi), truyền `ModuleOn` từ `modreg` và `Server.HTTPServer(addr)` (dùng `GetCertificate`, không `Certificates`) — vì sao để sau: SP-1 không nối module — ở đâu: `core/pki/authority.go`, `core/sensorlink/server.go`
- [ ] 2026-11-10 — SP-6/host: chủ `core_uid:sensor_gid` và setgid của thư mục `<creds>/<role>` do unit `.volume` dựng; `pki.WriteBundle` chỉ đặt mode 0640 và không chown (ghi ở godoc) — vì sao để sau: thuộc host — ở đâu: `core/pki/creds.go`, DEPLOYMENT §6.1
- [ ] 2026-11-10 — **không có gì gia hạn CA** (10 năm): CA hết hạn → `pki.ErrCA`, `core` không dựng được liên kết sensor; cần đường gia hạn/đổi CA (cấp CA mới, giữ CA cũ trong pool một thời gian) trước năm thứ 10 — vì sao để sau: 10 năm nữa, cần quyết định thiết kế; không phải lỗi hôm nay — ở đâu: `core/pki/ca.go` `ErrCA`
- [ ] 2026-11-10 — bảng `core_sensor_cert` không bao giờ xoá hàng (mỗi lần khởi động thêm 2 hàng, mỗi lần xoay thêm 1); dọn hàng đã `retired_at` quá N ngày nếu bảng lớn — vì sao để sau: vài hàng mỗi ngày, chưa đo — ở đâu: `modules/core/migrations/sqlite/0007_core_sensor_cert.sql`
- [ ] 2026-11-10 — hạn đọc thân 10 s là hằng của `sensorlink` (không flag); đo lại khi có sensor thật qua `lo` (ARCHITECTURE §11) cùng các số ở spec §9 — vì sao để sau: các số là điểm xuất phát — ở đâu: `core/sensorlink/limits.go`
- [ ] 2026-11-10 — SP-4: `Backend.PassiveHeartbeat` nhận `drops` là map ≤ 64 khoá regex `^[a-z][a-z0-9_]{0,47}$`; **tập đóng** tên khoá chốt ở SP-4 và kiểm ở handler (decoder chỉ kiểm hình dạng) — vì sao để sau: SP-4 — ở đâu: spec §6.3 `drops`, `core/sensorlink/wire.go`
- [ ] 2026-11-10 — SP-3/SP-4: kiểm từng mục của `observations` (MAC/IP/field/value/confidence/`out_of_window`/văn bản sạch) và hạn mức chống ngập là việc của handler; `sensorlink` chỉ kiểm hình dạng cả thân (epoch, seq, 1…500 mục, kiểu, `seen_at` RFC 3339) — vì sao để sau: SP-4 — ở đâu: spec §6.2, `core/sensorlink/wire.go`
- [ ] 2026-11-10 — SP-3: `Client.Jobs` không tự lùi khi lỗi (chỉ `SendObservations` thử lại); vòng long-poll và lease 60 s của worker dùng `sensorlink.NewBackoff` — vì sao để sau: SP-3 — ở đâu: `core/sensorlink/client.go`
