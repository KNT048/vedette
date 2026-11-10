# Triển khai

Trạng thái: **mới, 2026-11-09**, theo D-55 (appliance + container) và D-56 (cấu hình mạng của hộp); mạng, decoy, unit Quadlet và xác minh image cập nhật theo D-99…D-107 (WP-07b phần 3, 2026-11-10); container `sensor`/`scan`, volume khoá và giao thức sensor theo D-109…D-116 (lát SP-0, 2026-11-10). Chưa có mã; các giá trị đánh dấu **(đề xuất)** là mặc định thiết kế để người cài đặt/test dựa vào, **chốt sau khi đo ở M2** (xem §14). Mọi thứ ship như code (`rules/ships-as-code.md`): máy mới dựng từ repo phải đạt cùng trạng thái, xác minh bằng **hiệu ứng** (dịch vụ chạy, cổng mở, cấu hình đúng), không bằng exit code.

Liên quan: [`ARCHITECTURE.md`](ARCHITECTURE.md) · [`specs/host-api.md`](specs/host-api.md) (lệnh của `vedette-host`) · `specs/*.md` · [`UPDATES.md`](UPDATES.md) · [`DATA_MODEL.md`](DATA_MODEL.md) · `../PRIVACY.md`.

Đường dẫn file ship trong repo (đề xuất): `deploy/install.sh`, `deploy/quadlet/*.tmpl` (unit sinh ra từ mẫu), `deploy/compose/compose.yaml`, `deploy/containers/*/Containerfile`.

## 1. Nguyên tắc

1. Hộp là **một host trong LAN**, không inline (D-3). Mọi kết nối ra Internet do hộp mở; không cần cổng vào từ Internet.
2. Một codebase Go, đóng gói thành nhiều image OCI (D-8, D-55); cùng image chạy trên appliance (Podman) và dev/CI (Compose).
3. Cấu hình sinh từ DB/repo, không sửa tay trên máy: unit Quadlet do `vedette-host` render từ mẫu + trạng thái module.
4. Module tắt thì container tương ứng không khởi động (SYS-5).
5. Image ghim **digest**, ký cosign; host từ chối image không ký (fail-closed).
6. Subagent/AI dev không SSH, không deploy, không quét mạng thật (`rules/agent-safety.md`); kiểm bằng lab và fixture.

## 2. Topology container

```
 host (Ubuntu 24.04 / 26.04, Debian 13; netplan + networkd, chrony)
 ├─ vedette-host.service (root, Type=notify)  ◄── /run/vedette/host.sock (0660 root:vedette)
 ├─ Podman (rootful) ── Quadlet units: /etc/containers/systemd/*.container|*.network|*.volume
 │
 │   mạng bridge nội bộ `vedette-int`  (subnet tự chọn không đụng LAN, đề xuất)
 │   ┌──────────────┐        ┌──────────────┐
 │   │ core         │        │ greenbone    │ (tuỳ chọn, chỉ bridge nội bộ)
 │   │ :8443 (pub.) │        └──────────────┘
 │   │ :8444 mTLS   │
 │   └─▲───────▲────┘
 │     │       │ 127.0.0.1:8444
 │     │     ┌─┴──────────┐  ┌──────────┐
 │     │     │ sensor     │  │ scan     │   mạng host (raw socket; bắt/nhìn LAN thật)
 │     │     └────────────┘  └──────────┘
 │     │ tệp config/ (ro) + log/ (D-89), không cổng mạng
 │   ┌─┴────────────────────────────────────────────┐
 │   │ honeypot  (netns `vedette-hp` do host giữ,     │
 │   │ mỗi decoy một link macvlan + MAC riêng, D-102) │
 │   └───────────────────────────────────────────────┘
 └─ NIC quản trị (IP) · NIC SPAN (không IP, promisc) · decoy: macvlan trên NIC quản trị, trong `vedette-hp`
```

Tóm tắt (chi tiết từng container ở §2.1–§2.4, giới hạn tài nguyên ở §2.5):

| Container | Image (đề xuất) | Mạng | Capability | Mặc định bật |
|---|---|---|---|---|
| `core` | `ghcr.io/knt048/vedette-core` | bridge `vedette-int`, publish `8443:8443` (D-105) | không (drop ALL) | luôn |
| `sensor` | `ghcr.io/knt048/vedette-sensor` | host | chỉ `NET_RAW` (ambient, `User=<sensor_uid>`, D-114) | khi `sensor-passive` bật |
| `honeypot` | `ghcr.io/knt048/vedette-honeypot` | namespace `vedette-hp` của host (`Network=ns:`), macvlan một MAC mỗi IP (D-102) | không (drop ALL; `ip_unprivileged_port_start=0` trong namespace) | khi `honeypot` bật |
| `scan` | `localhost/vedette-scan-nmap:<version>` dựng trên hộp từ image nền `ghcr.io/knt048/vedette-scan` đã ký (D-113 (7)) | host | chỉ `NET_RAW` (ambient, `User=<sensor_uid>`, D-114) | khi `sensor-active` bật (sau: `scan`/`exposure`) |
| `greenbone` | upstream Greenbone Community Containers, ghim digest | bridge `vedette-int` | theo upstream | khi `scan-credentialed` bật |

Registry: `ghcr.io/knt048/vedette-<service>`, hằng trong `vedette-host` (D-57 (3), D-104; câu hỏi A3 đã đóng); `ghcr.io` đã có trong `PRIVACY.md` luồng 6 (lát 3-7). Hộp qua proxy HTTP(S): đặt `[engine] env = ["https_proxy=…", "no_proxy=…"]` trong `/etc/containers/containers.conf` (hoặc `containers.conf.d/`); `vedette-host` chạy `podman pull` với môi trường tối thiểu nên không thừa hưởng biến proxy của shell.

### 2.1 core

| Mục | Giá trị |
|---|---|
| Nội dung | Go binary tĩnh + SPA nhúng + skill/gói khuyến nghị đã xác nhận (đi cùng bản phát hành, D-36); chạy `vedette serve` |
| Người dùng | không root, `User=<core_uid>:<core_gid>` **cố định** từ `host.conf`, không `UserNS=auto` (uid của peer phải ổn định cho kiểm `SO_PEERCRED` và kiểm chủ sở hữu của D-87; D-105); `cap_drop=ALL`; `no-new-privileges`; rootfs chỉ đọc + tmpfs `/tmp` |
| Mạng | bridge `vedette-int`; publish `8443:8443` **không kèm IP** (D-105): địa chỉ LAN duy nhất của hộp là địa chỉ quản trị (SPAN không IP, decoy nằm trong `vedette-hp`), nên đổi địa chỉ bằng `net.apply` không phải khởi động lại `core` và GUI tới được ở địa chỉ mới để xác nhận; `8444` (giao thức sensor, mTLS, D-109) không publish ra LAN, chỉ `127.0.0.1:8444` cho container mạng host |
| Volume | `vedette-data` → `/var/lib/vedette` (SQLite WAL, chỉ mục RAG, tài liệu tải lên); `/etc/vedette/master.key` → `/run/secrets/master.key` (ro, 0600); `/run/vedette` (**thư mục** chứa socket `vedette-host`, không bind-mount tệp socket; D-123); `vedette-creds-passive`, `vedette-creds-active` → `/var/lib/vedette-creds/{passive,active}` (**đọc-ghi chỉ ở `core`**: bó khoá của sensor, D-110 (4), D-114 (4)); mẫu cấu hình ro. `PodmanArgs=--group-add=<sensor_gid>` hằng để `core` ghi tệp khoá `0640 core_uid:sensor_gid` |
| Cổng | 8443/tcp (UI, API, SSE, intake osquery, script cài osquery, trang duyệt email, URL danh sách chặn) |
| Health check | `vedette healthcheck` (D-137): `GET https://127.0.0.1:8443/api/v1/setup` (route công khai có sẵn, đọc hàng `org` nên 200 nghĩa là máy chủ, router, kiểm Host và DB cùng trả lời) phải 200 trong 3 s; ghim đúng chứng chỉ của hộp ở `/var/lib/vedette/vedette-selfsigned.crt` nếu đọc được, không đọc được thì bỏ kiểm chứng chỉ (chỉ loopback, không gửi gì ngoài một GET không thông tin đăng nhập); không proxy, không mở DB, không cần khoá chủ. Chu kỳ 30 s, start-period 60 s, 3 lần hỏng thì unhealthy |
| Phụ thuộc | không (khởi động đầu tiên) |

### 2.2 sensor

| Mục | Giá trị |
|---|---|
| Nội dung | `vedette-sensor passive` (D-114): nửa `capture` của `sensor-passive` (DHCP/ARP/mDNS/SSDP/LLDP, bộ phân tích SPAN metadata, D-43); nhận `config` bằng long-poll, gửi quan sát và heartbeat (`specs/sensor-protocol.md`). Không nmap (D-113), không syslog (để sau, `logs` chưa xây), không DB (binary không liên kết `database/sql`/SQLite) |
| Người dùng | `User=<sensor_uid>:<sensor_gid>` từ `host.conf`, **không `UserNS`** (capability của user namespace con không phủ namespace mạng của host, D-114 (3)); `NoNewPrivileges`; rootfs chỉ đọc + tmpfs `/tmp` |
| Mạng | **host** (cần thấy LAN thật và card SPAN) |
| Capability | `DropCapability=ALL`, **chỉ** `AddCapability=NET_RAW` (bắt gói AF_PACKET; Podman đặt vào tập ambient cho uid không root: **cổng lab**, đường lùi UID 0 + `NET_RAW`). Không `NET_BIND_SERVICE` tới khi có syslog; không bao giờ `NET_ADMIN` (card SPAN được `vedette-host` đặt promisc, không IP, D-56) |
| Volume | `vedette-creds-passive` → `/var/lib/vedette-creds` **chỉ đọc** (bó khoá vai `passive`, `0640 core_uid:sensor_gid`); không volume ghi được, hàng đợi trong bộ nhớ (D-112 (6)) |
| Cổng | không cổng nghe nào |
| Health check | `vedette-sensor healthcheck` (D-137): tiến trình chạm tệp `/tmp/vedette-sensor.heartbeat` (tmpfs) sau mỗi heartbeat mà `core` nhận; check đọc tuổi tệp, phải nhỏ hơn 60 s (2 nhịp 30 s). Không cần khoá hay mạng. Chưa có nhịp nào trong start-period (30 s) là chưa khoẻ. Không kiểm gói từ SPAN (D-56: chỉ cảnh báo, không unhealthy; để sau). Module tắt thì `core` trả 409 và heartbeat dừng nên sensor thành unhealthy: host chỉ chạy `sensor` khi module bật |
| Kênh | mTLS, **sensor gọi ra `core`** (`https://127.0.0.1:8444`), vai `passive` |

### 2.3 honeypot

| Mục | Giá trị |
|---|---|
| Nội dung | **một** tiến trình OpenCanary (BSD-3) nghe mọi địa chỉ của container (D-90 (1)) + honey token; hit ghi ra `log/opencanary.jsonl`, cấu hình đọc từ `config/` (D-89) |
| Mạng | network namespace **`vedette-hp`** do `vedette-host` tạo và sở hữu (D-102); unit có `Network=ns:/run/netns/vedette-hp` và không mạng nào khác (không `vedette-int`, không đường tới `core`: hit đi qua tệp, D-89). Mỗi IP phụ/decoy là **một link macvlan với MAC riêng** trên card quản trị, host thêm/gỡ bằng `decoy_ip.*` mà không khởi động lại container. Trong namespace: `arp_ignore=1`, `arp_announce=2`, `rp_filter=2`, `ip_unprivileged_port_start=0`, bảng định tuyến riêng mỗi IP, và ruleset nft chặn mọi kết nối mới đi ra (chỉ trả lời kết nối vào) |
| Capability | **không** (`DropCapability=ALL`): `ip_unprivileged_port_start=0` là sysctl theo namespace nên bind 22/80/445/1433/3389 không cần `NET_BIND_SERVICE` |
| Volume | `config/` gắn chỉ đọc, `log/` ghi được (D-89; hạn mức đĩa ở WP-08); không cert, không DB |
| Cổng | 22, 80, 445, 1433, 3389 **chỉ trên IP phụ/decoy** (INV-2 của honeypot); không trên IP quản trị |
| Health check | `/vedette honeypot healthcheck` (D-137): đọc `opencanary.conf` (`/var/lib/vedette/honeypot/config/`, gắn chỉ đọc), lấy cổng của dịch vụ đầu tiên đang bật có khoá `.port` (`smb` không có: cổng đó của Samba) rồi nối TCP tới `127.0.0.1:<cổng>` trong 2 s (`lo` bật và `oif lo accept`, D-121 L8; nối từ loopback bị `core` bỏ như nguồn không thể có thật, D-89 (e)); không dịch vụ nào của OpenCanary đang bật thì khoẻ (không gì phải nghe). Không gọi `core`. **Image `honeypot` phải chứa `/vedette`** (binary tĩnh, 0755): image do dự án dựng ở WP-08, không phải image OpenCanary gốc |
| Số container | **một** container cho mọi IP (D-90 (1), D-102); "một container mỗi IP" của bản nháp bị bỏ (câu hỏi A5 đã đóng) |
| MAC | mặc định local-administered, sinh bằng HMAC theo IP và khoá của bản cài; `oui` tuỳ chọn cho tiền tố hãng của vai giả (`host-api.md` §6.6) |
| Ràng buộc | IP phụ phải nằm ngoài dải DHCP của khách (hướng dẫn trong wizard); macvlan không dùng được trên Wi-Fi và bị chính sách MAC của vSwitch VMware/Hyper-V chặn (§4) |

### 2.4 scan và greenbone

`scan`:

| Mục | Giá trị |
|---|---|
| Nội dung | `vedette-sensor active` (D-113): worker nmap của `sensor-active`; long-poll job `{shape, rate, targets, timeout_s}`, dựng argv bằng `nmapargv` + `ValidateNmapArgs`, chạy `/usr/bin/nmap` qua `core/exec`, trả XML; một job một lúc; lease 60 s. Job nuclei của `scan`/`exposure` để sau (loại job mới trên cùng kênh) |
| Image | **dựng trên hộp** bởi `vedette-host` (D-57 (2), D-113 (7), lát SP-6): Containerfile hằng `FROM` digest image nền `ghcr.io/knt048/vedette-scan` đã ký (Debian slim + `vedette-sensor`) + `apt-get install --no-install-recommends nmap` (kho gói OS, PRIVACY luồng 6); tag `localhost/vedette-scan-nmap:<version>`; `container.pull scan` kéo image nền theo digest (kiểm minisign, cosign như mọi service) rồi chạy `podman build` với argv cố định; kiểm hiệu ứng `nmap --version` trong image; dựng hỏng thì giữ image trước. Dự án không phân phối nmap (D-4, `LEGAL.md`) |
| Người dùng, capability | như `sensor` (§2.2): `User=<sensor_uid>:<sensor_gid>`, không `UserNS`, `DropCapability=ALL` + `AddCapability=NET_RAW` (nmap `--privileged`, D-84 (8)), `NoNewPrivileges`, rootfs chỉ đọc + tmpfs |
| Mạng | host |
| Ràng buộc | worker không giữ phạm vi: `core` là bên đồng ý duy nhất (D-26, D-84) và chỉ giao IPv4 riêng trong ba mẫu; mỗi probe ghi `sa_probe` trước khi giao job (INV-9) |
| Volume | `vedette-creds-active` → `/var/lib/vedette-creds` **chỉ đọc**; tmpfs cho đầu ra tạm; không volume bền |
| Health check | `vedette-sensor healthcheck` (D-137): như `sensor` (§2.2): tệp heartbeat của vai `active` còn trẻ hơn 60 s (heartbeat 30 s; poll job không tính, heartbeat là nhịp của liên kết) |

`greenbone` (tuỳ chọn, M7, S-SCAN-5): nhóm container upstream, ghim digest theo `release.json` đã ký; giao diện web Greenbone **không** publish ra LAN; `core` nói chuyện với `gvmd` qua socket GMP trên volume dùng chung (**đề xuất**); chạy `vedette-int`; SSH key quét có đăng nhập lưu bằng `core/secrets`. GPL/AGPL: container riêng, không sửa (D-55).

### 2.5 Giới hạn tài nguyên và health (đề xuất, cho hộp 4 nhân / 8 GB)

| Container | CPU | RAM | PIDs | Ghi chú |
|---|---|---|---|---|
| `core` | 2 | 2 GiB | 512 | SQLite + RAG FTS5 |
| `sensor` | 1 | 512 MiB | 256 | trần chỉnh được ở Box network (D-56); mục tiêu ≤5% một nhân ở 100 Mbps |
| `honeypot` | 0.5 | 256 MiB | 128 | một container cho mọi decoy (D-102) |
| `scan` | 2, `CPUWeight` thấp | 1 GiB | 512 | burst theo việc; cửa sổ giờ + tốc độ (S-SCAN-4) |
| `greenbone` (cả nhóm) | 2 | ~3 GiB (đo lại) | theo upstream | bật thì nên 16 GB RAM (đề xuất) |

Tổng không kể greenbone ≈ 3,75 GiB, chừa phần còn lại cho OS và page cache. Swap tắt trong container (`memory-swap` = `memory`). Cách đo: `podman stats` trong bài test tải M2 (1.000 thiết bị, 50k IOC), ghi vào `docs/project-map/`. Hạn mức vượt thì container bị OOM-kill và `Restart=always` dựng lại; sự kiện hiện ở trang sức khoẻ module.

## 3. `vedette-host`

Tiến trình systemd chạy root, rất nhỏ, thay `vedette-updater` của D-53 (D-55). `core` gọi qua socket Unix `/run/vedette/host.sock` (quyền 0660 `root:vedette`, không lắng nghe TCP). Danh sách lệnh, tham số, mã lỗi, tiến trình trực tiếp: `specs/host-api.md`. Tại đây chỉ nêu **trách nhiệm** và **bất biến**.

| Nhóm | Trách nhiệm | Căn cứ |
|---|---|---|
| Cập nhật OS | kiểm bản vá (apt), cài bản vá bảo mật / tất cả, unattended-upgrades, cần khởi động lại, hạn hỗ trợ bản phát hành, lịch theo cửa sổ bảo trì, reboot ngay/theo lịch; nâng bản phát hành OS chỉ hướng dẫn | D-53, S-CORE-7 |
| Mạng | danh sách card và bộ đếm giao diện; card quản trị (DHCP/tĩnh, gateway, DNS) qua tệp netplan duy nhất của host, có cửa sổ xác nhận; card SPAN (không IP, promisc); IP phụ cho bẫy (macvlan trong namespace `vedette-hp`); NTP (chrony). Số MAC thấy được và lần nhận gói cuối do `sensor` đo, không do host | D-56, D-99…D-102, D-106 |
| Container | kiểm index, manifest (minisign) và chữ ký cosign trong manifest bằng mã của dự án, kéo image theo digest, render + áp unit Quadlet từ mẫu hằng, start/stop/restart, health gate, hoàn tác về `previous` (kèm khôi phục DB khi `rollback.safe=false`) | D-55, D-103…D-105 |
| Cập nhật Vedette | lấy `release.json` ký, kiểm cohort, tuần tự thay container, health gate, rollback | D-53, D-55, `UPDATES.md` |
| Sao lưu | lưu và xoay vòng snapshot do `core` tạo, khôi phục, kiểm dung lượng | §10 |
| "This box" | đọc dpkg trả danh sách gói (độ tin cậy 1.0) để `inventory` khớp lỗ hổng | D-53, S-INV-5 |
| Trạng thái | trạng thái/health của từng container, log cập nhật | §11 |

Bất biến (kiểm bằng test hợp đồng ở `modules/core/`):

- Chỉ chạy **lệnh trong danh sách cố định**; tham số kiểm kiểu trước khi dùng; không shell, không chuỗi lệnh tự do (SYS-1, SYS-2).
- Một việc tại một thời điểm (khoá); việc đang chạy không bị bỏ qua khi `core` khởi động lại.
- Sao lưu DB trước thao tác có thể làm hỏng dữ liệu (cập nhật Vedette, nâng cấp gói hệ thống lớn); kiểm sức khoẻ sau; mọi bước ghi kiểm toán (SYS-3).
- Không có đường nào cho AI gọi `vedette-host`; chỉ mã của `core` sau khi người dùng đủ quyền thực hiện thao tác (hoặc lịch đã cấu hình) (ARCHITECTURE §7.2).
- Không có logic nghiệp vụ, không đọc DB của `core`.
- Idempotent: gọi lại cùng lệnh không đổi trạng thái đã đạt.

## 4. Ma trận hỗ trợ OS và phần cứng

Quy tắc: OS ngoài bảng thì `install.sh` dừng và báo rõ (không cài dở).

| Hệ điều hành | Kiến trúc | Trạng thái | Ghi chú |
|---|---|---|---|
| Ubuntu 24.04 LTS | x86_64, arm64 | **hỗ trợ** (D-57 (1)) | Podman 4.9 có Quadlet (không drop-in, không `Notify=healthy`: D-105); netplan + networkd sẵn; NTP mặc định timesyncd, installer thay bằng chrony (D-106) |
| Ubuntu 26.04 LTS | x86_64, arm64 | **hỗ trợ** (D-57 (1)) | Podman 5.x (kiểm lại phiên bản ở lab); netplan + networkd; chrony là mặc định (từ 25.10) |
| Debian 13 | x86_64, arm64 | **hỗ trợ** (D-57 (1)) | Podman 5.x; installer cài `netplan.io` (1.1.2 trong trixie) và chrony (D-99, D-106) |
| Debian 12 | — | **không** hỗ trợ ở kiểu Appliance (D-57 (1)) | Podman 4.3, chưa có Quadlet (từ 4.4); dùng kiểu Chỉ container |
| Khác (RHEL, Alpine…) | — | không hỗ trợ ở kiểu Appliance | Dùng kiểu Chỉ container |

**Mạng của hộp là netplan với renderer `networkd` trên cả ba bản (D-99).** `vedette-host` sở hữu **độc quyền** netplan: chỉ có `/etc/netplan/90-vedette.yaml` (0600) do host ghi, cộng bản phủ tạm `/run/netplan/90-vedette.yaml` trong cửa sổ xác nhận (D-100). `install.sh` (WP-08, idempotent, xác minh bằng hiệu ứng) phải: cài `netplan.io` trên Debian; ghi `/etc/cloud/cloud.cfg.d/99-vedette-network.cfg` với `network: {config: disabled}` để cloud-init không viết lại mạng; dời mọi `*.yaml` khác trong `/etc/netplan` và `/run/netplan` sang chỗ khác (giữ để khôi phục tay); không để ifupdown hay NetworkManager quản card; rồi để host ghi tệp đầu tiên từ cấu hình đang chạy. Thiếu bước nào thì mọi `net.apply` bị `412 net_backend_unsupported` (host không bao giờ đọc tệp netplan nó không viết). Đồng hồ: installer cài chrony và sở hữu `chrony.conf` (chỉ `sourcedir /etc/chrony/sources.d`, không pool của distro); host ghi `vedette.sources` (D-106).

| Hạng mục | Tối thiểu (mục tiêu 1.000 thiết bị) | Ghi chú |
|---|---|---|
| CPU/RAM/đĩa | 4 nhân / 8 GB / SSD 64 GB | + `greenbone`: nên 16 GB (đề xuất) |
| NIC | 1 (quản trị) | SPAN cần thêm 1 card (USB được); chuyển SPAN/TAP trên switch (hướng dẫn theo hãng ở Box network, D-56) |
| Mạng có dây | bắt buộc cho SPAN, bẫy macvlan | Wi-Fi không hỗ trợ macvlan/SPAN |
| VM | được | vSwitch phải cho phép promiscuous/giả MAC cho macvlan và SPAN (VMware: Promiscuous Mode, Hyper-V: MAC spoofing; Proxmox bridge thường ổn); không thì decoy im lặng: kiểm bằng hiệu ứng ở Box network và trong lab |
| Đồng hồ | NTP bắt buộc (chrony, D-106) | TOTP, chứng chỉ mTLS, hết hạn token duyệt phụ thuộc giờ (D-56) |
| Kiểu cài | Ubuntu 24.04/26.04 hoặc Debian 13 mới bằng script; ISO/VM image **sau** (D-55) | |

## 5. Hai kiểu cài (D-55)

| | **Appliance** | **Chỉ container** |
|---|---|---|
| Cài bằng | `deploy/install.sh` trên Ubuntu 24.04/26.04 hoặc Debian 13 sạch (sau: ISO/VM image) | Compose/Quadlet trên Docker hoặc Podman sẵn có của khách |
| Runtime | Podman + Quadlet, rootful | Docker hoặc Podman, khách chọn |
| `vedette-host` | có | không |
| Cập nhật OS, reboot (S-CORE-7) | trong GUI | **không**; GUI hiện hướng dẫn, không có nút |
| Box network (D-56): card, SPAN, IP phụ, NTP | cấu hình trong GUI | **không**; khách tự cấu hình trước (card SPAN promisc, macvlan); GUI chỉ đọc trạng thái nếu thấy được |
| Tự cập nhật Vedette | có, theo lô, health gate, rollback | **không**; GUI báo có bản mới và hiện lệnh `pull`/`up`; khách tự bấm |
| Xác minh cosign | `vedette-host` tự kiểm (minisign cho index/manifest, cosign trong manifest) trước khi kéo theo digest (D-103) | khách tự xác minh bằng `cosign verify` (lệnh hiện trong GUI) hoặc policy Podman |
| Sao lưu | snapshot DB + xoay vòng bởi host | snapshot DB trong volume do `core` tạo; khách tự sao lưu volume |
| SPAN / syslog 514 | đủ | được nếu khách chạy `sensor` ở mạng host và card đã sẵn sàng |
| Bẫy trên IP phụ | macvlan trong namespace `vedette-hp` do host tạo (D-102) | macvlan do khách tạo, hoặc bẫy trên IP chính ở cổng không trùng dịch vụ host (bị hạn chế) |
| "This box" (S-INV-5) | danh sách gói dpkg của host | không đọc được host (câu hỏi mở A7 ở ARCHITECTURE) |
| Greenbone | được | được nếu khách có đủ tài nguyên |
| Cảnh báo | — | Docker `-p` đi vòng tường lửa UFW (xem §12): ràng buộc cổng vào đúng IP |

Hạn chế của kiểu Chỉ container phải hiện rõ ở GUI (Cài đặt → Updates, Box network): "Not available in container-only mode" kèm lý do, không ẩn mục (S-CORE-1: nói rõ chỗ thiếu vì sao thiếu). Phiên bản Docker/Podman tối thiểu: chốt ở M2.

## 6. Unit mẫu

Các file dưới đây là **ví dụ minh hoạ**; cờ dòng lệnh, tên biến, đường dẫn chốt ở M2. Unit `vedette-<service>.container` thật (văn bản ở đây là mẫu; mẫu hằng trong `host/ops/quadlet.go` và các tệp golden `host/ops/testdata/units/` là bản chính, D-123) do `vedette-host` dựng **toàn bộ** từ mẫu hằng trong binary (D-105): chỗ điền duy nhất là digest, dòng `[Install] WantedBy=` (bật/tắt bền, vì unit sinh ra không `systemctl enable`/`disable` được), `core_uid`/`core_gid` và `sensor_uid`/`sensor_gid` của `host.conf` (D-114); không drop-in (Podman 4.9 trên Ubuntu 24.04 không tài liệu hoá), không sửa tay. Test hợp đồng trên unit đã dựng: không `--privileged`, capability theo bảng §2, `Network=host` chỉ `sensor`/`scan`, honeypot chỉ `ns:/run/netns/vedette-hp`; `sensor`/`scan` có `User=<sensor_uid>:<sensor_gid>`, không `UserNS`, chỉ `NET_RAW`, mỗi cái chỉ gắn volume khoá của vai mình và chỉ đọc (D-114).

### 6.1 Quadlet (appliance)

`/etc/containers/systemd/vedette-int.network`

```ini
[Network]
NetworkName=vedette-int
Subnet=172.30.77.0/24
Gateway=172.30.77.1
# Subnet do vedette-host chọn để không đụng dải LAN (D-32)
```

`/etc/containers/systemd/vedette-data.volume`

```ini
[Volume]
VolumeName=vedette-data
```

`/etc/containers/systemd/vedette-creds-passive.volume` (và `vedette-creds-active.volume` như vậy; D-114 (4))

```ini
[Volume]
VolumeName=vedette-creds-passive
# chủ phía host: core ghi, nhóm của sensor đọc (Quadlet 4.9 có User=/Group= cho .volume)
User=<core_uid>
Group=<sensor_gid>
```

`/etc/containers/systemd/vedette-core.container`

```ini
[Unit]
Description=Vedette core
After=network-online.target vedette-host.service
Wants=network-online.target

[Container]
ContainerName=vedette-core
Image=ghcr.io/knt048/vedette-core@sha256:<digest>
Pull=never
Network=vedette-int.network
# Không kèm IP (D-105): đổi địa chỉ quản trị bằng net.apply không phải khởi động lại core
PublishPort=8443:8443
PublishPort=127.0.0.1:8444:8444
Volume=vedette-data.volume:/var/lib/vedette
Volume=/var/lib/vedette-honeypot/config:/var/lib/vedette/honeypot/config
Volume=/var/lib/vedette-honeypot/log:/var/lib/vedette/honeypot/log:ro
Volume=/etc/vedette/master.key:/run/secrets/master.key:ro
# cả thư mục, không phải tệp socket: bind-mount một tệp giữ inode cũ và mất kết nối khi host tạo lại socket (D-123)
Volume=/run/vedette:/run/vedette
# bó khoá của sensor (D-110 (4)): đọc-ghi chỉ ở core
Volume=vedette-creds-passive.volume:/var/lib/vedette-creds/passive
Volume=vedette-creds-active.volume:/var/lib/vedette-creds/active
ReadOnly=true
Tmpfs=/tmp
NoNewPrivileges=true
DropCapability=ALL
# core_uid:core_gid của /etc/vedette/host.conf; KHÔNG UserNS=auto (uid của peer phải cố định, D-105)
User=<core_uid>:<core_gid>
LogDriver=journald
# --group-add hằng: Quadlet 4.9 không có GroupAdd=; để core ghi tệp khoá 0640 core_uid:sensor_gid (D-114 (4))
PodmanArgs=--memory=2g --memory-swap=2g --cpus=2 --pids-limit=512 --group-add=<sensor_gid>
HealthCmd=/vedette healthcheck
HealthInterval=30s
HealthStartPeriod=60s
HealthRetries=3
Exec=-listen :8443 -key /run/secrets/master.key

[Service]
Restart=always
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
```

`/etc/containers/systemd/vedette-sensor.container`

```ini
[Unit]
Description=Vedette sensor (passive capture)
After=vedette-core.service
Wants=vedette-core.service

[Container]
ContainerName=vedette-sensor
Image=ghcr.io/knt048/vedette-sensor@sha256:<digest>
Pull=never
Network=host
# sensor_uid:sensor_gid của /etc/vedette/host.conf; KHÔNG UserNS (raw socket trên mạng host, D-114 (3))
User=<sensor_uid>:<sensor_gid>
DropCapability=ALL
# Podman đặt capability thêm vào tập ambient cho uid không root (kiểm ở lab; đường lùi UID 0 + NET_RAW)
AddCapability=NET_RAW
NoNewPrivileges=true
ReadOnly=true
Tmpfs=/tmp
Volume=vedette-creds-passive.volume:/var/lib/vedette-creds:ro
LogDriver=journald
PodmanArgs=--memory=512m --memory-swap=512m --cpus=1 --pids-limit=256
HealthCmd=/vedette-sensor healthcheck
HealthInterval=30s
HealthStartPeriod=30s
HealthRetries=3
Exec=passive --core https://127.0.0.1:8444 --creds /var/lib/vedette-creds/sensor.pem

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

Sensor chạy uid không root, không `UserNS`, chỉ `NET_RAW` (D-114; câu hỏi A4 ở ARCHITECTURE đã đóng). Không `NET_BIND_SERVICE` tới khi `logs` (syslog 514) được xây. Lab kiểm: AF_PACKET mở được và `nmap -sS`/`-O` chạy được với ambient `NET_RAW` cùng `NoNewPrivileges` trên Podman 4.9 và 5.x; không được thì đổi sang UID 0 + `NET_RAW` (vẫn không `UserNS`).

Không có `vedette-lan.network` (network macvlan của Podman) và không có một container mỗi IP: decoy là link macvlan do `vedette-host` đặt trong namespace `vedette-hp` (D-102), một container dùng chung.

`/etc/containers/systemd/vedette-honeypot.container`

```ini
[Unit]
Description=Vedette honeypot (all decoys, namespace vedette-hp)
# vedette-host tạo /run/netns/vedette-hp rồi mới báo READY=1 (Type=notify)
After=vedette-host.service
Requires=vedette-host.service

[Container]
ContainerName=vedette-honeypot
Image=ghcr.io/knt048/vedette-honeypot@sha256:<digest>
Pull=never
Network=ns:/run/netns/vedette-hp
# ip_unprivileged_port_start=0 trong namespace: không cần NET_BIND_SERVICE
DropCapability=ALL
NoNewPrivileges=true
ReadOnly=true
Tmpfs=/tmp
UserNS=auto
Volume=/var/lib/vedette-honeypot/config:/var/lib/vedette/honeypot/config:ro
Volume=/var/lib/vedette-honeypot/log:/var/lib/vedette/honeypot/log
LogDriver=journald
PodmanArgs=--memory=256m --memory-swap=256m --cpus=0.5 --pids-limit=128
HealthCmd=/vedette honeypot healthcheck
HealthInterval=30s
HealthRetries=3

[Service]
Restart=always

[Install]
# có khi module bật; container.stop persist=true dựng lại unit không có mục này (D-105)
WantedBy=multi-user.target
```

Thư mục trên hộp là hằng `/var/lib/vedette-honeypot` (D-123 (1)); `core` gắn cả thư mục vào `/var/lib/vedette/honeypot`, mặc định của `-honeypot-dir` (D-89); `config/` và `log/` gắn ở **cùng đường dẫn tuyệt đối** trong container vì `opencanary.conf` ghi đường dẫn log. Đường dẫn thật và quyền của `log/` khi dùng `UserNS=auto` chốt ở WP-08.

`/etc/containers/systemd/vedette-scan.container`: như `sensor` (cùng `User=<sensor_uid>:<sensor_gid>`, không `UserNS`, `DropCapability=ALL`, `AddCapability=NET_RAW`, `NoNewPrivileges`, `ReadOnly`, tmpfs), nhưng `Image=` là image dựng trên hộp `localhost/vedette-scan-nmap:<version>` (D-113 (7); cách ghim image dựng tại chỗ trong unit chốt ở lát SP-6), `Volume=vedette-creds-active.volume:/var/lib/vedette-creds:ro`, `PodmanArgs=--memory=1g --memory-swap=1g --cpus=2 --pids-limit=512 --cpu-shares=128`, `Exec=active --core https://127.0.0.1:8444 --creds /var/lib/vedette-creds/sensor.pem`.

`/etc/systemd/system/vedette-host.service` (khung; thông số hardening ở §12)

```ini
[Unit]
Description=Vedette host helper
After=network-online.target

[Service]
# READY=1 sau khi Ops.Start xong và socket đã mở: namespace vedette-hp, decoy, khôi phục run dở (D-102)
Type=notify
ExecStart=/usr/lib/vedette/vedette-host
RuntimeDirectory=vedette
RuntimeDirectoryMode=0750
# thư mục chạy giữ nguyên khi host dừng/khởi động lại: core gắn thư mục /run/vedette và nối lại socket mới (D-123)
RuntimeDirectoryPreserve=yes
Restart=on-failure
# Bao quanh các bước Start có cận (D-121): startHP 120 s + hoàn tác lúc khởi động 180 s + áp lại decoy 120 s
# + kiểm core 60 s + khôi phục restore dở 300 s + dừng/khởi động core 120 s + đặt lại unit dở 60 s (D-123) = 960 s = 16 phút.
TimeoutStartSec=16min
# KHÔNG đặt bất kỳ tuỳ chọn namespace hệ tệp nào ở đây (D-121, §12): PrivateTmp, ProtectHome, ProtectSystem, ...

[Install]
WantedBy=multi-user.target
```

Thứ tự khởi động: `vedette-host` (sẵn sàng khi `READY=1`) → `core` → `sensor`/`scan`/`honeypot` → `greenbone`. Cả bộ dựng lại sau reboot nhờ `WantedBy=multi-user.target` (service có module tắt thì unit không có dòng này, D-105).

### 6.2 Docker Compose (dev/CI tương đương)

Dùng **cùng image**. Khác biệt: mạng host/macvlan chỉ có ý nghĩa trên Linux có card thật (profile `lab`); trên máy dev macOS/Windows dùng profile `dev` (bridge + cổng cao + fixture pcap).

```yaml
# deploy/compose/compose.yaml (minh hoạ)
services:
  core:
    image: ghcr.io/knt048/vedette-core@sha256:<digest>   # dev: tag dev build tại chỗ
    command: ["serve"]
    ports: ["127.0.0.1:8443:8443", "127.0.0.1:8444:8444"]   # chỉ localhost
    volumes: ["vedette-data:/var/lib/vedette", "./dev/master.key:/run/secrets/master.key:ro"]
    read_only: true
    tmpfs: ["/tmp"]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 2g
    cpus: 2
    pids_limit: 512
    healthcheck: {test: ["CMD", "/vedette", "healthcheck"], interval: 30s, start_period: 60s, retries: 3}
  sensor:
    profiles: ["lab"]            # cần Linux + card thật
    image: ghcr.io/knt048/vedette-sensor@sha256:<digest>
    network_mode: host
    user: "<sensor_uid>:<sensor_gid>"   # không userns (D-114)
    cap_drop: [ALL]
    cap_add: [NET_RAW]
    read_only: true
    volumes: ["vedette-creds-passive:/var/lib/vedette-creds:ro"]
    command: ["passive", "--core", "https://127.0.0.1:8444", "--creds", "/var/lib/vedette-creds/sensor.pem"]
  sensor-replay:
    profiles: ["dev"]            # phát lại pcap mẫu, không đụng mạng thật
    image: ghcr.io/knt048/vedette-sensor@sha256:<digest>
    volumes: ["./fixtures:/fixtures:ro", "vedette-creds-passive:/var/lib/vedette-creds:ro"]
    command: ["passive", "--core", "https://core:8444", "--creds", "/var/lib/vedette-creds/sensor.pem", "--replay", "/fixtures"]
  honeypot:
    profiles: ["dev"]
    image: ghcr.io/knt048/vedette-honeypot@sha256:<digest>
    ports: ["127.0.0.1:2222:22", "127.0.0.1:8080:80"]       # cổng cao, không macvlan
    cap_drop: [ALL]
  honeypot-lab:
    profiles: ["lab"]
    image: ghcr.io/knt048/vedette-honeypot@sha256:<digest>
    networks: {lan: {ipv4_address: 192.168.10.241}, default: {}}
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
  scan:
    profiles: ["lab"]            # image dựng tại chỗ từ image nền + nmap của kho gói OS (D-113 (7))
    image: localhost/vedette-scan-nmap:<version>
    network_mode: host
    user: "<sensor_uid>:<sensor_gid>"
    cap_drop: [ALL]
    cap_add: [NET_RAW]
    volumes: ["vedette-creds-active:/var/lib/vedette-creds:ro"]
    command: ["active", "--core", "https://127.0.0.1:8444", "--creds", "/var/lib/vedette-creds/sensor.pem"]
  # dev: thêm "scan" với nmap giả (exectest) để CI chạy core + sensor-replay + scan (lát SP-5)
  # greenbone: profile "greenbone", dùng compose upstream ghim digest (M7)
networks:
  lan:
    driver: macvlan
    driver_opts: {parent: eth0}
    ipam: {config: [{subnet: 192.168.10.0/24, gateway: 192.168.10.1, ip_range: 192.168.10.240/29}]}
volumes:
  vedette-data:
  vedette-creds-passive:
  vedette-creds-active:
```

Không có `vedette-host` trong compose: dev/CI dùng **host giả** (`vedette-host --fake`, trả fixture qua socket cùng giao thức) để test các màn hình Updates và Box network (đề xuất). CI chạy test hợp đồng sensor↔core qua compose (profile `dev`: `core` + `sensor-replay` + `scan` với nmap giả, kiểm một thiết bị xuất hiện; lát SP-5). Volume khoá trong compose: `core` gắn đọc-ghi ở `/var/lib/vedette-creds/{passive,active}`.

## 7. Cổng và mạng

### 7.1 Vào hộp

| Cổng | Từ | Vào | Mục đích | Khi nào mở |
|---|---|---|---|---|
| 8443/tcp | LAN | `core`, trên IP quản trị (địa chỉ LAN duy nhất của hộp; publish không kèm IP, D-105) | UI, API, SSE, intake osquery, script cài osquery (`/install/*`), trang duyệt email, URL danh sách chặn cho firewall kéo (D-44, D-46, D-34) | luôn |
| 8444/tcp | nội bộ | `core` (`:8444` trong container), publish **chỉ** `127.0.0.1:8444` | giao thức sensor mTLS cho `sensor`/`scan` (D-109) | luôn; **không ra LAN** |
| 514 UDP/TCP (TLS tuỳ cấu hình) | LAN | `sensor` | nhận syslog | **để sau**: `logs` chưa xây; unit `sensor` chưa có `NET_BIND_SERVICE` (D-114) |
| 22, 80, 445, 1433, 3389 | LAN | `honeypot` trên **IP phụ/decoy** (namespace `vedette-hp`, D-102) | bẫy | `honeypot` bật |
| — | Internet | — | **không có cổng vào** | — |

### 7.2 Ra khỏi hộp

| Cổng | Tới | Mục đích | PRIVACY |
|---|---|---|---|
| 443/tcp | nguồn feed (D-36) | kéo feed | luồng 1 |
| 443/tcp | GitHub Releases (`core` tải index/manifest) + `ghcr.io` (`vedette-host` kéo image theo digest) | bản phát hành ký, image | luồng 6 (`ghcr.io` và host blob của nó, `pkg-containers.githubusercontent.com`, đã thêm ở lát 3-7) |
| 443/tcp | provider AI, dịch vụ tra cứu cần key, Slack (Socket Mode), Telegram (long polling), Zalo, tín hiệu ẩn danh, CT log + điểm dò IP | theo cấu hình | luồng 2–5, 8, 9 |
| 80,443/tcp | mirror apt (`archive.ubuntu.com`, `security.ubuntu.com`, `deb.debian.org`, `security.debian.org` hoặc mirror nội bộ) | cập nhật OS (D-53) | luồng 6 |
| 53 UDP/TCP | DNS | phân giải | — |
| 123/udp | NTP: `pool.ntp.org` mặc định hoặc máy chủ admin nhập (chrony, D-106) | đồng hồ (D-56) | luồng 10 |
| 25/465/587 | SMTP của khách | email cảnh báo, mã đăng nhập | luồng 5 |
| LAN ra | thiết bị | SNMP 161/udp, SSH/HTTPS tới API thiết bị (kết nối harness/response), Wazuh API, nmap trong phạm vi, SIEM forward | theo cấu hình |

### 7.3 Mạng container

- `vedette-int`: bridge nội bộ, subnet do `vedette-host` chọn không trùng LAN/VPN đã khai báo.
- `sensor`, `scan`: host network, tới `core` qua `127.0.0.1:8444` (cổng publish của `core`; netavark chuyển tiếp tới `127.0.0.1` cho tiến trình ở namespace của host có thể cần `route_localnet`: kiểm ở lab).
- `honeypot`: chỉ namespace `vedette-hp` do host giữ (D-102): mỗi IP phụ/decoy (ngoài dải DHCP) một link macvlan và MAC riêng; không chân `vedette-int`; nft trong namespace chặn kết nối mới đi ra. Lưu lượng macvlan không qua netfilter của host, nên luật nằm trong chính namespace.
- Card SPAN: không IP, promisc, bật bởi `vedette-host`; sensor đọc bằng AF_PACKET; kiểm bằng hiệu ứng: gói/giây > 0 và thấy ≥1 MAC khác MAC của hộp (D-56).
- Kiểm bằng hiệu ứng sau cài: `ss -ltnup` trên host không có cổng nghe ngoài bảng §7.1; từ máy lab (không phải mạng thật) cổng ngoài bảng không mở.

## 8. Lần khởi động đầu (first boot)

Kiểu Appliance, `deploy/install.sh` (idempotent; chạy lại không đổi gì khi đã đạt trạng thái):

| Bước | Việc | Xác minh bằng hiệu ứng |
|---|---|---|
| 1 | Preflight: OS/phiên bản/kiến trúc trong §4, Podman ≥ 4.4, ≥ 1 NIC có IP, giờ đồng bộ, đủ RAM/đĩa | sai OS thì dừng và in lý do; không cài dở |
| 2 | Cài gói ghim phiên bản (Podman, netavark, UFW nếu thiếu; `netplan.io` trên Debian, chrony, iproute2, nftables); giao netplan độc quyền cho host (§4, D-99); cài `vedette-host` (gói/binary đã xác minh chữ ký) | `vedette-host` active (`Type=notify` đã báo sẵn sàng); socket tồn tại, quyền 0660 `root:vedette`; `/etc/netplan` chỉ còn `90-vedette.yaml`; `chronyc -N -c sources` có nguồn |
| 3 | Tạo user hệ thống `vedette`, thư mục, khoá bí mật 0600 (`/etc/vedette/master.key`); khoá công khai minisign và cosign **nhúng trong `vedette-host`**, không có `policy.json` (D-103) | `vedette-host -bootstrap` từ chối manifest hay chữ ký cosign sai |
| 4 | `vedette-host -bootstrap` (không qua socket) kiểm index, manifest, chữ ký cosign, kéo image theo digest và ghi các unit Quadlet đầu tiên; khởi động `core` | `core` healthy trong 300 s; 8443 nghe trên IP quản trị (địa chỉ LAN duy nhất của hộp) |
| 5 | In `https://<IP>:8443` và **mã cài đặt một lần** trên console | endpoint `/setup` từ chối khi thiếu mã (D-75) |
| 6 | Trình hướng dẫn trên web (D-22, không SSH): tổ chức, quản trị viên + 2FA, dải LAN có **tiền tố** (D-32), ô cam kết quét (D-26), gói module (nhỏ/vừa/đầy đủ/tuỳ chọn), kênh thông báo, AI (tuỳ chọn), Box network (D-56) | mỗi bước ghi `core_audit`; module tắt không có container chạy |
| 7 | Thiết bị đầu tiên "This box" xuất hiện trong kho (D-53, S-INV-5) | danh sách gói dpkg có, không xoá được |
| 8 | Kéo feed lần đầu | `feeds` báo thành công cho nguồn bật; ≤ 5 MB/giờ sau đó |

Chứng chỉ TLS cho 8443: sinh tự ký lúc cài, cho phép tải chứng chỉ của khách lên (đề xuất, câu hỏi B3). Cookie `Secure` nên yêu cầu TLS luôn bật. Đã có trong `cmd/vedette` (WP-04b phần 2): `-tls-cert`/`-tls-key` dùng cặp của khách; thiếu mà `-listen` khác loopback thì tự sinh cặp P-256 10 năm (`vedette-selfsigned.crt/.key`, mode 0600) cạnh file DB lúc khởi động đầu, SAN gồm `-hosts`, tên loopback, tên máy và địa chỉ giao diện; HTTP thuần chỉ trên loopback; `-hosts` là danh sách `Host` được trả lời (421 cho tên khác, chống DNS rebinding).

## 9. Nâng cấp và hoàn tác

Thay A/B slot của binary bằng **image ký** (D-55). Tổng quan kênh: `UPDATES.md`.

### 9.1 Phần mềm Vedette

| Bước | Việc |
|---|---|
| 1. Phát hiện | `core` (lịch hoặc người dùng bấm "Check") lấy `index.json` và release manifest từ GitHub Releases (D-36, D-81; `update-manifest.md`), kiểm bằng `internal/release` rồi đưa cho `vedette-host`, host kiểm lại độc lập (D-103). Manifest **ký minisign** (xác minh offline được): kênh `stable`/`beta`, digest từng image, phần trăm rollout, phiên bản host tối thiểu, `revoked[]`, ghi chú migration |
| 2. Cohort | `cohort = hash(install_id) mod 100` (`UPDATES.md` §2). Tự động chỉ nhận khi `cohort < rollout`. Rollout 10 → 50 → 100 sau 24 giờ không báo lỗi; `stable` sau `beta` ≥ 7 ngày |
| 3. Pre-flight | đủ đĩa, không việc khác đang chạy, trong cửa sổ bảo trì (nếu tự động), Podman đủ phiên bản |
| 4. Kéo | `container.pull` từng service: host kiểm minisign, thu hồi và chữ ký cosign trong manifest **trước**, rồi `podman pull ghcr.io/knt048/vedette-<service>@sha256:…`; sai ký hoặc thiếu ký thì dừng, không đổi gì (D-103, D-104) |
| 5. Sao lưu | `core` tạo bản chụp DB nhất quán (D-87) và truyền `snapshot` cho `container.start` của `core`; host tạo bản `pre_update` trong run đó (D-104) |
| 6. Thay | `container.start`: host dựng lại unit (digest mới), `daemon-reload`, restart theo thứ tự `sensor`/`scan`/`honeypot` → `greenbone` → **`core` sau cùng** (`host-api.md` §6.8). Migration chạy khi `core` khởi động, **chỉ expand**: bản mới chỉ thêm, bản liền trước vẫn chạy được trên schema mới (đề xuất; test hợp đồng ở CI) |
| 7. Health gate | `core` healthy ≤ 120 s, các container khác ≤ 60 s, cộng smoke: đăng nhập trả 200, scheduler tick, sensor heartbeat. Cửa sổ và ngưỡng (đề xuất) |
| 8. Kết thúc | ghi `core_audit` (ai/lịch, từ/đến phiên bản, digest, kết quả); giữ image trước 1 đời, xoá đời cũ hơn |

Hỏng ở bước 6–7: `vedette-host` tự quay về unit/digest trước trong cùng run, kiểm health lại, báo lên UI (`reverted`, `unit_failed`). DB chỉ được khôi phục (từ bản `pre_update` của bước 5) khi manifest khai `rollback.safe=false`, và GUI báo rõ dữ liệu mất (D-104).

**Rollback thủ công** (S-CORE-2): nút "Rollback" trên trang Updates (`container.rollback`) chuyển về `previous` đã xác minh (còn giữ 1 đời); với `rollback.safe=false` GUI xin xác nhận mất dữ liệu và host khôi phục DB trong cùng run (D-104). Xác minh bằng hiệu ứng: phiên bản hiển thị đúng và health gate qua.

Ngoại tuyến (mạng cách ly): bundle ký chứa index, manifest + image dạng OCI archive; `vedette bundle import` kiểm minisign và cosign như đường online. Phía host (`source: bundle`) **để sau** (`412 bundle_unsupported` ở WP-07b phần 3).

### 9.2 Hệ điều hành (D-53)

- Settings → Updates kiểm **OS trước tiên**: bản phát hành, kernel, gói có bản vá bảo mật, cần reboot, hạn hỗ trợ.
- Thực thi qua `vedette-host`: danh sách lệnh apt cố định, tham số kiểm; cài bản vá bảo mật / tất cả; unattended-upgrades; lịch theo cửa sổ bảo trì; reboot ngay hoặc theo lịch. Nâng bản phát hành OS chỉ hướng dẫn, không tự làm.
- Sao lưu DB trước, health gate sau; tiến trình hiện trực tiếp.
- Sau reboot: tất cả container tự lên (§6.1); hộp không "xong" cho tới khi health gate qua.
- Nếu OS update nâng Podman/netavark: host kiểm lại phiên bản tối thiểu và health container; vi phạm thì cảnh báo và dừng tự động.
- Mirror apt trỏ về nội bộ được (PRIVACY luồng 6).

## 10. Sao lưu và khôi phục

| Mục | Thiết kế |
|---|---|
| Nội dung | snapshot SQLite nhất quán + tài liệu RAG đã tải + cấu hình sinh ra từ DB. Chỉ mục RAG dựng lại được. Unit Quadlet **không** cần sao lưu (sinh lại) |
| Khoá bí mật | **mặc định không** kèm `/etc/vedette/master.key` (bản sao lưu không tự mở được bí mật). Khôi phục thiếu khoá thì nhập lại khoá AI/feed/kênh (câu hỏi mở A6) |
| Lịch | hằng ngày + trước mỗi cập nhật; giữ 7 bản gần nhất (đề xuất); chỗ lưu `/var/backups/vedette`, tuỳ chọn thư mục ngoài (USB/NFS) do khách gắn. Không có đám mây (mọi luồng ra phải ở `PRIVACY.md`) |
| Xuất/xoá | Cài đặt → Data: xuất toàn bộ (không có bí mật), xoá toàn bộ (S-CORE-6, D-22) |
| Khôi phục | máy mới: `install.sh` → tải bản sao lưu ở trình hướng dẫn → `vedette-host` đưa vào volume → `core` khởi động, chạy migration → nhập lại bí mật nếu thiếu khoá |
| Xác minh | bài "restore drill" ở CI/lab: sao lưu → dựng máy mới → khôi phục → so số thiết bị, phát hiện, audit chain còn nguyên |

## 11. Log và quan sát

| Nguồn | Cách thu |
|---|---|
| Log container | `LogDriver=journald`, mỗi container một tag; log ứng dụng JSON có cấp độ, request ID; **không bao giờ log secret** (SYS-4); giới hạn `journald` (`SystemMaxUse`, đề xuất 1 GiB) |
| Sức khoẻ | trang sức khoẻ module + container (trạng thái/health do `vedette-host` báo), lịch sử job, lỗi feed, health sensor (có gói/không, D-56) |
| Kiểm toán | `core_audit` (SYS-3), gồm lệnh gửi `vedette-host`; nhật ký AI/phản ứng hash-chain, giữ mặc định 1 năm (D-48) |
| Tải về | Cài đặt → Data tải toàn bộ log hộp (kiểm toán, AI, phản ứng, probe quét, cảnh báo, log thiết bị) dạng JSON/CSV (S-CORE-6) |
| Chuyển tiếp | SIEM syslog/CEF/JSON (S-LOG-3), tắt mặc định |
| Báo lỗi | gói chẩn đoán đã lọc, người dùng xem trước và tự gửi (D-42); hộp không tự gửi gì |

Không có endpoint metrics kiểu Prometheus: chưa có story, không làm (`rules/no-imagined-features.md`); đề xuất thành story nếu cần.

## 12. Hardening

**Host.**
- `vedette-host.service`: `Type=notify` (host báo `READY=1` sau khi tạo namespace `vedette-hp`, áp lại decoy và khôi phục run dở, D-102); hạn chế mức có thể mà vẫn chạy apt/netplan/podman và vẫn để namespace `vedette-hp` hiện ra cho podman (**không** có tuỳ chọn namespace hệ tệp nào, D-121): `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET` (`AF_PACKET` cho ARP probe và kiểm gateway, D-101; root chỉ gửi/đọc khung ARP 42 byte, không đọc lưu lượng khác), `LockPersonality=yes`, `RestrictRealtime=yes`, `SystemCallArchitectures=native`, `MemoryDenyWriteExecute=yes`, `RuntimeDirectoryMode=0750`, `RuntimeDirectoryPreserve=yes`. Giới hạn thiệt hại chủ yếu dựa vào **danh sách lệnh cố định**, không dựa vào sandbox. `TimeoutStartSec=16min` (cận của các bước `Ops.Start`, D-121, D-123).
- **`vedette-host.service` không được đặt tuỳ chọn namespace hệ tệp nào (D-121).** `ip netns add vedette-hp` bind-mount lên `/run/netns/vedette-hp` và container `honeypot` (podman, ngoài unit) phải thấy mount đó. `systemd.exec(5)`: các tuỳ chọn namespace hệ tệp đặt lan truyền mount ở chế độ `slave` (mount của host hiện vào unit, mount của unit không ra host), và "Setting this option to `shared` does not reestablish propagation in that case" nên `MountFlags=shared` không cứu được. Cấm: `PrivateTmp=`, `PrivateDevices=`, `ProtectSystem=`, `ProtectHome=`, `ProtectKernelTunables=`, `ProtectKernelModules=`, `ProtectKernelLogs=`, `ProtectControlGroups=`, `ProtectProc=`, `ProcSubset=`, `ReadOnlyPaths=`, `ReadWritePaths=`, `InaccessiblePaths=`, `ExecPaths=`, `NoExecPaths=`, `BindPaths=`, `BindReadOnlyPaths=`, `TemporaryFileSystem=`, `PrivateMounts=`, `MountAPIVFS=`, `MountImages=`, `RootDirectory=`, `RootImage=`. `RestrictNamespaces=` phải để trống hoặc cho phép `net` và `mnt` (`ip netns` gọi `unshare`/`setns`). Giữ các tuỳ chọn không đụng mount ở trên (`RestrictAddressFamilies`, `LockPersonality`, `RestrictRealtime`, `SystemCallArchitectures`, `MemoryDenyWriteExecute`).
- UFW/nftables mặc định chặn vào, mở theo module bật (8443; 514 khi `logs` bật). `vedette-host` quản lý luật; kiểm bằng hiệu ứng (§7.3).
- Không gắn `podman.sock`/`docker.sock` vào bất kỳ container nào; không `--privileged`.
- SSH quản trị host nằm ngoài Vedette; khuyến nghị chỉ cho phép từ dải quản trị.

**Container.**
- `cap_drop=ALL` + capability tối thiểu (§2); `no-new-privileges`; rootfs chỉ đọc + tmpfs; seccomp/AppArmor mặc định của Podman; giới hạn tài nguyên (§2.5).
- Secret qua file mount ro, không qua biến môi trường.
- Non-root ở mọi container; `core` chạy `User=<core_uid>:<core_gid>` cố định, **không** `UserNS=auto` (kiểm peer của socket host và kiểm chủ sở hữu của D-87 cần uid ổn định); `sensor`/`scan` chạy `User=<sensor_uid>:<sensor_gid>` cố định, **không** `UserNS` (capability của user namespace con không phủ namespace mạng của host; D-114 sửa D-105 (5)); các container khác `UserNS=auto` (D-105). Unit là unit hệ thống, Podman rootful (đóng câu hỏi hệ thống/người dùng).
- Image: ghim digest, SBOM CycloneDX, quét `trivy`/`govulncheck` trong CI, cosign.

**Rootless.** Appliance dùng Podman **rootful** có hardening trên, vì: macvlan, mạng host + raw socket và mạng nội bộ chung giữa các container đều cần quyền thật; thử rootless sẽ buộc thêm lớp shim làm tăng bề mặt. Rootless dùng được ở dev/CI (profile `dev`) và ở kiểu Chỉ container cho phần `core`/`scan` không cần raw. Xác nhận bằng PoC ở M2 (B4).

**Podman với Docker và UFW.** Docker chèn luật iptables của `-p` vào chuỗi `DOCKER` nên cổng được publish **đi vòng** luật UFW (hành vi đã biết); đây là lý do D-55 chọn Podman cho appliance. Với Podman vẫn chỉ publish thứ cần publish (chỉ 8443) và không tin vào UFW một mình: mọi bản cài kiểm bằng `ss`/quét từ lab. Kiểu Chỉ container trên Docker: bind cổng vào IP cụ thể trong Compose (`192.168.10.5:8443:8443`), hoặc đặt luật ở chuỗi `DOCKER-USER`.

**Rủi ro riêng của bẫy.** Honeypot là bề mặt tấn công chủ đích từ LAN. Giảm thiểu: container riêng, `DropCapability=ALL` (không cả `NET_BIND_SERVICE`, nhờ `ip_unprivileged_port_start=0` của namespace), không DB, **không cổng mạng nào tới `core`** (hit qua tệp, D-89), `core` coi mọi dữ liệu từ bẫy là không tin cậy (SYS-6). Chặn đi ngang từ bẫy ra LAN: lưu lượng macvlan đi thẳng ra NIC, không qua netfilter của host, nhưng **có** qua netfilter của chính namespace `vedette-hp`; host đặt ở đó một ruleset nft hằng `ct state established,related accept; ct state new drop` ở hook output, nên bẫy chỉ trả lời được kết nối vào (D-102; câu hỏi B5 đã đóng). Kiểm hiệu ứng ở lab: `nft list ruleset` trong namespace và thử kết nối ra từ container.

## 13. Môi trường phát triển

| Việc | Lệnh | Ghi chú |
|---|---|---|
| Giao diện + dữ liệu mẫu | `make dev` (http://localhost:5173) | mock API (MSW), không cần container |
| Kiểm FE | `make verify` (tsc, lint, vitest, build rồi dọn) | `rules/build-artifacts.md` |
| E2E | `make e2e` (Playwright) | |
| Fixture KEV/EPSS thật | `make fixtures` | |
| Backend (từ M2) | `go test ./...`, `golangci-lint`; `go test ./modules/<id>/... -run Contract` | thêm vào `make verify` khi có Go |
| Cả bộ container | `docker compose --profile dev up` (hoặc `podman compose`) | cùng image với appliance; host giả thay `vedette-host` |
| Tích hợp mạng thật | profile `lab` trên VM Linux có card thật | **không quét/probe IP ngoài lab** (`agent-safety.md`); dùng fixture pcap/syslog |
| Nối GUI vào backend (từng module) | `make dev-api` (mặc định `REAL=core`; `make dev-api REAL=core,inventory`) | Go chạy ở `127.0.0.1:8080` (`.dev/vedette.db`, `.dev/vedette.key`, tạo khi chạy lần đầu), Vite `localhost:5173` proxy `/api` → backend; module trong `REAL` đi tới backend, module khác vẫn do MSW trả lời. Ctrl-C dừng cả hai |
| Nối GUI vào backend (toàn bộ) | build SPA với `VITE_API_MOCK=off` (hoặc `VITE_API_REAL=all`) | hợp đồng `api/openapi.json` |
| Dọn | `make clean` (gồm image `vedette-*:dev` build tại chỗ, đề xuất) | không xoá `node_modules`, module cache |

**`make dev-api` chi tiết.** `VITE_API_REAL` (danh sách id module hoặc `all`) quyết định handler MSW nào được đăng ký: `web/src/lib/apiModules.ts` ánh xạ đường dẫn → module đúng như `core/server/modules.go`, và `api/route-modules.json` (Go test `core/server/routemodules_test.go` giữ bằng bảng Go, vitest đối chiếu với `apiModules.ts`) ngăn lệch. Origin: Vite proxy với `changeOrigin: false` nên `Host` giữ `localhost:5173` đúng bằng `Origin` của trình duyệt, và `checkOrigin` của backend so `Origin` với `Host` của chính request đó nên chấp nhận; POST/PUT/PATCH/DELETE gửi thêm `X-CSRF-Token` lấy từ cookie `__Host-vedette_csrf`. Cookie của hộp mang tiền tố `__Host-`/`__Secure-` và thuộc tính `Secure`: Chrome và Firefox chấp nhận chúng từ `http://localhost` (coi localhost là ngữ cảnh an toàn) nên `make dev-api` chạy bình thường qua `http://localhost:5173`; Safari thì không, hãy dùng Chrome hoặc Firefox (hoặc TLS) khi thử với backend thật. Chưa có đăng nhập ở backend (WP-04b phần 2) thì `GET /api/v1/modules` trả 401: đúng như mong đợi. **Module mock khi `core` là thật (issue #78).** Đăng nhập thật không điền phiên của mock, nên handler MSW của module mock (feeds, kiểm kê…) sẽ trả 401. Khi `core` ∈ `VITE_API_REAL` mà còn module mock, `web/src/mocks/realSession.ts` đăng ký một handler đứng đầu: trước khi module mock trả lời, nó đọc `GET /api/v1/me` của backend thật (qua `bypass()` của MSW), giữ kết quả 3 giây và bỏ khi có yêu cầu ghi tới module thật (đăng nhập, đăng xuất, setup, đổi vai); `guard()` và `currentUser()` của mock dùng người dùng và vai đó, không cấp quyền admin. Chưa đăng nhập thật = 401 như thường. Docker Compose cả bộ container chờ image (WP-08).

Quy ước: dev trên macOS dùng Docker Desktop/Podman machine: không có mạng host, macvlan, bắt gói thật, nên sensor chạy chế độ phát lại fixture. CI (GitHub Actions): test từng module, contract test, build đa kiến trúc, `trivy` + SBOM, **ký cosign** ở job phát hành, bài restore drill, thử "kéo image không ký bị từ chối". AI không tạo git tag; kien tag tay (`CLAUDE.md` #12).

## 14. Câu hỏi mở

| # | Câu hỏi |
|---|---|
| B1 | ~~Thêm endpoint health vào `api/openapi.json`.~~ **Đã quyết: không thêm; `vedette healthcheck` dùng route công khai `GET /api/v1/setup` (D-137).** |
| B2 | ~~Mã cài đặt một lần in trên console để chống kẻ trong LAN chiếm `/setup` trước admin thật. Có chấp nhận không?~~ **Đã quyết: có (D-75).** |
| B3 | Chứng chỉ TLS 8443: tự ký + cho tải lên (đề xuất) hay ACME nội bộ? |
| B4 | Có chấp nhận Podman rootful trên appliance (§12) hay bắt buộc rootless và chịu thêm shim? **Đã chốt cho unit (D-105):** unit hệ thống, rootful; PoC trên máy thật vẫn ở lab. |
| B5 | ~~Chặn egress của honeypot (macvlan không qua netfilter host)~~ **Đã chốt (D-102):** ruleset nft trong chính namespace `vedette-hp` chặn mọi kết nối mới đi ra (§12). |
| B6 | Cohort chỉ chặn cập nhật **tự động**; người dùng bấm tay có cài được bản chưa tới cohort không? (đề xuất: được, bản đã ký) |
| B7 | Quản lý greenbone: socket GMP trên volume hay cổng nội bộ; ghim digest theo `release.json` thay cho cosign của upstream? |
| B8 | Số tối thiểu phiên bản Docker/Podman cho kiểu Chỉ container; đường dẫn file ship trong `deploy/`. |
