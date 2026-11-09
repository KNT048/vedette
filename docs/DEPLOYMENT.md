# Triển khai

Trạng thái: **mới, 2026-11-09**, theo D-55 (appliance + container) và D-56 (cấu hình mạng của hộp). Chưa có mã; các giá trị đánh dấu **(đề xuất)** là mặc định thiết kế để người cài đặt/test dựa vào, **chốt sau khi đo ở M2** (xem §14). Mọi thứ ship như code (`rules/ships-as-code.md`): máy mới dựng từ repo phải đạt cùng trạng thái, xác minh bằng **hiệu ứng** (dịch vụ chạy, cổng mở, cấu hình đúng), không bằng exit code.

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
 host (Debian/Ubuntu)
 ├─ vedette-host.service (root)  ◄── /run/vedette/host.sock (0660 root:vedette)
 ├─ Podman (rootful) ── Quadlet units: /etc/containers/systemd/*.container|*.network|*.volume
 │
 │   mạng bridge nội bộ `vedette-int`  (subnet tự chọn không đụng LAN, đề xuất)
 │   ┌──────────────┐        ┌──────────────┐
 │   │ core         │◄──8444─┤ honeypot-N   │ (macvlan vào LAN + chân bridge nội bộ)
 │   │ :8443 (pub.) │        └──────────────┘
 │   │ :8444 mTLS   │        ┌──────────────┐
 │   └─▲────────────┘        │ greenbone    │ (tuỳ chọn, chỉ bridge nội bộ)
 │     │ 127.0.0.1:8444      └──────────────┘
 │   ┌─┴──────────┐  ┌──────────┐
 │   │ sensor     │  │ scan     │   mạng host (raw socket; bắt/nhìn LAN thật)
 │   └────────────┘  └──────────┘
 └─ NIC quản trị (IP) · NIC SPAN (không IP, promisc) · IP phụ cho bẫy (macvlan)
```

Tóm tắt (chi tiết từng container ở §2.1–§2.4, giới hạn tài nguyên ở §2.5):

| Container | Image (đề xuất) | Mạng | Capability | Mặc định bật |
|---|---|---|---|---|
| `core` | `ghcr.io/knt048/vedette-core` | bridge `vedette-int`, publish 8443 | không (drop ALL) | luôn |
| `sensor` | `ghcr.io/knt048/vedette-sensor` | host | `NET_RAW`, `NET_BIND_SERVICE` | khi `sensor-*` hoặc `logs` bật |
| `honeypot` | `ghcr.io/knt048/vedette-honeypot` | macvlan + `vedette-int` | `NET_BIND_SERVICE` | khi `honeypot` bật |
| `scan` | `ghcr.io/knt048/vedette-scan` | host | `NET_RAW` | khi `scan`/`exposure`/`sensor-active` bật |
| `greenbone` | upstream Greenbone Community Containers, ghim digest | bridge `vedette-int` | theo upstream | khi `scan-credentialed` bật |

Registry và quyền sở hữu namespace là **câu hỏi mở A3** (luồng dữ liệu ra mới → `PRIVACY.md`).

### 2.1 core

| Mục | Giá trị |
|---|---|
| Nội dung | Go binary tĩnh + SPA nhúng + skill/gói khuyến nghị đã xác nhận (đi cùng bản phát hành, D-36); chạy `vedette serve` |
| Người dùng | không root; `cap_drop=ALL`; `no-new-privileges`; rootfs chỉ đọc + tmpfs `/tmp` |
| Mạng | bridge `vedette-int`; publish **chỉ** `<IP quản trị>:8443`; `8444` (sensor-intake mTLS) không publish ra LAN, chỉ `127.0.0.1:8444` cho container mạng host |
| Volume | `vedette-data` → `/var/lib/vedette` (SQLite WAL, chỉ mục RAG, tài liệu tải lên); `/etc/vedette/master.key` → `/run/secrets/master.key` (ro, 0600); `/run/vedette/host.sock` (socket `vedette-host`); mẫu cấu hình ro |
| Cổng | 8443/tcp (UI, API, SSE, intake osquery, script cài osquery, trang duyệt email, URL danh sách chặn) |
| Health check | `vedette healthcheck`: mở được DB, scheduler còn tick, HTTP nội bộ trả 200 (endpoint health chưa có trong `api/openapi.json`, cần thêm: câu hỏi mở B1). Chu kỳ 30 s, start-period 60 s, 3 lần hỏng thì unhealthy |
| Phụ thuộc | không (khởi động đầu tiên) |

### 2.2 sensor

| Mục | Giá trị |
|---|---|
| Nội dung | `vedette sensor`: listener thụ động (DHCP/ARP/mDNS/SSDP/LLDP), bộ phân tích SPAN metadata (D-43), nhận syslog (`logs`), `sensor-active` gọi nmap qua `core/exec` |
| Mạng | **host** (cần thấy LAN thật và card SPAN) |
| Capability | `NET_RAW` (bắt gói), `NET_BIND_SERVICE` (syslog 514). Card SPAN được đặt promisc, không IP bởi `vedette-host` (D-56), nên không cần `NET_ADMIN` |
| Volume | `vedette-sensor` → `/var/lib/vedette-sensor` (cert mTLS, hàng đợi sự kiện chịu khởi động lại); không chạm DB |
| Cổng | UDP/TCP 514 (khi `logs` bật); không cổng khác |
| Health check | `vedette sensor healthcheck`: poll `core` thành công trong 60 s; nếu SPAN bật: có gói trong 60 s (nếu không có chỉ cảnh báo, không unhealthy, D-56) |
| Kênh | mTLS, **sensor gọi ra `core`** (`127.0.0.1:8444`), không có cổng vào ngoài syslog |

### 2.3 honeypot

| Mục | Giá trị |
|---|---|
| Nội dung | tác tử Go (poll cấu hình sinh từ DB, giám sát OpenCanary, đẩy `honeypot.hit`) + OpenCanary (BSD-3) + honey token |
| Mạng | **macvlan** trên card quản trị với IP phụ (D-50, D-55) + chân `vedette-int` để poll `core:8444` (container macvlan không nói chuyện được trực tiếp với IP của chính host) |
| Capability | `NET_BIND_SERVICE` (cổng 22/80/445/1433/3389 trên IP riêng) |
| Volume | cấu hình OpenCanary sinh vào tmpfs; cert mTLS riêng `vedette-honeypot` |
| Cổng | 22, 80, 445, 1433, 3389 (và vai giả khác theo D-50) **chỉ trên IP phụ**; không trên IP quản trị |
| Health check | cổng bẫy đang bật trả lời kết nối TCP + poll `core` thành công |
| Số container | một container mỗi IP/vai giả (**đề xuất**, câu hỏi mở A5): OpenCanary mỗi tiến trình một vai |
| Ràng buộc | IP phụ phải nằm ngoài dải DHCP của khách (hướng dẫn trong wizard); macvlan không dùng được trên Wi-Fi (§4) |

### 2.4 scan và greenbone

`scan`:

| Mục | Giá trị |
|---|---|
| Nội dung | `vedette scan-worker`: nmap + nuclei (template tag an toàn `kev,vkev`) trong image; poll hàng đợi việc của `core` |
| Mạng | host; capability `NET_RAW` (nmap SYN/OS) |
| Ràng buộc | chỉ quét trong `inv_scope` / mục tiêu đã xác thực (SYS-7, D-25, D-32); egress kiểm theo bảng phạm vi; mỗi probe ghi log |
| Volume | tmpfs cho kết quả tạm; không volume bền |
| Health check | heartbeat poll `core` trong 60 s |
| Ghi chú | nmap trong image: xem câu hỏi mở A2 (giấy phép) |

`greenbone` (tuỳ chọn, M7, S-SCAN-5): nhóm container upstream, ghim digest theo `release.json` đã ký; giao diện web Greenbone **không** publish ra LAN; `core` nói chuyện với `gvmd` qua socket GMP trên volume dùng chung (**đề xuất**); chạy `vedette-int`; SSH key quét có đăng nhập lưu bằng `core/secrets`. GPL/AGPL: container riêng, không sửa (D-55).

### 2.5 Giới hạn tài nguyên và health (đề xuất, cho hộp 4 nhân / 8 GB)

| Container | CPU | RAM | PIDs | Ghi chú |
|---|---|---|---|---|
| `core` | 2 | 2 GiB | 512 | SQLite + RAG FTS5 |
| `sensor` | 1 | 512 MiB | 256 | trần chỉnh được ở Box network (D-56); mục tiêu ≤5% một nhân ở 100 Mbps |
| `honeypot` (mỗi cái) | 0.5 | 256 MiB | 128 | |
| `scan` | 2, `CPUWeight` thấp | 1 GiB | 512 | burst theo việc; cửa sổ giờ + tốc độ (S-SCAN-4) |
| `greenbone` (cả nhóm) | 2 | ~3 GiB (đo lại) | theo upstream | bật thì nên 16 GB RAM (đề xuất) |

Tổng không kể greenbone ≈ 3,75 GiB, chừa phần còn lại cho OS và page cache. Swap tắt trong container (`memory-swap` = `memory`). Cách đo: `podman stats` trong bài test tải M2 (1.000 thiết bị, 50k IOC), ghi vào `docs/project-map/`. Hạn mức vượt thì container bị OOM-kill và `Restart=always` dựng lại; sự kiện hiện ở trang sức khoẻ module.

## 3. `vedette-host`

Tiến trình systemd chạy root, rất nhỏ, thay `vedette-updater` của D-53 (D-55). `core` gọi qua socket Unix `/run/vedette/host.sock` (quyền 0660 `root:vedette`, không lắng nghe TCP). Danh sách lệnh, tham số, mã lỗi, tiến trình trực tiếp: `specs/host-api.md`. Tại đây chỉ nêu **trách nhiệm** và **bất biến**.

| Nhóm | Trách nhiệm | Căn cứ |
|---|---|---|
| Cập nhật OS | kiểm bản vá (apt), cài bản vá bảo mật / tất cả, unattended-upgrades, cần khởi động lại, hạn hỗ trợ bản phát hành, lịch theo cửa sổ bảo trì, reboot ngay/theo lịch; nâng bản phát hành OS chỉ hướng dẫn | D-53, S-CORE-7 |
| Mạng | danh sách card; card quản trị (DHCP/tĩnh, gateway, DNS); card SPAN (không IP, promisc); IP phụ cho bẫy (macvlan); NTP; số liệu SPAN thật (gói/giây, MAC thấy được, lần nhận gói cuối) | D-56 |
| Container | kéo image theo digest, **xác minh cosign**, render + áp unit Quadlet, start/stop/restart, health gate, hoàn tác bằng tag/digest cũ | D-55 |
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
| Ubuntu 24.04 LTS | x86_64, arm64 | **chính** (D-53, D-55) | Podman 4.9 có Quadlet; cần kiểm lại phiên bản thực tế |
| Debian 12 | x86_64, arm64 | D-55 liệt kê; **cần xác minh** | Podman 4.3 trong repo mặc định, chưa có Quadlet (từ 4.4). Câu hỏi mở A1 trong ARCHITECTURE |
| Debian 13 | x86_64, arm64 | chưa quyết | Podman 5.x; ứng viên thay Debian 12 |
| Khác (RHEL, Alpine…) | — | không hỗ trợ ở kiểu Appliance | Dùng kiểu Chỉ container |

| Hạng mục | Tối thiểu (mục tiêu 1.000 thiết bị) | Ghi chú |
|---|---|---|
| CPU/RAM/đĩa | 4 nhân / 8 GB / SSD 64 GB | + `greenbone`: nên 16 GB (đề xuất) |
| NIC | 1 (quản trị) | SPAN cần thêm 1 card (USB được); chuyển SPAN/TAP trên switch (hướng dẫn theo hãng ở Box network, D-56) |
| Mạng có dây | bắt buộc cho SPAN, bẫy macvlan | Wi-Fi không hỗ trợ macvlan/SPAN |
| VM | được | vSwitch phải cho phép promiscuous/giả MAC cho macvlan và SPAN (VMware: Promiscuous Mode, Hyper-V: MAC spoofing; Proxmox bridge thường ổn): kiểm bằng hiệu ứng ở Box network |
| Đồng hồ | NTP bắt buộc | TOTP, chứng chỉ mTLS, hết hạn token duyệt phụ thuộc giờ (D-56) |
| Kiểu cài | Debian/Ubuntu mới bằng script; ISO/VM image **sau** (D-55) | |

## 5. Hai kiểu cài (D-55)

| | **Appliance** | **Chỉ container** |
|---|---|---|
| Cài bằng | `deploy/install.sh` trên Debian/Ubuntu sạch (sau: ISO/VM image) | Compose/Quadlet trên Docker hoặc Podman sẵn có của khách |
| Runtime | Podman + Quadlet, rootful | Docker hoặc Podman, khách chọn |
| `vedette-host` | có | không |
| Cập nhật OS, reboot (S-CORE-7) | trong GUI | **không**; GUI hiện hướng dẫn, không có nút |
| Box network (D-56): card, SPAN, IP phụ, NTP | cấu hình trong GUI | **không**; khách tự cấu hình trước (card SPAN promisc, macvlan); GUI chỉ đọc trạng thái nếu thấy được |
| Tự cập nhật Vedette | có, theo lô, health gate, rollback | **không**; GUI báo có bản mới và hiện lệnh `pull`/`up`; khách tự bấm |
| Xác minh cosign | `policy.json` bắt buộc khi kéo | khách tự xác minh bằng `cosign verify` (lệnh hiện trong GUI) hoặc policy Podman |
| Sao lưu | snapshot DB + xoay vòng bởi host | snapshot DB trong volume do `core` tạo; khách tự sao lưu volume |
| SPAN / syslog 514 | đủ | được nếu khách chạy `sensor` ở mạng host và card đã sẵn sàng |
| Bẫy trên IP phụ | macvlan do host tạo | macvlan do khách tạo, hoặc bẫy trên IP chính ở cổng không trùng dịch vụ host (bị hạn chế) |
| "This box" (S-INV-5) | danh sách gói dpkg của host | không đọc được host (câu hỏi mở A7 ở ARCHITECTURE) |
| Greenbone | được | được nếu khách có đủ tài nguyên |
| Cảnh báo | — | Docker `-p` đi vòng tường lửa UFW (xem §12): ràng buộc cổng vào đúng IP |

Hạn chế của kiểu Chỉ container phải hiện rõ ở GUI (Cài đặt → Updates, Box network): "Not available in container-only mode" kèm lý do, không ẩn mục (S-CORE-1: nói rõ chỗ thiếu vì sao thiếu). Phiên bản Docker/Podman tối thiểu: chốt ở M2.

## 6. Unit mẫu

Các file dưới đây là **ví dụ minh hoạ**; cờ dòng lệnh, tên biến, đường dẫn chốt ở M2. Unit thật do `vedette-host` render từ `deploy/quadlet/*.tmpl` (giá trị như IP, digest, giới hạn lấy từ trạng thái hộp), không sửa tay.

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

`/etc/containers/systemd/vedette-core.container`

```ini
[Unit]
Description=Vedette core
After=network-online.target vedette-host.service
Wants=network-online.target

[Container]
ContainerName=vedette-core
Image=ghcr.io/knt048/vedette-core@sha256:<digest>
Network=vedette-int.network
PublishPort=192.168.10.5:8443:8443
PublishPort=127.0.0.1:8444:8444
Volume=vedette-data.volume:/var/lib/vedette
Volume=/etc/vedette/master.key:/run/secrets/master.key:ro
Volume=/run/vedette/host.sock:/run/vedette/host.sock
ReadOnly=true
Tmpfs=/tmp
NoNewPrivileges=true
DropCapability=ALL
User=65532:65532
UserNS=auto
LogDriver=journald
PodmanArgs=--memory=2g --memory-swap=2g --cpus=2 --pids-limit=512
HealthCmd=/vedette healthcheck
HealthInterval=30s
HealthStartPeriod=60s
HealthRetries=3
Exec=serve

[Service]
Restart=always
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
```

`/etc/containers/systemd/vedette-sensor.container`

```ini
[Unit]
Description=Vedette sensor (passive/active, syslog, SPAN metadata)
After=vedette-core.service
Requires=vedette-core.service

[Container]
ContainerName=vedette-sensor
Image=ghcr.io/knt048/vedette-sensor@sha256:<digest>
Network=host
DropCapability=ALL
AddCapability=NET_RAW NET_BIND_SERVICE
NoNewPrivileges=true
ReadOnly=true
Tmpfs=/tmp
Volume=vedette-sensor.volume:/var/lib/vedette-sensor
LogDriver=journald
PodmanArgs=--memory=512m --memory-swap=512m --cpus=1 --pids-limit=256
HealthCmd=/vedette sensor healthcheck
HealthInterval=30s
HealthStartPeriod=30s
HealthRetries=3
Exec=sensor --core https://127.0.0.1:8444

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

Sensor chạy UID 0 trong container nhưng chỉ còn hai capability; nếu thử nghiệm cho thấy non-root nhận được capability hiệu lực thì đổi sang non-root (câu hỏi mở A4 ở ARCHITECTURE).

`/etc/containers/systemd/vedette-lan.network` (macvlan cho bẫy)

```ini
[Network]
NetworkName=vedette-lan
Driver=macvlan
Options=parent=eth0
Subnet=192.168.10.0/24
Gateway=192.168.10.1
IPRange=192.168.10.240/29
```

`/etc/containers/systemd/vedette-honeypot-1.container`

```ini
[Unit]
Description=Vedette honeypot (decoy 1)
After=vedette-core.service
Requires=vedette-core.service

[Container]
ContainerName=vedette-honeypot-1
Image=ghcr.io/knt048/vedette-honeypot@sha256:<digest>
Network=vedette-lan.network:ip=192.168.10.241
Network=vedette-int.network
DropCapability=ALL
AddCapability=NET_BIND_SERVICE
NoNewPrivileges=true
ReadOnly=true
Tmpfs=/tmp
LogDriver=journald
PodmanArgs=--memory=256m --memory-swap=256m --cpus=0.5 --pids-limit=128
HealthCmd=/vedette honeypot healthcheck
HealthInterval=30s
HealthRetries=3
Exec=honeypot --core https://vedette-core:8444

[Service]
Restart=always

[Install]
WantedBy=multi-user.target
```

`/etc/containers/systemd/vedette-scan.container`: như `sensor`, nhưng `Image=…vedette-scan@sha256:…`, `AddCapability=NET_RAW`, `PodmanArgs=--memory=1g --memory-swap=1g --cpus=2 --pids-limit=512 --cpu-shares=128`, `Exec=scan-worker --core https://127.0.0.1:8444`.

`/etc/systemd/system/vedette-host.service` (khung; thông số hardening ở §12)

```ini
[Unit]
Description=Vedette host helper
After=network-online.target

[Service]
ExecStart=/usr/lib/vedette/vedette-host
RuntimeDirectory=vedette
RuntimeDirectoryMode=0750
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Thứ tự khởi động: `vedette-host` → `core` → `sensor`/`scan`/`honeypot-N` → `greenbone`. Cả bộ dựng lại sau reboot nhờ `WantedBy=multi-user.target`.

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
    cap_drop: [ALL]
    cap_add: [NET_RAW, NET_BIND_SERVICE]
    read_only: true
    command: ["sensor", "--core", "https://127.0.0.1:8444"]
  sensor-replay:
    profiles: ["dev"]            # phát lại pcap/syslog mẫu, không đụng mạng thật
    image: ghcr.io/knt048/vedette-sensor@sha256:<digest>
    command: ["sensor", "--core", "https://core:8444", "--replay", "/fixtures"]
    volumes: ["./fixtures:/fixtures:ro"]
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
    profiles: ["lab"]
    image: ghcr.io/knt048/vedette-scan@sha256:<digest>
    network_mode: host
    cap_drop: [ALL]
    cap_add: [NET_RAW]
  # greenbone: profile "greenbone", dùng compose upstream ghim digest (M7)
networks:
  lan:
    driver: macvlan
    driver_opts: {parent: eth0}
    ipam: {config: [{subnet: 192.168.10.0/24, gateway: 192.168.10.1, ip_range: 192.168.10.240/29}]}
volumes:
  vedette-data:
```

Không có `vedette-host` trong compose: dev/CI dùng **host giả** (`vedette-host --fake`, trả fixture qua socket cùng giao thức) để test các màn hình Updates và Box network (đề xuất). CI chạy test hợp đồng sensor↔core qua compose.

## 7. Cổng và mạng

### 7.1 Vào hộp

| Cổng | Từ | Vào | Mục đích | Khi nào mở |
|---|---|---|---|---|
| 8443/tcp | LAN | `core`, **chỉ IP quản trị** | UI, API, SSE, intake osquery, script cài osquery (`/install/*`), trang duyệt email, URL danh sách chặn cho firewall kéo (D-44, D-46, D-34) | luôn |
| 8444/tcp | nội bộ | `core`, `127.0.0.1` + `vedette-int` | sensor-intake mTLS (đề xuất) | luôn; **không ra LAN** |
| 514 UDP/TCP (TLS tuỳ cấu hình) | LAN | `sensor` | nhận syslog | `logs` bật |
| 22, 80, 445, 1433, 3389 (+ vai giả D-50) | LAN | `honeypot` trên **IP phụ** | bẫy | `honeypot` bật |
| — | Internet | — | **không có cổng vào** | — |

### 7.2 Ra khỏi hộp

| Cổng | Tới | Mục đích | PRIVACY |
|---|---|---|---|
| 443/tcp | nguồn feed (D-36) | kéo feed | luồng 1 |
| 443/tcp | GitHub Releases + registry image | bản phát hành ký, image | luồng 6 (cần bổ sung registry, A3) |
| 443/tcp | provider AI, dịch vụ tra cứu cần key, Slack (Socket Mode), Telegram (long polling), Zalo, tín hiệu ẩn danh, CT log + điểm dò IP | theo cấu hình | luồng 2–5, 8, 9 |
| 80,443/tcp | mirror apt (`archive.ubuntu.com`, `security.ubuntu.com`, `deb.debian.org`, `security.debian.org` hoặc mirror nội bộ) | cập nhật OS (D-53) | luồng 6 |
| 53 UDP/TCP | DNS | phân giải | — |
| 123/udp | NTP | đồng hồ (D-56) | — |
| 25/465/587 | SMTP của khách | email cảnh báo, mã đăng nhập | luồng 5 |
| LAN ra | thiết bị | SNMP 161/udp, SSH/HTTPS tới API thiết bị (kết nối harness/response), Wazuh API, nmap trong phạm vi, SIEM forward | theo cấu hình |

### 7.3 Mạng container

- `vedette-int`: bridge nội bộ, subnet do `vedette-host` chọn không trùng LAN/VPN đã khai báo.
- `sensor`, `scan`: host network, tới `core` qua `127.0.0.1:8444`.
- `honeypot`: macvlan (IP phụ, ngoài dải DHCP) + chân `vedette-int`.
- Card SPAN: không IP, promisc, bật bởi `vedette-host`; sensor đọc bằng AF_PACKET; kiểm bằng hiệu ứng: gói/giây > 0 và thấy ≥1 MAC khác MAC của hộp (D-56).
- Kiểm bằng hiệu ứng sau cài: `ss -ltnup` trên host không có cổng nghe ngoài bảng §7.1; từ máy lab (không phải mạng thật) cổng ngoài bảng không mở.

## 8. Lần khởi động đầu (first boot)

Kiểu Appliance, `deploy/install.sh` (idempotent; chạy lại không đổi gì khi đã đạt trạng thái):

| Bước | Việc | Xác minh bằng hiệu ứng |
|---|---|---|
| 1 | Preflight: OS/phiên bản/kiến trúc trong §4, Podman ≥ 4.4, ≥ 1 NIC có IP, giờ đồng bộ, đủ RAM/đĩa | sai OS thì dừng và in lý do; không cài dở |
| 2 | Cài gói ghim phiên bản (Podman, netavark, UFW nếu thiếu); cài `vedette-host` (gói/binary đã xác minh chữ ký) | `vedette-host` active; socket tồn tại, quyền 0660 `root:vedette` |
| 3 | Tạo user hệ thống `vedette`, thư mục, khoá bí mật 0600 (`/etc/vedette/master.key`), khoá công khai cosign, `policy.json` bắt buộc chữ ký cho image của dự án | thử kéo image không ký bị từ chối |
| 4 | Render và áp unit Quadlet; kéo image theo digest; khởi động `core` | `core` healthy trong 300 s; 8443 nghe **chỉ** trên IP quản trị |
| 5 | In `https://<IP>:8443` và **mã cài đặt một lần** trên console | endpoint `/setup` từ chối khi thiếu mã (D-75) |
| 6 | Trình hướng dẫn trên web (D-22, không SSH): tổ chức, quản trị viên + 2FA, dải LAN có **tiền tố** (D-32), ô cam kết quét (D-26), gói module (nhỏ/vừa/đầy đủ/tuỳ chọn), kênh thông báo, AI (tuỳ chọn), Box network (D-56) | mỗi bước ghi `core_audit`; module tắt không có container chạy |
| 7 | Thiết bị đầu tiên "This box" xuất hiện trong kho (D-53, S-INV-5) | danh sách gói dpkg có, không xoá được |
| 8 | Kéo feed lần đầu | `feeds` báo thành công cho nguồn bật; ≤ 5 MB/giờ sau đó |

Chứng chỉ TLS cho 8443: sinh tự ký lúc cài, cho phép tải chứng chỉ của khách lên (đề xuất, câu hỏi B3). Cookie `Secure` nên yêu cầu TLS luôn bật.

## 9. Nâng cấp và hoàn tác

Thay A/B slot của binary bằng **image ký** (D-55). Tổng quan kênh: `UPDATES.md`.

### 9.1 Phần mềm Vedette

| Bước | Việc |
|---|---|
| 1. Phát hiện | `vedette-host` (lịch hoặc người dùng bấm "Check") lấy `release.json` từ GitHub Releases (D-36). Manifest **ký minisign** (xác minh offline được): kênh `stable`/`beta`, digest từng image, phần trăm rollout, phiên bản host tối thiểu, `revoked[]`, ghi chú migration |
| 2. Cohort | `cohort = hash(install_id) mod 100` (`UPDATES.md` §2). Tự động chỉ nhận khi `cohort < rollout`. Rollout 10 → 50 → 100 sau 24 giờ không báo lỗi; `stable` sau `beta` ≥ 7 ngày |
| 3. Pre-flight | đủ đĩa, không việc khác đang chạy, trong cửa sổ bảo trì (nếu tự động), Podman đủ phiên bản |
| 4. Kéo | `podman pull` theo digest; `policy.json` yêu cầu **cosign hợp lệ**; sai ký hoặc thiếu ký thì dừng, không đổi gì |
| 5. Sao lưu | `core` tạo snapshot DB nhất quán (SQLite online backup), host lưu `/var/backups/vedette/pre-<ver>` |
| 6. Thay | render unit mới (digest mới), `daemon-reload`, restart theo thứ tự: `core` → `sensor`/`scan` → `honeypot` → `greenbone`. Migration chạy khi `core` khởi động, **chỉ expand**: bản mới chỉ thêm, bản liền trước vẫn chạy được trên schema mới (đề xuất; test hợp đồng ở CI) |
| 7. Health gate | `core` healthy ≤ 120 s, các container khác ≤ 60 s, cộng smoke: đăng nhập trả 200, scheduler tick, sensor heartbeat. Cửa sổ và ngưỡng (đề xuất) |
| 8. Kết thúc | ghi `core_audit` (ai/lịch, từ/đến phiên bản, digest, kết quả); giữ image trước 1 đời, xoá đời cũ hơn |

Hỏng ở bước 6–7: `vedette-host` tự quay về unit/digest trước, kiểm health lại, báo lên UI. Không khôi phục DB trừ khi migration vi phạm quy tắc expand-only (khi đó dùng snapshot bước 5 và báo rõ dữ liệu mất).

**Rollback thủ công** (S-CORE-2): nút "Rollback" trên trang Updates hoặc `vedette-host rollback` chuyển về tag/digest trước đó (còn giữ 1 đời). Xác minh bằng hiệu ứng: phiên bản hiển thị đúng và health gate qua.

Ngoại tuyến (mạng cách ly): bundle ký chứa `release.json` + image dạng OCI archive; `vedette bundle import` kiểm minisign và cosign như đường online.

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
- `vedette-host.service`: hạn chế mức có thể mà vẫn chạy apt/netplan (nên không dùng `ProtectSystem=strict`): `ProtectHome=yes`, `PrivateTmp=yes`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `LockPersonality=yes`, `RestrictRealtime=yes`, `SystemCallArchitectures=native`, `MemoryDenyWriteExecute=yes`, `RuntimeDirectoryMode=0750`. Giới hạn thiệt hại chủ yếu dựa vào **danh sách lệnh cố định**, không dựa vào sandbox.
- UFW/nftables mặc định chặn vào, mở theo module bật (8443; 514 khi `logs` bật). `vedette-host` quản lý luật; kiểm bằng hiệu ứng (§7.3).
- Không gắn `podman.sock`/`docker.sock` vào bất kỳ container nào; không `--privileged`.
- SSH quản trị host nằm ngoài Vedette; khuyến nghị chỉ cho phép từ dải quản trị.

**Container.**
- `cap_drop=ALL` + capability tối thiểu (§2); `no-new-privileges`; rootfs chỉ đọc + tmpfs; seccomp/AppArmor mặc định của Podman; giới hạn tài nguyên (§2.5).
- Secret qua file mount ro, không qua biến môi trường.
- `UserNS=auto` và non-root khi tương thích (core, honeypot).
- Image: ghim digest, SBOM CycloneDX, quét `trivy`/`govulncheck` trong CI, cosign.

**Rootless.** Appliance dùng Podman **rootful** có hardening trên, vì: macvlan, mạng host + raw socket và mạng nội bộ chung giữa các container đều cần quyền thật; thử rootless sẽ buộc thêm lớp shim làm tăng bề mặt. Rootless dùng được ở dev/CI (profile `dev`) và ở kiểu Chỉ container cho phần `core`/`scan` không cần raw. Xác nhận bằng PoC ở M2 (B4).

**Podman với Docker và UFW.** Docker chèn luật iptables của `-p` vào chuỗi `DOCKER` nên cổng được publish **đi vòng** luật UFW (hành vi đã biết); đây là lý do D-55 chọn Podman cho appliance. Với Podman vẫn chỉ publish thứ cần publish (chỉ 8443) và không tin vào UFW một mình: mọi bản cài kiểm bằng `ss`/quét từ lab. Kiểu Chỉ container trên Docker: bind cổng vào IP cụ thể trong Compose (`192.168.10.5:8443:8443`), hoặc đặt luật ở chuỗi `DOCKER-USER`.

**Rủi ro riêng của bẫy.** Honeypot là bề mặt tấn công chủ đích từ LAN. Giảm thiểu: container riêng, `cap_drop ALL`, không DB, cert mTLS riêng, chỉ nói với `core:8444`, `core` coi mọi dữ liệu từ bẫy là không tin cậy (SYS-6). Chặn đi ngang từ bẫy ra LAN (macvlan đi thẳng ra NIC, không qua netfilter của host) cần quyết định riêng (câu hỏi mở B5).

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

**`make dev-api` chi tiết.** `VITE_API_REAL` (danh sách id module hoặc `all`) quyết định handler MSW nào được đăng ký: `web/src/lib/apiModules.ts` ánh xạ đường dẫn → module đúng như `core/server/modules.go`, và `api/route-modules.json` (Go test `core/server/routemodules_test.go` giữ bằng bảng Go, vitest đối chiếu với `apiModules.ts`) ngăn lệch. Origin: Vite proxy với `changeOrigin: false` nên `Host` giữ `localhost:5173` đúng bằng `Origin` của trình duyệt, và `checkOrigin` của backend so `Origin` với `Host` của chính request đó nên chấp nhận; POST/PUT/PATCH/DELETE gửi thêm `X-CSRF-Token` lấy từ cookie `vedette_csrf`. Chưa có đăng nhập ở backend (WP-04b phần 2) thì `GET /api/v1/modules` trả 401: đúng như mong đợi. Docker Compose cả bộ container chờ image (WP-08).

Quy ước: dev trên macOS dùng Docker Desktop/Podman machine: không có mạng host, macvlan, bắt gói thật, nên sensor chạy chế độ phát lại fixture. CI (GitHub Actions): test từng module, contract test, build đa kiến trúc, `trivy` + SBOM, **ký cosign** ở job phát hành, bài restore drill, thử "kéo image không ký bị từ chối". AI không tạo git tag; kien tag tay (`CLAUDE.md` #12).

## 14. Câu hỏi mở

| # | Câu hỏi |
|---|---|
| B1 | Thêm endpoint health vào `api/openapi.json` (ví dụ `GET /api/v1/health` không cần đăng nhập, trả tối thiểu) và quy ước trong `API_CONVENTIONS.md`. |
| B2 | ~~Mã cài đặt một lần in trên console để chống kẻ trong LAN chiếm `/setup` trước admin thật. Có chấp nhận không?~~ **Đã quyết: có (D-75).** |
| B3 | Chứng chỉ TLS 8443: tự ký + cho tải lên (đề xuất) hay ACME nội bộ? |
| B4 | Có chấp nhận Podman rootful trên appliance (§12) hay bắt buộc rootless và chịu thêm shim? Cần PoC. |
| B5 | Chặn egress của honeypot (macvlan không qua netfilter host): nftables bảng `netdev` trên NIC cha, hay chấp nhận rủi ro với cert mTLS riêng? |
| B6 | Cohort chỉ chặn cập nhật **tự động**; người dùng bấm tay có cài được bản chưa tới cohort không? (đề xuất: được, bản đã ký) |
| B7 | Quản lý greenbone: socket GMP trên volume hay cổng nội bộ; ghim digest theo `release.json` thay cho cosign của upstream? |
| B8 | Số tối thiểu phiên bản Docker/Podman cho kiểu Chỉ container; đường dẫn file ship trong `deploy/`. |
