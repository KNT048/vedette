# Việc để sau — nhánh feat/honeypot (WP-14)

- [ ] **Host thật (WP-07b phần 2-3)**: khi `vedette-host` có `decoy_ip.add/remove` (host-api 6.6) và `container.start/stop` cho service `honeypot` (6.8, 6.9), thay `notAnAppliance` trong `cmd/vedette/honeypot.go` bằng bộ chuyển trên `host/client` (`Client.Run`). Đến lúc đó mọi bẫy bật vẫn hiển thị `off` (không nghe).
- [ ] **GUI chưa có trạng thái "máy này không chạy được bẫy" và lý do**: hợp đồng `Trap.state` chỉ có off/listening/conflict. Lý do nằm ở log và `Service.HostStatus()`. Cần story + trường mới (đổi GUI là story mới, gui-first.md).
- [ ] **Gói tin ra từ container (INV-1)**: test bắt gói từ container `honeypot` tới IP nguồn = 0 là tính chất đóng gói/mạng: WP-08. Phía mã đã có test AST không import `net`/`os/exec` (TestContract_INV1_NoDialer).
- [ ] **WP-08**: container `honeypot` phải (a) mount `-honeypot-dir` (core ghi `opencanary.conf`, `honeytokens.json`; container ghi `opencanary.jsonl`), (b) rải các tệp trong `honeytokens.json` vào share Samba, (c) ghi `/var/log/samba-audit.log` -> OpenCanary `smb.auditfile`, (d) chạy một tiến trình OpenCanary trong network macvlan (D-90 (1)).
- [ ] **Module `logs` (Emily)**: nối cổng `Logs` (`Config.Logs`) để `HitDetail.events` có dòng firewall/DHCP/AD quanh hit; hiện chỉ có dòng của chính honeypot.
- [ ] **Token URL/DNS chưa có bộ bắt** (CONTRACT câu hỏi mở 3, D-90 (7)): cần quyết định điểm thu (không máy chủ dự án, D-81).
- [ ] **Quét cổng (câu hỏi mở 1)**: OpenCanary `portscan` đang tắt; bật cần quyết `net_raw`/iptables cho container.
- [ ] **`response`**: đọc hit qua `Service.Hits` (có `is_test`, `SourceIP()`); module response (agent khác) nối khi có.
- [ ] **Tín hiệu ẩn danh (INV-14)**: D-82 bỏ luồng gửi; module không có đường mã nào gửi. Giữ nguyên.
