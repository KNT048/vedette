# Việc để sau — `host.self_update` (thiết kế D-316, nhánh feat/host-self-update)

Kế hoạch: `docs/plans/2026-11-12-host-self-update.md`. Lát này chỉ có tài liệu.

- [ ] 2026-11-12 — Lát 1–5 của kế hoạch (khung Resume cho run `running`, lệnh + bộ áp + test hợp đồng, `install.sh` giữ gói đầu, mock/GUI, phía `core`) — vì sao để sau: bước này chỉ là thiết kế, chờ lead và Opus đọc — ở đâu: docs/plans/2026-11-12-host-self-update.md §1
- [ ] 2026-11-12 — Lab lát 6 (8 mục: nâng thật, bản mới không khởi động, phụ thuộc mới, reboot giữa bộ áp, policy-rc.d, khoá dpkg, tên unit tạm, không kẹt READY) trên ubuntu2404, debian13, Ubuntu 26.04 — vì sao để sau: cần mã và bản phát hành thử — ở đâu: kế hoạch §1 lát 6, docs/LAB-VM.md
- [ ] 2026-11-12 — `install.sh --uninstall` không biết phụ thuộc mới mà một lần tự nâng kéo về (không có trong `installed-by-us`) — vì sao để sau: chưa có bản host nào thêm `Depends` sau lần cài; cần quyết host ghi danh sách đó hay uninstall đọc `apt-get -s` — ở đâu: install.sh `record_new_packages`, D-316
