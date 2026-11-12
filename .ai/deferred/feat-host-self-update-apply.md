# Việc để sau — `host.self_update` lát 2b (D-316, nhánh feat/host-self-update-apply)

Kế hoạch: `docs/plans/2026-11-12-host-self-update.md` §1 lát 2 ("Built in 2b").

- [ ] 2026-11-12 — Bộ áp chỉ ghi câu của chính nó vào `journal.json.log` (pha, mã thoát, "dpkg is half done…"), không ghi đầu ra của apt/dpkg (chỉ journald của unit tạm có): GUI/`core` không thấy lý do apt từ chối — thêm đuôi đầu ra (đã lọc, ≤ 512 byte mỗi dòng, trong 50 dòng) nếu lát 4–5 cần hiện nó — vì sao để sau: lát 4–5 chưa định câu nào cần — ở đâu: host/ops/selfupdateapply.go `logLine`, `exec`
- [ ] 2026-11-12 — Lab lát 6 vẫn là nơi kiểm thật `systemd-run` (tên unit trùng, `--collect`), `RuntimeMaxSec`, cgroup riêng, reboot giữa bộ áp, policy-rc.d, `TimeoutStartSec` không kẹt READY: máy giả chỉ kiểm logic — vì sao để sau: cần VM và bản phát hành thử — ở đâu: kế hoạch lát 6, `.ai/deferred/feat-host-self-update.md` dòng lab
