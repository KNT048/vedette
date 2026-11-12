# Việc để sau — run đỗ của khung host (D-316 lát 1, nhánh feat/host-parked-run)

Kế hoạch: `docs/plans/2026-11-12-host-self-update.md` §1 lát 1.

- [ ] 2026-11-12 — Khung không tự kết thúc run đỗ ở `parked_deadline`: chỉ goroutine kết thúc của lệnh (lát 2) gọi `SettleParked`; một lỗi ở đó giữ khoá ghi tới lần host khởi động lại mà `Resume` trả lời không. Quyết ở lát 2 có cần lưới an toàn của khung (ví dụ `failed self_update_interrupted` khi quá `parked_deadline` + biên) hay test của lát 2 phủ đủ — vì sao để sau: lát 1 không có lệnh sản xuất nào đỗ — ở đâu: host/server/parked.go, kế hoạch lát 2
- [ ] 2026-11-12 — D-316 (6) còn ghi "`recover()` hỏi `Options.Resume` cho mọi run không kết thúc"; mã lát 1 chỉ hỏi run `awaiting_confirm` và run đỗ (hỏi run `running` thường làm `(*Ops).Resume` của mạng bỏ qua `recoverOrphan`); spec §6.14 và kế hoạch đã sửa, D-316 cần một câu bổ sung khi kien/lead "doc" — vì sao để sau: không tự sửa văn bản quyết định đã chốt — ở đâu: docs/decisions/D-316.md (6), host/ops/netpending.go `Resume`
- [ ] 2026-11-12 — Tên `SettleParked` thay cho `Settle(runID, status, result, *RunError)` của spec/D-316 (Go không nạp chồng, `Settle` của run chờ đã có); D-316 (6) dùng chữ `Settle` chung — cùng câu bổ sung với dòng trên — vì sao để sau: như trên — ở đâu: docs/decisions/D-316.md
