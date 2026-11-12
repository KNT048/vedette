# Deferred: feat/release-gates (WP-08k part B, D-401)

- [ ] 2026-11-13 — chạy thật `make release-gates VERSION=<v> RELEASE_PREV_INDEX=<prev>` lần đầu trên bản phát hành thật (full clone tại tag, 4 manifest list `make images` + 2 `.deb`): trivy với cơ sở dữ liệu thật, `podman images --all` thật (nhãn sàn của core), và lượt dựng lại `.deb` so byte trong full clone — vì sao để sau: chỉ có ở lượt phát hành của kien; ở đây đã đo `make host-deb` hai lần cho cùng byte và sàn khác cho byte khác, phần còn lại thử bằng fake — ở đâu: Makefile `release-gates`, `scripts/release/gates.go`
