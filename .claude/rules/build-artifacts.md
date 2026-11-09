# Dọn build output cùng lượt build (2026-09-03)

`go build`, `pnpm build`, `docker build` xong → dùng → xoá (`make clean`). Không để `bin/`, `web/dist/` lại trừ khi đang đóng gói release. Không xoá `node_modules`, `$GOMODCACHE`, file git theo dõi.
