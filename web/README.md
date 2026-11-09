# web — giao diện Vedette (React 19 + TypeScript)

Chạy với dữ liệu mẫu (không cần backend): từ thư mục gốc `make dev` rồi mở http://localhost:5173.
Lần đầu mở sẽ vào trang cài đặt ban đầu; chọn "Dùng dữ liệu mẫu" để vào ngay. Tài khoản mẫu: `admin@congty.vn`, `it@congty.vn`, `giamdoc@congty.vn`, mật khẩu `vedette-demo`.

- Kiến trúc và quy ước: `docs/FRONTEND.md`, `docs/plans/2026-11-06-fe-spec.md`.
- Mock API (MSW) là hợp đồng với backend (D-18): handler ở `src/features/<module>/mocks.ts`. Nối backend Go thật từng module: `make dev-api` (`REAL=core,inventory` chọn module; xem `docs/DEPLOYMENT.md` §13). Build nối toàn bộ backend: `VITE_API_MOCK=off pnpm build`.
- Bảng nóng dùng dữ liệu CISA KEV/EPSS thật: `make fixtures` (chạy lại mỗi tuần).
- Kiểm tra: `make verify` (tsc + lint + vitest + build), `make e2e` (Playwright).
- Node ghim bằng `devEngines.runtime` trong `package.json`: pnpm tự tải đúng bản Node, không cần nvm.
