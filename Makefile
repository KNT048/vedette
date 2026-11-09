# Vedette — lệnh chung. Node được ghim trong web/package.json (devEngines), pnpm tự tải đúng bản.
.PHONY: help dev verify verify-fast test build lint e2e fixtures clean

help:
	@echo "make dev        chạy giao diện với dữ liệu mẫu tại http://localhost:5173"
	@echo "make verify     gõ kiểu + lint + test + build (rồi dọn build)"
	@echo "make e2e        kiểm thử đầu-cuối bằng Playwright (Chromium)"
	@echo "make fixtures   kéo dữ liệu KEV/EPSS thật cho bảng nóng"
	@echo "make clean      xoá web/dist và báo cáo test"

dev:
	pnpm --dir web install --frozen-lockfile
	pnpm --dir web dev

verify:
	pnpm --dir web install --frozen-lockfile
	pnpm --dir web exec tsc -b
	pnpm --dir web lint
	pnpm --dir web test
	pnpm --dir web build
	$(MAKE) clean

verify-fast:
	@echo "chỉ docs: không có gì để chạy"

test:
	pnpm --dir web test

build:
	pnpm --dir web build

lint:
	pnpm --dir web lint

e2e:
	pnpm --dir web e2e

fixtures:
	pnpm --dir web fixtures

clean:
	rm -rf web/dist web/playwright-report web/test-results web/node_modules/.tmp web/node_modules/.vite
