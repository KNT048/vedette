# Vedette — lệnh chung. Không có CI (D-61): mọi kiểm tra chạy trên máy bằng các đích ở đây (docs/ENGINEERING.md §7).
# Node ghim trong web/package.json (devEngines), pnpm tự tải đúng bản.
# Go ghim trong go.mod (go tự tải toolchain); công cụ Go ghim trong tools/go.mod.
.PHONY: help dev verify verify-web verify-go test test-go contract lint lint-go vuln audit openapi-check build e2e fixtures clean

GO_TOOL := go tool -modfile=tools/go.mod

help:
	@echo "make dev           chạy giao diện với dữ liệu mẫu tại http://localhost:5173"
	@echo "make verify        web + Go: gõ kiểu, lint, test, kiểm lệch hợp đồng, build (rồi dọn)"
	@echo "make verify-web    chỉ phần giao diện"
	@echo "make verify-go     chỉ phần Go: build, vet, test -race, contract, golangci-lint, govulncheck"
	@echo "make contract      go test ./modules/... -run Contract"
	@echo "make e2e           kiểm thử đầu-cuối bằng Playwright (Chromium)"
	@echo "make audit         quét lỗ hổng dependency: govulncheck + pnpm audit (đầu mỗi phiên)"
	@echo "make fixtures      kéo dữ liệu KEV/EPSS thật cho bảng nóng"
	@echo "make clean         xoá build output và báo cáo test"

dev:
	pnpm --dir web install --frozen-lockfile
	pnpm --dir web dev

verify: verify-web verify-go

verify-web:
	pnpm --dir web install --frozen-lockfile
	pnpm --dir web exec tsc -b
	pnpm --dir web lint
	pnpm --dir web test
	$(MAKE) openapi-check
	pnpm --dir web build
	$(MAKE) clean

verify-go:
	go build ./...
	go vet ./...
	$(MAKE) generate-api-check test-go contract lint-go vuln
	$(MAKE) clean

# api/openapi.json phải đúng bằng bản sinh từ contract.ts (D-18).
openapi-check:
	pnpm --dir web openapi
	git diff --exit-code -- api/openapi.json

test:
	pnpm --dir web test

test-go:
	go test -race ./...

# Mỗi INV/POST trong modules/<id>/CONTRACT.md có một TestContract… (docs/MODULE_CONTRACTS.md).
# Chưa có module Go nào thì bỏ qua thay vì lỗi "matched no packages".
contract:
	@if [ -n "$$(go list ./modules/... 2>/dev/null)" ]; then go test ./modules/... -run Contract; else echo "contract: no Go modules yet"; fi

build:
	pnpm --dir web build

lint:
	pnpm --dir web lint

lint-go:
	$(GO_TOOL) golangci-lint run

vuln:
	$(GO_TOOL) govulncheck ./...

# Quét định kỳ thay lịch CI (rules/local-checks.md): đầu mỗi phiên làm việc và trước phát hành.
audit: vuln
	pnpm --dir web audit --prod

e2e:
	pnpm --dir web e2e

fixtures:
	pnpm --dir web fixtures

clean:
	rm -rf bin coverage.out web/dist web/playwright-report web/test-results web/node_modules/.tmp web/node_modules/.vite

# Mã Go server sinh từ api/openapi.json (D-60): chuẩn hoá vào thư mục tạm, chạy ogen, ghi bảng vai.
# Bản chuẩn hoá không commit. Không sửa tay core/api/oas và core/api/routes/routes_gen.go.
.PHONY: generate-api generate-api-check
generate-api:
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	go run ./core/api/apigen -in api/openapi.json -spec "$$tmp/openapi.json" -routes core/api/routes/routes_gen.go && \
	go tool ogen --config core/api/ogen.yml --target core/api/oas --package oas --clean "$$tmp/openapi.json"

generate-api-check: generate-api
	git diff --exit-code -- core/api
	@test -z "$$(git status --porcelain -- core/api)" || { git status --porcelain -- core/api; echo "generate-api-check: untracked generated files"; exit 1; }
