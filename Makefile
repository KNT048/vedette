# Vedette — lệnh chung. Máy: `make check` trước khi push (D-62); CI gọi đúng các đích ở đây (D-63, docs/ENGINEERING.md §7).
# Node ghim trong web/package.json (devEngines), pnpm tự tải đúng bản.
# Go ghim trong go.mod (go tự tải toolchain); công cụ Go ghim trong tools/go.mod.
.PHONY: help oui dev dev-api check verify node-version-check verify-web verify-go test test-go contract lint lint-go vuln audit generate generate-sql generate-api generate-check openapi-check build e2e fixtures clean

GO_TOOL := go tool -modfile=tools/go.mod

# Chỉ dựng/kiểm trên Linux hoặc macOS (sản phẩm chạy Linux; test dùng syscall Unix). Windows: dùng WSL2 (D-62).
ifeq ($(OS),Windows_NT)
$(error Vedette builds and checks run on Linux or macOS only. On Windows, run make inside WSL2 (Ubuntu), from the WSL file system, not /mnt/c)
endif

help:
	@echo "make dev           chạy giao diện với dữ liệu mẫu tại http://localhost:5173"
	@echo "make dev-api      backend Go thật + giao diện; REAL=core,inventory chọn module thật, còn lại là mock"
	@echo "make check         kiểm nhanh phần đã đổi so với origin/main (cổng PR); đổi file dùng chung thì chạy verify"
	@echo "make verify        web + Go: gõ kiểu, lint, test, kiểm lệch hợp đồng, build (rồi dọn)"
	@echo "make verify-web    chỉ phần giao diện"
	@echo "make verify-go     chỉ phần Go: build, vet, generate-check, test -race, contract, golangci-lint, govulncheck"
	@echo "make generate      sinh lại mã Go: sqlc (core/store/coredb) + ogen (core/api), commit kết quả"
	@echo "make contract      go test ./modules/... -run Contract"
	@echo "make e2e           kiểm thử đầu-cuối bằng Playwright (Chromium)"
	@echo "make audit         quét lỗ hổng dependency: govulncheck + pnpm audit (đầu mỗi phiên)"
	@echo "make oui          dựng lại content/oui/oui.tsv.gz từ runZero mac-tracker (cần mạng tới raw.githubusercontent.com, D-83)"
	@echo "make fixtures      kéo dữ liệu KEV/EPSS thật cho bảng nóng"
	@echo "make reaper-install  cài bộ dọn tiến trình test/dev mồ côi (10 phút một lần)"
	@echo "make clean         xoá build output và báo cáo test"

dev:
	pnpm --dir web install --frozen-lockfile
	pnpm --dir web dev

# Backend Go thật cho các module trong REAL (mặc định core), mock cho phần còn lại; Ctrl-C dừng cả hai.
dev-api:
	scripts/dev/dev-api.sh

# Cổng PR (D-62): chỉ phần đã đổi; file dùng chung đổi thì tự chuyển sang verify đầy đủ.
check:
	scripts/check.sh

verify: verify-web verify-go

verify-web: node-version-check
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
	$(MAKE) generate-check test-go contract lint-go vuln
	$(MAKE) clean

# Mọi mã sinh được commit: truy vấn sqlc (DATA_MODEL §6) + server ogen (D-60). Không sửa tay.
generate: generate-sql generate-api

generate-sql:
	$(GO_TOOL) sqlc generate

# Sinh lại rồi so với bản đã commit: lệch (hoặc file sinh chưa được git theo dõi) = đỏ.
GENERATED := core/store/coredb core/api
generate-check: generate
	git diff --exit-code -- $(GENERATED)
	@test -z "$$(git status --porcelain -- $(GENERATED))" || { git status --porcelain -- $(GENERATED); echo "generate-check: untracked generated files"; exit 1; }

# web/.npmrc node-version phải bằng devEngines.runtime.version: pnpm bản độc lập kiểm engine bằng
# Node nhúng của nó và bỏ qua native binding của oxlint/rolldown (issue #21).
node-version-check:
	@want=$$(sed -n '/"devEngines"/,/}/s/.*"version": *"\([0-9.]*\)".*/\1/p' web/package.json); \
	have=$$(sed -n 's/^node-version=//p' web/.npmrc); \
	test -n "$$want" && test "$$want" = "$$have" || { echo "web/.npmrc node-version=$$have, devEngines.runtime.version=$$want: make them equal"; exit 1; }

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

# Quét lỗ hổng dependency: đầu mỗi phiên làm việc (CI cũng quét hằng ngày trên main).
audit: vuln
	pnpm --dir web audit --prod

e2e:
	pnpm --dir web e2e

fixtures:
	pnpm --dir web fixtures

# Bảng OUI→hãng (D-83): kéo macs.json của runZero mac-tracker (MIT, dựng từ 5 file CSV của IEEE) ở commit đã ghim, kiểm SHA-256, giữ tổ chức mới nhất cho mỗi tiền tố /24 /28 /36, ghi file nén có thứ tự cố định. Kết quả được commit; sản phẩm không tải gì lúc chạy.
oui:
	go run ./scripts/oui

clean:
	rm -rf bin .dev/bin coverage.out web/dist web/playwright-report web/test-results web/node_modules/.tmp web/node_modules/.vite

# Mã Go server sinh từ api/openapi.json (D-60): chuẩn hoá vào thư mục tạm, chạy ogen, ghi bảng vai.
# Bản chuẩn hoá không commit. Không sửa tay core/api/oas và core/api/routes/routes_gen.go.
generate-api:
	@tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
	go run ./core/api/apigen -in api/openapi.json -spec "$$tmp/openapi.json" -routes core/api/routes/routes_gen.go && \
	go tool ogen --config core/api/ogen.yml --target core/api/oas --package oas --clean "$$tmp/openapi.json"

.PHONY: reaper-install reaper-uninstall
# Dừng tiến trình test/dev mồ côi làm quá tải máy, chạy 10 phút một lần (launchd/systemd user).
reaper-install:
	scripts/dev/reaper-install.sh

reaper-uninstall:
	scripts/dev/reaper-install.sh --uninstall
