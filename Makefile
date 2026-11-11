# Vedette — lệnh chung. Máy: `make check` trước khi push (D-62); CI gọi đúng các đích ở đây (D-63, docs/ENGINEERING.md §7).
# Node ghim trong web/package.json (devEngines), pnpm tự tải đúng bản.
# Go ghim trong go.mod (go tự tải toolchain); công cụ Go ghim trong tools/go.mod.
.PHONY: images check-min-sequence host-deb host-deb-check sensor-image core-image scan-pack scan-base-image scan-image images-check dev-sensors dev-sensors-down dev-sensors-smoke help oui dev dev-api check verify node-version-check verify-web verify-go verify-go-static test test-go test-go-shard test-go-release test-go-shards-check ci-changes contract lint lint-go vuln audit generate generate-sql generate-api generate-check openapi-check build web-release webui-dist webui-csp-check e2e fixtures clean

GO_TOOL := go tool -modfile=tools/go.mod

# Container images (D-146): every version and digest comes from deploy/containers/pins.env.
include deploy/containers/pins.env
CONTAINER ?= podman
IMAGE_VERSION ?= 0.0.0-dev
IMAGE_TAG ?= dev
PIN_ARGS := $(foreach v,GOLANG_IMAGE DEBIAN_IMAGE DISTROLESS_IMAGE NUCLEI_VERSION NUCLEI_ZIP_SHA256_AMD64 NUCLEI_ZIP_SHA256_ARM64 NUCLEI_BIN_SHA256_AMD64 NUCLEI_BIN_SHA256_ARM64 NMAP_MIN_VERSION SCAN_PACK_VERSION,--build-arg $(v)=$($(v))) --build-arg VERSION=$(IMAGE_VERSION)
PACK_DIR := deploy/containers/scan-base/pack
# Multi-arch images (WP-08d, D-158): `make images` builds sensor, scan-base and core for PLATFORMS as one manifest list per image.
PLATFORMS ?= linux/amd64,linux/arm64
# The index sequence floor compiled into vedette-host, the only binary that links internal/release (core does not, a test keeps that true).
# A plain decimal: it is the -X value of internal/release.MinSequenceText. The release job (WP-08f/k) passes the sequence of the index current at build time.
MIN_SEQUENCE ?= 0
RELEASE_PKG := github.com/knt048/vedette/internal/release

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
	@echo "make verify-go-static / test-go-shard SHARD=n / test-go-release   các phần của verify-go mà CI chạy song song (D-140)"
	@echo "make generate      sinh lại mã Go: sqlc (core/store/coredb) + ogen (core/api), commit kết quả"
	@echo "make contract      go test ./modules/... -run Contract"
	@echo "make e2e           kiểm thử đầu-cuối bằng Playwright (Chromium)"
	@echo "make audit         quét lỗ hổng dependency: govulncheck + pnpm audit (đầu mỗi phiên)"
	@echo "make oui          dựng lại content/oui/oui.tsv.gz từ runZero mac-tracker (cần mạng tới raw.githubusercontent.com, D-83)"
	@echo "make fixtures      kéo dữ liệu KEV/EPSS thật cho bảng nóng"
	@echo "make dev-sensors   core + sensor (pcap replay) + scan (fake nmap, fake nuclei) with docker compose, profile dev (D-146)"
	@echo "make dev-sensors-smoke   the same, checks that a device appears via the API within a bound, then tears down"
	@echo "make webui-dist    build the web release and copy it to internal/webui/dist (embedded by -tags webui; core-image runs it, D-149)"
	@echo "make sensor-image scan-base-image scan-image core-image  build the container images (CONTAINER=podman|docker); images-check builds and checks them by effect"
	@echo "make images       build sensor, scan-base and core for PLATFORMS=linux/amd64,linux/arm64 as one manifest list each, without CPU emulation (WP-08d, D-158); PLATFORMS=linux/amd64 needs no binfmt; no push"
	@echo "make host-deb VERSION=x.y.z [ARCH=amd64|arm64]   build dist/vedette-host_<version>_<arch>.deb with nfpm (WP-08g, D-155); host-deb-check installs it in systemd containers (opt-in, pulls images)"
	@echo "make reaper-install cài bộ dọn tiến trình test/dev mồ côi (10 phút một lần)"
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
	$(MAKE) web-release
	$(MAKE) clean

verify-go: verify-go-static
	$(MAKE) test-go vuln
	$(MAKE) clean

# CI job "go-static" (D-140): everything in verify-go except the tests and govulncheck, which run in their own jobs.
verify-go-static:
	go build ./...
	go vet ./...
	$(MAKE) generate-check contract lint-go test-go-shards-check

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

# test-go also runs internal/release, and the host's pull and embedded-keys tests (real minisign and cosign vectors, end to end), with the throwaway release keys (-tags releasetestkeys, keys_testonly.go); production never passes that tag
test-go:
	go test -race ./...
	$(MAKE) test-go-release

test-go-release:
	go test -race -tags releasetestkeys ./internal/release/...
	go test -race -tags releasetestkeys -run 'Pull|Embedded' ./modules/host/

# CI (D-140): the same `go test -race ./...` in SHARDS parallel jobs. `make test-go-shard SHARD=2` runs the second.
# scripts/ci splits `go list ./...` by test-file size; every package lands in exactly one shard.
SHARDS ?= 3
test-go-shard:
	@test -n "$(SHARD)" || { echo "usage: make test-go-shard SHARD=1 (of $(SHARDS))"; exit 2; }
	go test -race $$(go run ./scripts/ci shard $(SHARD) $(SHARDS))

# The shards together must be exactly `go list ./...` (no package lost, none twice).
test-go-shards-check:
	@want=$$(go list ./... | sort) && got=$$(for i in $$(seq 1 $(SHARDS)); do go run ./scripts/ci shard $$i $(SHARDS); done | sort) && \
	test "$$want" = "$$got" && echo "test-go-shards-check: $(SHARDS) shards cover $$(echo "$$want" | wc -l | tr -d ' ') packages exactly" || { echo "test-go-shards-check: shards differ from go list ./..."; exit 1; }

# CI change detection (D-140): prints go/web/vuln/audit switches (to $$GITHUB_OUTPUT when set) from GITHUB_EVENT_NAME and git diff HEAD^1..HEAD.
ci-changes:
	go run ./scripts/ci changes

# Mỗi INV/POST trong modules/<id>/CONTRACT.md có một TestContract… (docs/MODULE_CONTRACTS.md).
# Chưa có module Go nào thì bỏ qua thay vì lỗi "matched no packages".
contract:
	@if [ -n "$$(go list ./modules/... 2>/dev/null)" ]; then go test ./modules/... -run Contract; else echo "contract: no Go modules yet"; fi

build:
	pnpm --dir web build

# Release SPA (WP-08a): VITE_API_MOCK=off build, then fail if any mock layer is in web/dist.
# web/dist is left in place for the core embed (WP-08b); `make clean` removes it (build-artifacts rule).
web-release:
	VITE_API_MOCK=off pnpm --dir web build
	pnpm --dir web exec node scripts/check-release.mjs dist

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
	rm -rf bin .dev/bin dist coverage.out web/dist internal/webui/dist web/playwright-report web/test-results web/node_modules/.tmp web/node_modules/.vite $(PACK_DIR)

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

# Container images (D-146, DEPLOYMENT.md 2.2, 2.4). Build context is the repository root (.dockerignore keeps it small).
sensor-image:
	$(CONTAINER) build -f deploy/containers/sensor/Containerfile $(PIN_ARGS) -t localhost/vedette-sensor:$(IMAGE_TAG) .

# The core image embeds the interface (D-149): build it on this machine (Node is pinned by devEngines), copy it where `-tags webui` embeds it from.
webui-dist: web-release
	rm -rf internal/webui/dist
	mkdir -p internal/webui/dist
	cp -R web/dist/. internal/webui/dist/

# Real-browser CSP check of the embedded interface (D-149); heavy (Chromium), not part of check/verify.
webui-csp-check: webui-dist
	bash scripts/dev/webui-csp-check.sh || { $(MAKE) clean; exit 1; }
	$(MAKE) clean

# The generated web/dist and internal/webui/dist are removed on every exit path (build-artifacts rule), a failed build included.
core-image: webui-dist
	$(CONTAINER) build -f deploy/containers/core/Containerfile $(PIN_ARGS) -t localhost/vedette-core:$(IMAGE_TAG) . || { rm -rf web/dist internal/webui/dist; exit 1; }
	rm -rf web/dist internal/webui/dist

# The safe template pack: pinned download of nuclei-templates, filter, index (scripts/scanpack). Rebuilt (the folder removed first) whenever pins.env or the builder changes.
scan-pack: $(PACK_DIR)/index.json
$(PACK_DIR)/index.json: deploy/containers/pins.env $(wildcard scripts/scanpack/*.go)
	rm -rf $(PACK_DIR)
	go run ./scripts/scanpack -src-version $(NUCLEI_TEMPLATES_VERSION) -src-sha256 $(NUCLEI_TEMPLATES_SHA256) -version $(SCAN_PACK_VERSION) -out $(PACK_DIR)

# Multi-arch (WP-08d, D-158): one manifest list per image, every platform of PLATFORMS in it, local only (the push is the release job's, WP-08k).
# The Go and download stages run on this machine ($BUILDPLATFORM) and the target stages only COPY, so arm64 needs no qemu/binfmt.
# podman: `podman build --platform a,b --manifest`; docker: buildx writes an OCI archive to dist/images/ (the classic image store holds no
# manifest list) and a single platform is loaded with --load. $(1) = image name, $(2) = Containerfile.
ifeq ($(CONTAINER),docker)
MULTI = { mkdir -p dist/images && docker buildx build --platform $(PLATFORMS) $(if $(findstring $(comma),$(PLATFORMS)),--output type=oci$(comma)dest=dist/images/vedette-$(1)-$(IMAGE_TAG).tar,--load -t localhost/vedette-$(1):$(IMAGE_TAG)) -f $(2) $(PIN_ARGS) .; }
else
MULTI = { $(CONTAINER) rmi -f localhost/vedette-$(1):$(IMAGE_TAG) >/dev/null 2>&1 || true; $(CONTAINER) build --platform $(PLATFORMS) --manifest localhost/vedette-$(1):$(IMAGE_TAG) -f $(2) $(PIN_ARGS) .; }
endif
comma := ,
images: webui-dist scan-pack
	$(call MULTI,sensor,deploy/containers/sensor/Containerfile) && $(call MULTI,scan-base,deploy/containers/scan-base/Containerfile) && $(call MULTI,core,deploy/containers/core/Containerfile) || { rm -rf web/dist internal/webui/dist; exit 1; }
	rm -rf web/dist internal/webui/dist

# The published scan base: sensor binary + nuclei + the pack. NO nmap (D-4, D-113 (7)).
scan-base-image: scan-pack
	$(CONTAINER) build -f deploy/containers/scan-base/Containerfile $(PIN_ARGS) -t localhost/vedette-scan-base:$(IMAGE_TAG) .

# What vedette-host builds on the box, here for development and the check of the effect: scan-base + the pinned nmap from the OS repository.
scan-image: scan-base-image
	$(CONTAINER) build -f deploy/containers/scan/Containerfile.onbox $(PIN_ARGS) --build-arg BASE_IMAGE=localhost/vedette-scan-base:$(IMAGE_TAG) -t localhost/vedette-scan-nmap:$(IMAGE_TAG) .

# The vedette-host package (WP-08g, D-155): a static binary (the version flag like the core image's) and nfpm. VERSION is SemVer without a v.
# The binary goes to dist/host-deb/<arch>/, the package to dist/ (both removed by `make clean`).
ARCH ?= amd64
DEB_OUT ?= dist
check-min-sequence:
	@printf '%s' "$(MIN_SEQUENCE)" | grep -Eq '^(0|[1-9][0-9]{0,17})$$' || { echo "MIN_SEQUENCE must be a plain decimal number (0, or no leading zero, at most 18 digits), got '$(MIN_SEQUENCE)'" >&2; exit 1; }
host-deb: check-min-sequence
	@printf '%s' "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$$' || { echo "host-deb: VERSION must be SemVer without v (VERSION=0.1.0), got '$(VERSION)'" >&2; exit 1; }
	@case "$(ARCH)" in amd64|arm64) ;; *) echo "host-deb: ARCH must be amd64 or arm64, got '$(ARCH)'" >&2; exit 1;; esac
	mkdir -p $(DEB_OUT)/host-deb/$(ARCH)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -trimpath -ldflags "-s -w -X main.version=$(VERSION) -X $(RELEASE_PKG).MinSequenceText=$(MIN_SEQUENCE)" -o $(DEB_OUT)/host-deb/$(ARCH)/vedette-host ./cmd/vedette-host
	go run ./scripts/hostlicenses -goos linux -goarch $(ARCH) -out $(DEB_OUT)/host-deb/$(ARCH)/third-party-licenses
	VERSION=$(VERSION) ARCH=$(ARCH) BINARY=$(DEB_OUT)/host-deb/$(ARCH)/vedette-host LICENSES=$(DEB_OUT)/host-deb/$(ARCH)/third-party-licenses $(GO_TOOL) nfpm pkg --packager deb --config deploy/deb/nfpm.yaml --target $(DEB_OUT)/

# Installs the package twice in a systemd container per target OS (Debian 13, Ubuntu 24.04, pinned by digest in deploy/deb/check-pins.env)
# and checks the effects (scripts/dev/host-deb-check.sh). Pulls images and runs apt in them: opt-in, not in `make check` or CI.
host-deb-check:
	scripts/dev/host-deb-check.sh

# Builds the images one at a time and checks each by effect (scripts/dev/images-check.sh), then removes them (rules/build-artifacts.md).
images-check:
	scripts/dev/images-check.sh

# core + sensor (replays a pcap) + scan (fake nmap, fake nuclei) with docker compose, profile dev. Ctrl-C stops it; the volumes stay until `make dev-sensors-down`.
dev-sensors: scan-pack
	docker compose --env-file deploy/containers/pins.env -f deploy/compose/compose.yaml --profile dev up --build

dev-sensors-down:
	docker compose --env-file deploy/containers/pins.env -f deploy/compose/compose.yaml --profile dev down --rmi local --volumes --remove-orphans

# Up, a device that only the sensor can have seen appears in the inventory within a bound, down (D-146: not in CI yet).
dev-sensors-smoke: scan-pack
	scripts/dev/sensors-smoke.sh
