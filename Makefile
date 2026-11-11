# Vedette — lệnh chung. Máy: `make check` trước khi push (D-62); CI gọi đúng các đích ở đây (D-63, docs/ENGINEERING.md §7).
# Node ghim trong web/package.json (devEngines), pnpm tự tải đúng bản.
# Go ghim trong go.mod (go tự tải toolchain); công cụ Go ghim trong tools/go.mod.
.PHONY: images check-min-sequence host-deb host-deb-check sensor-image core-image honeypot-image honeypot-check scan-pack scan-base-image scan-image images-check dev-sensors dev-sensors-down dev-sensors-smoke help oui dev dev-api check verify node-version-check verify-web verify-go verify-go-static test test-go test-go-shard test-go-release test-go-shards-check ci-changes contract lint lint-go vuln audit generate generate-sql generate-api generate-check openapi-check build web-release webui-dist webui-csp-check e2e e2e-real fixtures clean sbom vuln-scan notices-check

GO_TOOL := go tool -modfile=tools/go.mod

# Container images (D-146): every version and digest comes from deploy/containers/pins.env.
include deploy/containers/pins.env
CONTAINER ?= podman
IMAGE_VERSION ?= 0.0.0-dev
IMAGE_TAG ?= dev
PIN_ARGS := $(foreach v,GOLANG_IMAGE DEBIAN_IMAGE DISTROLESS_IMAGE NUCLEI_VERSION NUCLEI_ZIP_SHA256_AMD64 NUCLEI_ZIP_SHA256_ARM64 NUCLEI_BIN_SHA256_AMD64 NUCLEI_BIN_SHA256_ARM64 NMAP_MIN_VERSION SCAN_PACK_VERSION OPENCANARY_VERSION SAMBA_MIN_VERSION,--build-arg $(v)=$($(v))) --build-arg VERSION=$(IMAGE_VERSION)
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
	@echo "make e2e-real      the real backend (release GUI inside core) + Playwright, web/e2e-real/; SPECS=..., E2E_WORKERS=n, HOLD=1; heavy, not in CI or check (D-170)"
	@echo "make audit         quét lỗ hổng dependency: govulncheck + pnpm audit (đầu mỗi phiên)"
	@echo "make oui          dựng lại content/oui/oui.tsv.gz từ runZero mac-tracker (cần mạng tới raw.githubusercontent.com, D-83)"
	@echo "make fixtures      kéo dữ liệu KEV/EPSS thật cho bảng nóng"
	@echo "make dev-sensors   core + sensor (pcap replay) + scan (fake nmap, fake nuclei) with docker compose, profile dev (D-146)"
	@echo "make dev-sensors-smoke   the same, checks that a device appears via the API within a bound, then tears down"
	@echo "make webui-dist    build the web release and copy it to internal/webui/dist (embedded by -tags webui; core-image runs it, D-149)"
	@echo "make sensor-image scan-base-image scan-image core-image  build the container images (CONTAINER=podman|docker); images-check builds and checks them by effect"
	@echo "make honeypot-image  build the honeypot image (OpenCanary + Samba, D-162); make honeypot-check builds it and checks it by effect (opt-in)"
	@echo "make images       build sensor, scan-base, core and honeypot for PLATFORMS=linux/amd64,linux/arm64 as one manifest list each, without CPU emulation (WP-08d, D-158); PLATFORMS=linux/amd64 needs no binfmt; no push"
	@echo "make sbom        CycloneDX SBOM (trivy) of each local image per platform and of the source, into dist/sbom/; RELEASE=1 keeps it; trivy's database cache: TRIVY_CACHE_DIR=~/.cache/vedette-trivy (WP-08i, D-159)"
	@echo "make vuln-scan    trivy on the local images and the source: fails on a fixable HIGH/CRITICAL; exceptions only in .trivyignore.yaml with reason and date (D-159)"
	@echo "make notices-check  THIRD_PARTY_NOTICES.md against the Go modules linked into the binaries and the web production dependencies; no GPL/AGPL (D-159)"
	@echo "make install-artifacts [FAST=1] [TEST_VERSION=0.0.1-test.1]   the TEST release for install.sh --test-artifacts into dist/install (.deb, images, documents signed with throwaway keys; WP-08h, D-166); install-check runs install.sh end to end in systemd containers (opt-in)"
	@echo "make release-cosign-plan / release-manifest / release-refresh / release-sign / release-verify   the release builder, offline, on the maintainer's machine (WP-08f, D-164): print the cosign commands, build release-manifest.json + index.json (refuses rollback.safe=true unless rollback.min_version is set and every migration since that release, read from git, is add-only, D-183); release-refresh = the weekly index refresh without a manifest (RELEASE_PREV_INDEX = the published index), sign with the pinned minisign (keys from MINISIGN_KEY / COSIGN_KEY, never argv secrets), verify with the box's verifier; output dist/release, removed after a successful verify unless RELEASE=1; see scripts/release"
	@echo "make release-interop   the builder and the box's verifier against the real pinned minisign (downloads it into ~/.cache/vedette-minisign, checks deploy/tools.env)"
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
	$(MAKE) notices-check NOTICES_WEB_LICENSES=0
	bash scripts/dev/orphan-reaper-test.sh

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
	go test -race -tags releasetestkeys -run 'Pull|Embedded|CommittedVectors' ./modules/host/

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

# Real-backend end-to-end (WP-30, D-170): builds the release GUI and the box, runs web/e2e-real/ on desktop. The script removes its build
# output on every exit path; the traces of a failed run stay in web/test-results/real until `make clean`.
e2e-real:
	bash scripts/dev/e2e-real.sh

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
	# core plans jobs against the same index (scan S5): a committed copy, embedded by content/nucleipack; a test holds it to pins.env
	cp $(PACK_DIR)/index.json content/nucleipack/index.json
	printf 'nuclei_templates_version: %s\nnuclei_templates_sha256: %s\nscan_pack_version: %s\n' '$(NUCLEI_TEMPLATES_VERSION)' '$(NUCLEI_TEMPLATES_SHA256)' '$(SCAN_PACK_VERSION)' > content/nucleipack/index.source

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
	$(call MULTI,sensor,deploy/containers/sensor/Containerfile) && $(call MULTI,scan-base,deploy/containers/scan-base/Containerfile) && $(call MULTI,core,deploy/containers/core/Containerfile) && $(call MULTI,honeypot,deploy/containers/honeypot/Containerfile) || { rm -rf web/dist internal/webui/dist; exit 1; }
	rm -rf web/dist internal/webui/dist

# The honeypot image (WP-08e, D-162): OpenCanary + Samba. Needs the network at build time (apt, PyPI). Its effects are checked by `make honeypot-check`.
honeypot-image:
	$(CONTAINER) build -f deploy/containers/honeypot/Containerfile $(PIN_ARGS) -t localhost/vedette-honeypot:$(IMAGE_TAG) .

# Builds the honeypot image, runs it as the unit does (no new privileges, read-only root, no capability) and checks what a connection does
# (scripts/dev/honeypot-check.sh), then removes the image and the containers. Opt-in, like images-check.
honeypot-check:
	scripts/dev/honeypot-check.sh

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

# Supply chain (WP-08i, D-159): the tool is trivy, the official image pinned by digest in deploy/tools.env, run with $(CONTAINER); its vulnerability
# database (1.7 GB) lands in $(TRIVY_CACHE_DIR), on disk, never /tmp (the maintainer's own download, not a product flow). They scan the local images of `make images` (every platform of
# PLATFORMS, tag IMAGE_TAG) and the source tree. RELEASE=1 keeps dist/sbom and dist/vuln for the release job (WP-08k); otherwise they are removed.
include deploy/tools.env
TRIVY_CACHE_DIR ?= $(HOME)/.cache/vedette-trivy
RELEASE ?=
SUPPLY_ENV = CONTAINER=$(CONTAINER) IMAGE_TAG=$(IMAGE_TAG) PLATFORMS=$(PLATFORMS) TRIVY_IMAGE=$(TRIVY_IMAGE) TRIVY_CACHE_DIR=$(TRIVY_CACHE_DIR) RELEASE=$(RELEASE)
sbom:
	$(SUPPLY_ENV) scripts/dev/supply-chain.sh sbom

# Fails on any HIGH or CRITICAL vulnerability that has a fix, in an image or in the source; the rest is reported. Exceptions: .trivyignore.yaml only,
# and an entry without a reason, or past its date (or too far ahead), fails first (scripts/trivyignore).
vuln-scan:
	go run ./scripts/trivyignore -file .trivyignore.yaml
	$(SUPPLY_ENV) scripts/dev/supply-chain.sh scan

# THIRD_PARTY_NOTICES.md against the Go modules linked into the shipped binaries and the web production dependencies (no network). With
# NOTICES_WEB_LICENSES=1 (default) it also asks pnpm for the licenses of the whole web production tree; verify-go-static turns that off (no pnpm in the go job).
NOTICES_WEB_LICENSES ?= 1
notices-check:
	go run ./scripts/noticescheck -notices THIRD_PARTY_NOTICES.md -cmd ./cmd/vedette -cmd ./cmd/vedette-host -cmd ./cmd/vedette-sensor -web web $(if $(filter 1,$(NOTICES_WEB_LICENSES)),-web-licenses)

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

# ---- install.sh (WP-08h, D-166) ----------------------------------------------------------------------------------------------
# install-artifacts: the TEST release for `install.sh --test-artifacts DIR`, signed with throwaway keys made on the spot (the real keys and
# images do not exist before WP-08k). The folder dist/install is the product (copy it to the box); the work folder and the local images
# are removed unless RELEASE=1; `make clean` removes dist. FAST=1: core with a placeholder interface + sensor, for install-check.
# install-check: install.sh end to end in systemd containers (Ubuntu 24.04, 26.04, Debian 13), opt-in: pulls base images, runs apt in them.
.PHONY: install-artifacts install-check
TEST_VERSION ?= 0.0.1-test.1
FAST ?=
install-artifacts:
	VERSION=$(TEST_VERSION) ARCH=$(ARCH) FAST=$(FAST) RELEASE=$(RELEASE) scripts/dev/install-artifacts.sh

install-check:
	scripts/dev/install-check.sh
# ---- Release builder (WP-08f, D-164): offline, on the maintainer's machine, no key in the repo, nothing pushed, no tag. Block kept apart on purpose. ----
# Flow: kien tags v<version> first (the manifest reads the migrations at that ref, even for rollback.safe=false; or pass RELEASE_REF) ->
# build and push the images (08k) -> write release.in.json (leave released_at empty: the builder fills it, and a time more than 10 minutes
# from the clock is refused) -> release-cosign-plan (prints the cosign commands; run them) -> release-manifest
# (release-manifest.json + index.json, unsigned) -> release-sign (active key; again with RELEASE_SLOT=backup for the offline key, indexes only) ->
# release-verify (the box's verifier over the output, with the keys of RELEASE_KEYS or, when unset, the ones compiled into the build).
#   RELEASE_IN     release description (default release.in.json)
#   RELEASE_PREV_INDEX  directory of the published index.json and .minisig (omit for the first release); the sequence, revocations and
#                  channels carry on from it. It is not the rollback baseline: that is rollback.min_version of release.in.json, and
#                  rollback.safe=true requires it (the D-183 guard compares the migrations of git tag v<min_version> with the release's, D-164)
#   RELEASE_REF / RELEASE_BASELINE_REF  git refs of the release (default v<version>) and of the baseline (default v<min_version>); the
#                  migrations are read from git, and a modified or untracked migration file refuses the build
#   release-refresh  the weekly index refresh (D-150): no manifest; builds a new index from RELEASE_PREV_INDEX into dist/release (use a clean
#                  dist), then run release-sign and release-verify on it
#   RELEASE_KEYS   directory with minisign.pub, minisign-backup.pub, cosign.pub
#   COSIGN_KEY / MINISIGN_KEY  paths of the private key files (outside the repo, mode 600); passphrases are never arguments:
#                  cosign reads COSIGN_PASSWORD from your shell, minisign asks on the terminal (PASSPHRASE_STDIN=1 reads one line of stdin)
#   MINISIGN_BIN   a minisign you trust (default: the pinned one, fetched by scripts/release/minisign.sh)
.PHONY: release-cosign-plan release-manifest release-refresh release-sign release-verify release-interop
RELEASE_OUT := dist/release
RELEASE_IN ?= release.in.json
RELEASE_PREV_INDEX ?=
RELEASE_REF ?=
RELEASE_BASELINE_REF ?=
RELEASE_KEYS ?=
RELEASE_SLOT ?= active
RELEASE_GO = go run ./scripts/release
RELEASE_KEYS_ARG = $(if $(RELEASE_KEYS),-keys-dir $(RELEASE_KEYS))

release-cosign-plan:
	@test -n "$$COSIGN_KEY" || { echo "release-cosign-plan: set COSIGN_KEY to the path of the cosign private key" >&2; exit 1; }
	$(RELEASE_GO) cosign-plan -in $(RELEASE_IN) -key "$$COSIGN_KEY" -out $(RELEASE_OUT)/cosign

release-manifest:
	$(RELEASE_GO) manifest -in $(RELEASE_IN) -cosign-dir $(RELEASE_OUT)/cosign -out $(RELEASE_OUT) $(if $(RELEASE_PREV_INDEX),-prev-index $(RELEASE_PREV_INDEX)) $(if $(RELEASE_REF),-ref $(RELEASE_REF)) $(if $(RELEASE_BASELINE_REF),-baseline-ref $(RELEASE_BASELINE_REF)) $(RELEASE_KEYS_ARG)
	$(RELEASE_GO) index -out $(RELEASE_OUT) -manifest $(RELEASE_OUT)/release-manifest.json $(if $(RELEASE_PREV_INDEX),-prev-index $(RELEASE_PREV_INDEX)) $(RELEASE_KEYS_ARG)

release-refresh:
	$(RELEASE_GO) index -out $(RELEASE_OUT) -prev-index "$(RELEASE_PREV_INDEX)" $(RELEASE_KEYS_ARG)

release-sign:
	@test -n "$$MINISIGN_KEY" || { echo "release-sign: set MINISIGN_KEY to the path of the minisign secret key (outside the repo)" >&2; exit 1; }
	$(RELEASE_GO) sign -dir $(RELEASE_OUT) -key "$$MINISIGN_KEY" -minisign "$${MINISIGN_BIN:-$$(scripts/release/minisign.sh)}" -slot $(RELEASE_SLOT) $(if $(PASSPHRASE_STDIN),-passphrase-stdin)

# A failed verify leaves dist/release for inspection; a good one removes it unless RELEASE=1 (rules/build-artifacts.md).
release-verify:
	$(RELEASE_GO) verify -dir $(RELEASE_OUT) $(if $(RELEASE_PREV_INDEX),-prev-index $(RELEASE_PREV_INDEX)) $(RELEASE_KEYS_ARG)
	@if [ "$(RELEASE)" != 1 ]; then rm -rf $(RELEASE_OUT); rmdir dist 2>/dev/null || true; fi

# The builder and the verifier against the real, pinned minisign (fails when the tool is missing, unlike `go test`, which skips).
release-interop:
	scripts/release/minisign.sh > /dev/null
	VEDETTE_REQUIRE_MINISIGN=1 go test -count=1 -run 'Interop|Pin' ./scripts/release
