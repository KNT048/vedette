# Vedette — lệnh chung. Máy: `make check` trước khi push (D-62); CI gọi đúng các đích ở đây (D-63, docs/ENGINEERING.md §7).
# Node ghim trong web/package.json (devEngines), pnpm tự tải đúng bản.
# Go ghim trong go.mod (go tự tải toolchain); công cụ Go ghim trong tools/go.mod.
.PHONY: images check-min-sequence host-deb host-deb-check sensor-image core-image honeypot-image honeypot-check syslog-ports-check scan-pack scan-base-image scan-image images-check dev-sensors dev-sensors-down dev-sensors-smoke help oui dev dev-api check check-fast verify node-version-check verify-web verify-go verify-go-static test test-go test-go-shard test-go-release test-go-shards-check ci-changes ci-flaky contract lint lint-go vuln audit generate generate-sql generate-api generate-check openapi-check build web-release webui-dist webui-csp-check e2e e2e-real fixtures clean sbom vuln-scan notices-check

GO_TOOL := go tool -modfile=tools/go.mod

# Container images (D-146): every version and digest comes from deploy/containers/pins.env.
include deploy/containers/pins.env
CONTAINER ?= podman
IMAGE_VERSION ?= 0.0.0-dev
# test channel only (scripts/dev/install-artifacts.sh, #469): the public throwaway keys compiled into core; the Containerfile refuses it unless VERSION has -test.
TEST_KEYS_B64 ?=
IMAGE_TAG ?= dev
PIN_ARGS := $(foreach v,GOLANG_IMAGE DEBIAN_IMAGE DISTROLESS_IMAGE NUCLEI_VERSION NUCLEI_SRC_SHA256 NMAP_MIN_VERSION SCAN_PACK_VERSION OPENCANARY_VERSION SAMBA_MIN_VERSION,--build-arg $(v)=$($(v))) --build-arg VERSION=$(IMAGE_VERSION)
PACK_DIR := deploy/containers/scan-base/pack
# Multi-arch images (WP-08d, D-158): `make images` builds sensor, scan-base and core for PLATFORMS as one manifest list per image.
PLATFORMS ?= linux/amd64,linux/arm64
# The index sequence floor compiled into the binaries that link internal/release: vedette-host, and core (since D-347, for the signed
# mitigation packs; a test keeps the list exact). A plain decimal: it is the -X value of internal/release.MinSequenceText. With
# RELEASE_PREV_INDEX (the published index, a directory) it is that index's sequence, read and verified by `release min-sequence`; without
# it, 0 (development, the first release). host-deb of a real version refuses to default it (below): give RELEASE_PREV_INDEX, or
# MIN_SEQUENCE=0 for the very first release.
ifndef MIN_SEQUENCE
ifneq ($(RELEASE_PREV_INDEX),)
MIN_SEQUENCE := $(shell go run ./scripts/release min-sequence -prev-index '$(RELEASE_PREV_INDEX)' $(if $(RELEASE_KEYS),-keys-dir '$(RELEASE_KEYS)'))
else
MIN_SEQUENCE := 0
endif
endif
RELEASE_PKG := github.com/knt048/vedette/internal/release

# Chỉ dựng/kiểm trên Linux hoặc macOS (sản phẩm chạy Linux; test dùng syscall Unix). Windows: dùng WSL2 (D-62).
ifeq ($(OS),Windows_NT)
$(error Vedette builds and checks run on Linux or macOS only. On Windows, run make inside WSL2 (Ubuntu), from the WSL file system, not /mnt/c)
endif

help:
	@echo "make dev           chạy giao diện với dữ liệu mẫu tại http://localhost:5173"
	@echo "make dev-api      backend Go thật + giao diện; REAL=core,inventory chọn module thật, còn lại là mock"
	@echo "make check-fast    cổng trước khi push: build, vet, lint dòng mới, test (không -race) của gói đã đổi, tsc/lint/vitest --changed (D-370)"
	@echo "make check         kiểm phần đã đổi so với origin/main kèm -race và gói phụ thuộc (tuỳ chọn; tái hiện CI đỏ)"
	@echo "make verify        web + Go: gõ kiểu, lint, test, kiểm lệch hợp đồng, build (rồi dọn)"
	@echo "make verify-web    chỉ phần giao diện"
	@echo "make verify-go     chỉ phần Go: build, vet, generate-check, test -race (gồm contract), golangci-lint, govulncheck"
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
	@echo "make container-only-smoke   the container-only install on Docker and Podman (builds images, checks ports/key/uid/caps, tears down); opt-in, slow, not in check or CI"
	@echo "make webui-dist    build the web release and copy it to internal/webui/dist (embedded by -tags webui; core-image runs it, D-149)"
	@echo "make sensor-image scan-base-image scan-image core-image  build the container images (CONTAINER=podman|docker); images-check builds and checks them by effect"
	@echo "make honeypot-image  build the honeypot image (OpenCanary + Samba, D-162); make honeypot-check builds it and checks it by effect (opt-in)"
	@echo "make images       build sensor, scan-base, core and honeypot for PLATFORMS=linux/amd64,linux/arm64 as one manifest list each, without CPU emulation (WP-08d, D-158); PLATFORMS=linux/amd64 needs no binfmt; no push"
	@echo "make sbom        CycloneDX SBOM (trivy) of each local image per platform and of the source, into dist/sbom/; RELEASE=1 keeps it; trivy's database cache: TRIVY_CACHE_DIR=~/.cache/vedette-trivy (WP-08i, D-159)"
	@echo "make vuln-scan    trivy on the local images and the source: fails on a fixable HIGH/CRITICAL; exceptions only in .trivyignore.yaml with reason and date (D-159)"
	@echo "make notices-check  THIRD_PARTY_NOTICES.md against the Go modules linked into the binaries and the web production dependencies; no GPL/AGPL (D-159)"
	@echo "make release-gates VERSION=<v> RELEASE_PREV_INDEX=<prev>   step 3 of the release job (D-457, D-401), after make images and both host-deb: vuln-scan + sbom (kept in dist/sbom, dist/vuln), notices-check, check-binaries -release inside each .deb, the version label of every image platform and core's floor label, each .deb rebuilt with the floor and compared byte for byte; then dist/release/gates.json, the record release-push and release-in refuse to differ from; MIN_SEQUENCE=0 instead of RELEASE_PREV_INDEX for the very first release only"
	@echo "make install-artifacts [FAST=1] [TEST_VERSION=0.0.1-test.1]   the TEST release for install.sh --test-artifacts into dist/install (.deb, images, documents signed with throwaway keys; WP-08h, D-166); install-check runs install.sh end to end in systemd containers (opt-in)"
	@echo "make release-cosign-plan / release-manifest / release-refresh / release-sign / release-verify   the release builder, offline, on the maintainer's machine (WP-08f, D-164): print the cosign commands, build release-manifest.json + index.json (refuses rollback.safe=true unless rollback.min_version is set and every migration since that release, read from git, is add-only, D-183); release-refresh = the weekly index refresh without a manifest (RELEASE_PREV_INDEX = the published index), sign with the pinned minisign (keys from MINISIGN_KEY / COSIGN_KEY, never argv secrets), verify with the box's verifier; output dist/release, removed after a successful verify unless RELEASE=1; see scripts/release"
	@echo "make release-container-assets   after release-manifest: the container-only files (compose.yaml, compose.sensors.yaml, compose.syslog.yaml, vedette.env with the three image digests) read from git at the tag into dist/release; release-sign signs them, release-verify requires them when install_modes lists container (D-451)"
	@echo "make release-push VERSION=<v> / release-in RELEASE_CHANNEL=stable RELEASE_ROLLBACK_SAFE=false / release-publish [PUBLISH=1]   the release job's network steps (WP-08k, D-457): images by digest to ghcr (images.json), release.in.json, then the gh release assets with the index last; order in docs/plans/2026-11-12-wp08k-release-job.md"
	@echo "make release-deb-name VERSION=<v> / release-bake-install   part A of the release job (D-457): SemVer names of prerelease .deb before release-in; install.sh with its three lines baked and signed (MINISIGN_KEY) into dist/release"
	@echo "make release-packs PACKS_VERSION=<n.n.n>   sign the confirmed mitigation packs of content/mitigation/packs with the release minisign key before the core image is built (D-345; MINISIGN_KEY, maintainer machine)"
	@echo "make release-interop   the builder and the box's verifier against the real pinned minisign (downloads it into ~/.cache/vedette-minisign, checks deploy/tools.env)"
	@echo "release preflight: release-manifest refuses a -test. version and, with RELEASE_PREV_INDEX, an index sequence not above MIN_SEQUENCE (host-deb takes it from that index); host-deb of a real version needs RELEASE_PREV_INDEX (or MIN_SEQUENCE=0 for the first release), refuses -overlay/-tags in GOFLAGS and a dirty tree, and checks the built vedette-host (go run ./scripts/release check-binaries -release BINARY: no -tags releasetestkeys, the production key bytes inside) and sets file times from SOURCE_DATE_EPOCH (commit time)"
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

# Cổng trước khi push (D-370): gói đã đổi, không -race, không gói phụ thuộc, không Playwright; không cần khe việc nặng. CI là cổng merge.
check-fast:
	scripts/check-fast.sh

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
	$(MAKE) lint-go test-go vuln
	$(MAKE) clean

# CI job "go-static" (D-140): everything in verify-go except golangci-lint (job go-lint), the tests and govulncheck. No
# `make contract` (D-372): go-test runs every TestContract… already, with -race on the merge queue; `make contract` stays for check.
verify-go-static:
	go build ./...
	go vet ./...
	$(MAKE) generate-check test-go-shards-check
	$(MAKE) notices-check NOTICES_WEB_LICENSES=0
	bash scripts/dev/orphan-reaper-test.sh
	bash scripts/dev/lab-vm-test.sh

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
# RACE= drops the race detector: every go-test but the daily run's does (D-371, D-376), so main's test cache serves the merge queue.
# scripts/ci splits `go list ./...` by the measured test time of scripts/ci/testtime.tsv (D-365); every package lands in
# exactly one shard. The shard's packages may come from go test's cache, except those whose tests read files through a child
# process (go build, go list), which the cache cannot see: they always run (`ci shard I N uncached`, D-365). GOTESTFLAGS adds go
# test flags (CI's daily run: -count=2 -shuffle=on and a longer -timeout, uncached).
# -timeout 18m (the job allows 20 m) is a stopgap: modules/response alone passes go test's default 10 m under -race on CI and turned
# main red (2026-11-12). The real fix is fast response tests (branch fix/storetest-sync-off, target < 120 s); then lower it.
# SKIPTESTS=1 (the default) skips the tests of scripts/ci/skip-tests.txt (slow ones, quarantined flaky ones; D-376); the daily
# schedule sets SKIPTESTS= and runs them all. -skip is a cacheable flag, so main's test cache still serves pull requests.
SHARDS ?= 4
RACE ?= -race
SKIPTESTS ?= 1
test-go-shard:
	@test -n "$(SHARD)" || { echo "usage: make test-go-shard SHARD=1 (of $(SHARDS))"; exit 2; }
	@c=$$(go run ./scripts/ci shard $(SHARD) $(SHARDS) cached) && u=$$(go run ./scripts/ci shard $(SHARD) $(SHARDS) uncached) || exit 1; \
	skip='^$$'; if [ -n "$(SKIPTESTS)" ]; then skip=$$(go run ./scripts/ci skip) || exit 1; skip=$${skip:-^$$}; fi; \
	s=0; if [ -n "$$c" ]; then go test $(RACE) -timeout 18m -skip "$$skip" $(GOTESTFLAGS) $$c || s=1; fi; \
	if [ -n "$$u" ]; then go test $(RACE) -count=1 -timeout 18m -skip "$$skip" $(GOTESTFLAGS) $$u || s=1; fi; exit $$s

# The shards together must be exactly `go list ./...` (no package lost, none twice).
test-go-shards-check:
	@want=$$(go list ./... | sort) && got=$$(for i in $$(seq 1 $(SHARDS)); do go run ./scripts/ci shard $$i $(SHARDS); done | sort) && \
	test "$$want" = "$$got" && echo "test-go-shards-check: $(SHARDS) shards cover $$(echo "$$want" | wc -l | tr -d ' ') packages exactly" || { echo "test-go-shards-check: shards differ from go list ./..."; exit 1; }

# CI change detection (D-140): prints go/web/vuln/audit switches (to $$GITHUB_OUTPUT when set) from GITHUB_EVENT_NAME and git diff HEAD^1..HEAD.
ci-changes:
	go run ./scripts/ci changes

# The daily run's flaky issue (D-365), CI only (GH_TOKEN, GH_REPO): the failed go-test jobs' logs of this run become the list of
# failed tests by package, added to the one open issue labelled flaky (or a new one).
ci-flaky:
	@test -n "$$GITHUB_RUN_ID" && test -n "$$GH_REPO" || { echo "ci-flaky runs in CI (GITHUB_RUN_ID, GH_REPO, GH_TOKEN)"; exit 2; }
	@url="$$GITHUB_SERVER_URL/$$GH_REPO/actions/runs/$$GITHUB_RUN_ID"; \
	jobs=$$(gh api "repos/$$GH_REPO/actions/runs/$$GITHUB_RUN_ID/jobs?per_page=100" --jq '.jobs[] | select(.conclusion != "success" and .conclusion != "skipped" and (.name | startswith("go-test"))) | .id') || exit 1; \
	: > logs.txt; for j in $$jobs; do gh api "repos/$$GH_REPO/actions/jobs/$$j/logs" >> logs.txt || exit 1; done; \
	go run ./scripts/ci flaky "$$url" < logs.txt > flaky.md || exit 1; rm -f logs.txt; \
	[ -s flaky.md ] || echo "The daily run failed in go-test, but no failed test was found in its logs: $$url" > flaky.md; \
	gh label create flaky --color d93f0b --description "A test failed in the daily -count=2 -shuffle=on run (D-365)" --force >/dev/null || exit 1; \
	n=$$(gh issue list --label flaky --state open --json number --jq '.[0].number') || exit 1; \
	if [ -n "$$n" ]; then gh issue comment "$$n" --body-file flaky.md; else gh issue create --title "Flaky tests (daily -count=2 -shuffle=on run)" --label flaky --body-file flaky.md; fi; \
	s=$$?; rm -f flaky.md; exit $$s

# Mỗi INV/POST trong modules/<id>/CONTRACT.md có một TestContract… (docs/MODULE_CONTRACTS.md).
# Chưa có module Go nào thì bỏ qua thay vì lỗi "matched no packages".
contract:
	@if [ -n "$$(go list ./modules/... 2>/dev/null)" ]; then go test ./modules/... -run Contract; else echo "contract: no Go modules yet"; fi

build:
	pnpm --dir web build

# Release SPA (WP-08a): VITE_API_MOCK=off build, then fail if any mock layer is in web/dist.
# web/dist is left in place for the core embed (WP-08b); `make clean` removes it (build-artifacts rule).
web-release:
	pnpm --dir web install --frozen-lockfile
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
	rm -rf bin .dev/bin dist coverage.out web/dist internal/webui/dist internal/webui/licenses web/playwright-report web/test-results web/node_modules/.tmp web/node_modules/.vite $(PACK_DIR)

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
# The licenses of its npm packages go to internal/webui/licenses/ (outside dist, so they are not embedded in the binary; the core image copies them).
webui-dist: web-release
	rm -rf internal/webui/dist
	mkdir -p internal/webui/dist
	cp -R web/dist/. internal/webui/dist/
	rm -rf internal/webui/licenses
	go run ./scripts/weblicenses -web web -out internal/webui/licenses/web-third-party-licenses.txt

# Real-browser CSP check of the embedded interface (D-149); heavy (Chromium), not part of check/verify.
webui-csp-check: webui-dist
	bash scripts/dev/webui-csp-check.sh || { $(MAKE) clean; exit 1; }
	$(MAKE) clean

# The generated web/dist and internal/webui/dist are removed on every exit path (build-artifacts rule), a failed build included.
core-image: webui-dist check-min-sequence
	$(CONTAINER) build -f deploy/containers/core/Containerfile $(PIN_ARGS) --build-arg MIN_SEQUENCE=$(MIN_SEQUENCE) --build-arg TEST_KEYS_B64=$(TEST_KEYS_B64) -t localhost/vedette-core:$(IMAGE_TAG) . || { rm -rf web/dist internal/webui/dist internal/webui/licenses; exit 1; }
	rm -rf web/dist internal/webui/dist internal/webui/licenses

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
# manifest list) and a single platform is loaded with --load. $(1) = image name, $(2) = Containerfile, $(3) = extra build arguments. An old list of the same tag is removed first (`manifest rm`; `rmi` of a list says "tag not known"), else the build is appended to it.
ifeq ($(CONTAINER),docker)
MULTI = { mkdir -p dist/images && docker buildx build --platform $(PLATFORMS) $(if $(findstring $(comma),$(PLATFORMS)),--output type=oci$(comma)dest=dist/images/vedette-$(1)-$(IMAGE_TAG).tar,--load -t localhost/vedette-$(1):$(IMAGE_TAG)) -f $(2) $(PIN_ARGS) $(3) .; }
else
MULTI = { $(CONTAINER) manifest rm localhost/vedette-$(1):$(IMAGE_TAG) >/dev/null 2>&1 || $(CONTAINER) rmi -f localhost/vedette-$(1):$(IMAGE_TAG) >/dev/null 2>&1 || true; $(CONTAINER) build --platform $(PLATFORMS) --manifest localhost/vedette-$(1):$(IMAGE_TAG) -f $(2) $(PIN_ARGS) $(3) .; }
endif
comma := ,
images: webui-dist scan-pack check-min-sequence
	$(call MULTI,sensor,deploy/containers/sensor/Containerfile) && $(call MULTI,scan-base,deploy/containers/scan-base/Containerfile) && $(call MULTI,core,deploy/containers/core/Containerfile,--build-arg MIN_SEQUENCE=$(MIN_SEQUENCE) --build-arg TEST_KEYS_B64=$(TEST_KEYS_B64)) && $(call MULTI,honeypot,deploy/containers/honeypot/Containerfile) || { rm -rf web/dist internal/webui/dist internal/webui/licenses; exit 1; }
	rm -rf web/dist internal/webui/dist internal/webui/licenses

# The honeypot image (WP-08e, D-162): OpenCanary + Samba. Needs the network at build time (apt, PyPI). Its effects are checked by `make honeypot-check`.
honeypot-image:
	$(CONTAINER) build -f deploy/containers/honeypot/Containerfile $(PIN_ARGS) -t localhost/vedette-honeypot:$(IMAGE_TAG) .

# Builds the honeypot image, runs it as the unit does (no new privileges, read-only root, no capability) and checks what a connection does
# (scripts/dev/honeypot-check.sh), then removes the image and the containers. Opt-in, like images-check.
honeypot-check:
	scripts/dev/honeypot-check.sh

# Does core's published syslog port (514 -> 5514, rootful podman) keep the real sender address for UDP and TCP, and survive a core restart (#266, D-167)?
# Opt-in, run as root from your own account: `sudo make syslog-ports-check`. While it runs it changes the host: a podman network and container (with
# netavark's nftables DNAT of <LAN address>:514), a netns vedette-slc-peer with a veth pair on 10.231.77.0/30, and net.ipv4.ip_forward is read and
# written back; the trap undoes all of it. Never netplan, NetworkManager, the LAN interface or other firewall rules. Needs 514 free (scripts/dev/syslog-ports-check.sh).
syslog-ports-check:
	scripts/dev/syslog-ports-check.sh

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
# The file time inside the .deb (nfpm reads SOURCE_DATE_EPOCH): the commit time, so two builds of one commit give the same bytes.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct)
# A real release is any VERSION that is not a test one (-test. anywhere, like install.sh, or a -test suffix): only that one gets the release preflight.
RELEASE_BUILD := $(if $(or $(findstring -test.,$(VERSION)),$(filter %-test,$(VERSION))),,1)
check-min-sequence:
	@printf '%s' "$(MIN_SEQUENCE)" | grep -Eq '^(0|[1-9][0-9]{0,17})$$' || { echo "MIN_SEQUENCE must be a plain decimal number (0, or no leading zero, at most 18 digits), got '$(MIN_SEQUENCE)'" >&2; exit 1; }
host-deb: check-min-sequence
	@printf '%s' "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$$' || { echo "host-deb: VERSION must be SemVer without v (VERSION=0.1.0), got '$(VERSION)'" >&2; exit 1; }
	@case "$(ARCH)" in amd64|arm64) ;; *) echo "host-deb: ARCH must be amd64 or arm64, got '$(ARCH)'" >&2; exit 1;; esac
	@printf '%s' "$(SOURCE_DATE_EPOCH)" | grep -Eq '^[0-9]{1,12}$$' || { echo "host-deb: SOURCE_DATE_EPOCH must be Unix seconds (default: the commit time of HEAD; is this a git checkout?), got '$(SOURCE_DATE_EPOCH)'" >&2; exit 1; }
ifneq ($(RELEASE_BUILD),)
	@$(if $(or $(RELEASE_PREV_INDEX),$(filter-out file,$(origin MIN_SEQUENCE))),:,echo "host-deb: a release ($(VERSION)) needs the sequence floor of the published index: pass RELEASE_PREV_INDEX=<published index dir>, or MIN_SEQUENCE=0 for the very first release only" >&2; exit 1)
	@case " $$GOFLAGS $$(go env GOFLAGS) " in *-overlay*|*-tags*) echo "host-deb: a release ($(VERSION)) is not built with -overlay or -tags in GOFLAGS (it could embed other keys); unset GOFLAGS" >&2; exit 1;; esac
endif
	mkdir -p $(DEB_OUT)/host-deb/$(ARCH)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) GOAMD64=v1 GOARM64=v8.0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION) -X $(RELEASE_PKG).MinSequenceText=$(MIN_SEQUENCE)" -o $(DEB_OUT)/host-deb/$(ARCH)/vedette-host ./cmd/vedette-host
	GOFLAGS= go run ./scripts/release check-binaries $(if $(RELEASE_BUILD),-release) $(DEB_OUT)/host-deb/$(ARCH)/vedette-host
	go run ./scripts/hostlicenses -goos linux -goarch $(ARCH) -out $(DEB_OUT)/host-deb/$(ARCH)/third-party-licenses
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) VERSION=$(VERSION) ARCH=$(ARCH) BINARY=$(DEB_OUT)/host-deb/$(ARCH)/vedette-host LICENSES=$(DEB_OUT)/host-deb/$(ARCH)/third-party-licenses $(GO_TOOL) nfpm pkg --packager deb --config deploy/deb/nfpm.yaml --target $(DEB_OUT)/

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

# The release gates (WP-08k part B, step 3 of docs/plans/2026-11-12-wp08k-release-job.md; D-457, D-401): after `make images IMAGE_TAG=<v>
# IMAGE_VERSION=<v>` and `make host-deb VERSION=<v> ARCH=amd64|arm64`, all with the same RELEASE_PREV_INDEX, from a full clone at the clean tag.
# In order, stopping at the first failure: VERSION and the tree (`release gates -preflight`: SemVer, no -test., HEAD = tag v<v>, clean);
# vuln-scan (the .trivyignore.yaml dates first) and sbom of the lists tagged <v>, kept in dist/vuln and dist/sbom (RELEASE=1, part C attests
# the SBOMs); notices-check; then `release gates`: check-binaries -release on the vedette-host inside both .deb, the version label of every
# platform of the four lists (and core's floor label), and each .deb built again with the floor of RELEASE_PREV_INDEX (MIN_SEQUENCE, the
# verified sequence of that index, checked again by `release gates` since make lets a MIN_SEQUENCE from the environment win; MIN_SEQUENCE=0
# for the very first release only) and compared byte for byte (the .deb is reproducible: build it and run this with GOFLAGS unset).
# Only when all of it passed does `release gates` write $(RELEASE_OUT)/gates.json (each .deb's sha256 and size, each image platform's
# config digest); it removes an earlier one first. release-push and release-in refuse anything that differs from it.
.PHONY: release-gates
RELEASE_GATES_ARGS = -version '$(VERSION)' -min-sequence '$(MIN_SEQUENCE)' $(if $(RELEASE_PREV_INDEX),-prev-index '$(RELEASE_PREV_INDEX)') $(RELEASE_KEYS_ARG)
release-gates: check-min-sequence
	@test "$(CONTAINER)" = podman || { echo "release-gates: reads the podman manifest lists of make images; CONTAINER=$(CONTAINER) is not supported yet (D-457)" >&2; exit 1; }
	@$(if $(or $(RELEASE_PREV_INDEX),$(filter-out file,$(origin MIN_SEQUENCE))),:,echo "release-gates: the release floor is the sequence of the published index: pass RELEASE_PREV_INDEX=<published index dir>, or MIN_SEQUENCE=0 for the very first release only" >&2; exit 1)
	@printf '%s' "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$$' || { echo "release-gates: VERSION must be SemVer without v (VERSION=1.0.0), got '$(VERSION)'" >&2; exit 1; }
	$(RELEASE_GO) gates -preflight $(RELEASE_GATES_ARGS)
	$(MAKE) --no-print-directory vuln-scan IMAGE_TAG='$(VERSION)' RELEASE=1 MIN_SEQUENCE='$(MIN_SEQUENCE)'
	$(MAKE) --no-print-directory sbom IMAGE_TAG='$(VERSION)' RELEASE=1 MIN_SEQUENCE='$(MIN_SEQUENCE)'
	$(MAKE) --no-print-directory notices-check MIN_SEQUENCE='$(MIN_SEQUENCE)'
	GOFLAGS= $(RELEASE_GO) gates $(RELEASE_GATES_ARGS) -platforms '$(PLATFORMS)' -deb-dir '$(DEB_OUT)' -out $(RELEASE_OUT)

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

# The container-only install (WP-08m, D-168) the way docs/INSTALL-CONTAINER.md tells a customer, on Docker and on Podman: builds the three images
# locally, checks by effect (ports, key owner and mode, uid and capabilities), tears down. Slow, opt-in, not in check or CI. Run it as
# `~/vedette-wt/heavy make container-only-smoke`; SMOKE_RUNTIMES="docker" or "podman" picks one. The scan pack folder is a build output: removed after.
.PHONY: container-only-smoke
container-only-smoke:
	scripts/dev/container-only-smoke.sh; rc=$$?; rm -rf $(PACK_DIR); exit $$rc

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
# build the images and push them by digest (release-push, then release-in writes release.in.json; D-457); build the .deb with `make host-deb VERSION=<version> RELEASE_PREV_INDEX=<published index dir>` (that
# index's sequence becomes the host's floor; MIN_SEQUENCE=0 only for the very first release) -> write release.in.json (leave released_at empty: the builder fills it, and a time more than 10 minutes
# from the clock is refused; "install_modes": ["appliance", "container"], D-451) -> release-cosign-plan (prints the cosign commands; run them) -> release-manifest
# (release-manifest.json + index.json, unsigned) -> release-container-assets (the four container-only files, D-451) -> release-sign (active key; again with RELEASE_SLOT=backup for the offline key, indexes only; RELEASE_SLOT=rescue after a leak of the active key, docs/RELEASE_KEYS.md) ->
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
.PHONY: release-cosign-plan release-manifest release-container-assets release-refresh release-sign release-verify release-interop release-packs
RELEASE_OUT := dist/release
RELEASE_IN ?= release.in.json
RELEASE_PREV_INDEX ?=
RELEASE_REF ?=
RELEASE_BASELINE_REF ?=
RELEASE_KEYS ?=
RELEASE_SLOT ?= active
RELEASE_GO = go run ./scripts/release
RELEASE_KEYS_ARG = $(if $(RELEASE_KEYS),-keys-dir $(RELEASE_KEYS))

# WP-08k step 6 (D-457 part C): one cosign sign per image (index digest of RELEASE_IN, the files release-manifest reads), then one
# cosign attest --type cyclonedx per platform SBOM of `make sbom RELEASE=1 IMAGE_TAG=<version>` onto that platform's digest in images.json
# (each SBOM's trivy ImageID must be the config digest images.json records for that platform: the image that was pushed). Printed with
# the pinned cosign (COSIGN_BIN: an absolute path), never run; the first line is `cd` to the repo. The attest lines upload to ghcr with
# the registry login cosign reads (docker config, or REGISTRY_AUTH_FILE=<podman auth.json>).
release-cosign-plan:
	@test -n "$$COSIGN_KEY" || { echo "release-cosign-plan: set COSIGN_KEY to the path of the cosign private key" >&2; exit 1; }
	@$(RELEASE_GO) cosign-plan -in $(RELEASE_IN) -images $(RELEASE_OUT)/images.json -sbom dist/sbom -key "$$COSIGN_KEY" -out $(RELEASE_OUT)/cosign -cosign "$${COSIGN_BIN:-$$(scripts/release/cosign.sh)}"

release-manifest: check-min-sequence
	$(RELEASE_GO) manifest -in $(RELEASE_IN) -cosign-dir $(RELEASE_OUT)/cosign -out $(RELEASE_OUT) $(if $(RELEASE_PREV_INDEX),-prev-index $(RELEASE_PREV_INDEX)) $(if $(RELEASE_REF),-ref $(RELEASE_REF)) $(if $(RELEASE_BASELINE_REF),-baseline-ref $(RELEASE_BASELINE_REF)) $(RELEASE_KEYS_ARG)
	$(RELEASE_GO) index -out $(RELEASE_OUT) -manifest $(RELEASE_OUT)/release-manifest.json $(if $(RELEASE_PREV_INDEX),-prev-index $(RELEASE_PREV_INDEX) -min-sequence $(MIN_SEQUENCE)) $(RELEASE_KEYS_ARG)

# D-451: read from git at the release tag (RELEASE_REF, default v<version>), like the migrations of release-manifest.
release-container-assets:
	$(RELEASE_GO) container-assets -in $(RELEASE_IN) -out $(RELEASE_OUT) $(if $(RELEASE_REF),-ref $(RELEASE_REF))

release-refresh:
	$(RELEASE_GO) index -out $(RELEASE_OUT) -prev-index "$(RELEASE_PREV_INDEX)" $(RELEASE_KEYS_ARG)

release-sign:
	@test -n "$$MINISIGN_KEY" || { echo "release-sign: set MINISIGN_KEY to the path of the minisign secret key (outside the repo)" >&2; exit 1; }
	$(RELEASE_GO) sign -dir $(RELEASE_OUT) -key "$$MINISIGN_KEY" -minisign "$${MINISIGN_BIN:-$$(scripts/release/minisign.sh)}" -slot $(RELEASE_SLOT) $(if $(filter rescue,$(RELEASE_SLOT)),-prev-index "$(RELEASE_PREV_INDEX)" $(RELEASE_KEYS_ARG)) $(if $(PASSPHRASE_STDIN),-passphrase-stdin)

# A failed verify leaves dist/release for inspection; a good one removes it unless RELEASE=1 (rules/build-artifacts.md).
release-verify:
	$(RELEASE_GO) verify -dir $(RELEASE_OUT) $(if $(RELEASE_PREV_INDEX),-prev-index $(RELEASE_PREV_INDEX)) $(RELEASE_KEYS_ARG)
	@if [ "$(RELEASE)" != 1 ]; then rm -rf $(RELEASE_OUT); rmdir dist 2>/dev/null || true; fi

# The release job's network steps (WP-08k, D-457; order and owners in docs/plans/2026-11-12-wp08k-release-job.md). Each refuses rather than guesses.
#   release-push      the four podman manifest lists of `make images IMAGE_TAG=<VERSION> IMAGE_VERSION=<VERSION>` to REGISTRY by digest (read back
#                     by digest, the version tag pushed too and checked; a version already there is reused only with the same images), then
#                     dist/release/images.json. Each platform image must carry the version label VERSION and be the one dist/release/gates.json
#                     of release-gates names (config digest), all four checked before anything is pushed. The real registry needs a clean tree at
#                     kien's tag v<VERSION> and no -test. version; REGISTRY=127.0.0.1:<port> is a rehearsal (no TLS, no git check; Linux only:
#                     podman machine on macOS cannot reach the Mac's 127.0.0.1); a rehearsal needs a gates.json too.
#   release-in        release.in.json from images.json and the two dist/vedette-host_<VERSION>_<arch>.deb; RELEASE_CHANNEL (stable|beta) and
#                     RELEASE_ROLLBACK_SAFE (true|false) are required, RELEASE_ROLLBACK_MIN / RELEASE_MIN_UPGRADE_FROM optional; add the notes by hand.
#                     Each .deb (sha256), each image of images.json and of the local lists (config digest) must be what gates.json names
#   release-publish   verifies dist/release again (install.sh too) and prints the gh release commands; PUBLISH=1 runs them (needs RELEASE_PREV_INDEX
#                     equal to the live index, or FIRST_RELEASE=1 before any index exists; signers must be the compiled-in production keys): draft
#                     v<version>, every asset, read back, anonymous pull of every image, publish, then index.json + .minisig to the release "index" LAST
.PHONY: release-push release-in release-publish
REGISTRY ?= ghcr.io/knt048
RELEASE_CHANNEL ?=
RELEASE_ROLLBACK_SAFE ?=
RELEASE_ROLLBACK_MIN ?=
RELEASE_MIN_UPGRADE_FROM ?=
PUBLISH ?=
FIRST_RELEASE ?=
release-push:
	@test "$(CONTAINER)" = podman || { echo "release-push: pushes the podman manifest lists of make images; CONTAINER=$(CONTAINER) is not supported yet (D-457)" >&2; exit 1; }
	$(RELEASE_GO) push -version '$(VERSION)' -registry '$(REGISTRY)' -platforms '$(PLATFORMS)' -out $(RELEASE_OUT)

release-in:
	$(RELEASE_GO) in -images $(RELEASE_OUT)/images.json -out $(RELEASE_IN) -deb-dir $(DEB_OUT) -channel '$(RELEASE_CHANNEL)' -rollback-safe '$(RELEASE_ROLLBACK_SAFE)' -rollback-min-version '$(RELEASE_ROLLBACK_MIN)' -min-upgrade-from '$(RELEASE_MIN_UPGRADE_FROM)'

release-publish:
	$(RELEASE_GO) publish -dir $(RELEASE_OUT) -in $(RELEASE_IN) $(if $(RELEASE_PREV_INDEX),-prev-index $(RELEASE_PREV_INDEX)) $(RELEASE_KEYS_ARG) $(if $(filter 1,$(FIRST_RELEASE)),-first-release) $(if $(filter 1,$(PUBLISH)),-run)

# Part A of the release job (D-457). release-deb-name: after both host-deb runs and before release-in, nfpm's prerelease name
# vedette-host_1.0.0~beta.1_<arch>.deb becomes the SemVer one (a plain 1.0.0 needs nothing; idempotent). release-bake-install: after
# release-container-assets, install.sh read from git at the tag (RELEASE_REF) with its three lines baked from release-manifest.json,
# signed with MINISIGN_KEY (the key that signs the manifest) into install.sh.minisig, "file:install.sh version:<v>", checked with the
# keys of RELEASE_KEYS or the compiled-in ones.
.PHONY: release-deb-name release-bake-install
release-deb-name:
	$(RELEASE_GO) deb-name -version '$(VERSION)' -dir $(DEB_OUT)

release-bake-install:
	@test -n "$$MINISIGN_KEY" || { echo "release-bake-install: set MINISIGN_KEY to the path of the minisign secret key (outside the repo)" >&2; exit 1; }
	$(RELEASE_GO) bake-install -dir $(RELEASE_OUT) -in $(RELEASE_IN) $(if $(RELEASE_REF),-ref $(RELEASE_REF)) -key "$$MINISIGN_KEY" -minisign "$${MINISIGN_BIN:-$$(scripts/release/minisign.sh)}" $(RELEASE_KEYS_ARG) $(if $(PASSPHRASE_STDIN),-passphrase-stdin)

# The confirmed mitigation packs that ship in the core image (D-345): signed before the image is built, on the maintainer's machine.
# PACKS_VERSION: dotted numbers newer than content/mitigation/packs/VERSION. The result (VERSION, packs.list, packs.minisig) is committed.
release-packs:
	@test -n "$$MINISIGN_KEY" || { echo "release-packs: set MINISIGN_KEY to the path of the minisign secret key (outside the repo)" >&2; exit 1; }
	@test -n "$(PACKS_VERSION)" || { echo "release-packs: set PACKS_VERSION (dotted numbers, such as 2026.12.2.1)" >&2; exit 1; }
	$(RELEASE_GO) packs -dir content/mitigation/packs -version "$(PACKS_VERSION)" -key "$$MINISIGN_KEY" -minisign "$${MINISIGN_BIN:-$$(scripts/release/minisign.sh)}" $(RELEASE_KEYS_ARG) $(if $(PASSPHRASE_STDIN),-passphrase-stdin)

# The builder and the verifier against the real, pinned minisign (fails when the tool is missing, unlike `go test`, which skips).
release-interop:
	scripts/release/minisign.sh > /dev/null
	VEDETTE_REQUIRE_MINISIGN=1 go test -count=1 -run 'Interop|Pin' ./scripts/release
