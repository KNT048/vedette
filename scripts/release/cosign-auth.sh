#!/usr/bin/env bash
# Runs a command (the printed cosign plan) with podman's registry login as cosign's login (WP-08k step 7, D-457 part C).
# Why: cosign reads registry credentials the way Docker does, from $DOCKER_CONFIG/config.json or ~/.docker/config.json, and falls back
# to podman's auth.json only when neither exists. A ~/.docker/config.json without ghcr.io (Docker Desktop, podman's Docker compatibility)
# hides the `podman login ghcr.io` of the release, and the attest uploads are refused (seen releasing v0.1.0-beta.1). This points
# DOCKER_CONFIG at a private temporary folder whose config.json is a symlink to podman's auth file (same JSON format), runs the command
# and removes the folder. The credentials are never copied, printed or put in argv.
#   COSIGN_PASSWORD=… scripts/release/cosign-auth.sh sh -eu dist/cosign-plan.sh
# podman's auth file (containers-auth.json(5)): $REGISTRY_AUTH_FILE, else $XDG_RUNTIME_DIR/containers/auth.json when it exists (Linux),
# else ~/.config/containers/auth.json (macOS). Refuses when it holds no ghcr.io login. Needs jq, mktemp. Linux or macOS.
set -euo pipefail
fail() {
	echo "cosign-auth: $*" >&2
	exit 1
}
[ $# -gt 0 ] || fail "usage: cosign-auth.sh COMMAND [ARGS...] (for example: sh -eu dist/cosign-plan.sh)"
for t in jq mktemp; do command -v "$t" >/dev/null || fail "needs $t (macOS: brew install $t; Debian/Ubuntu: apt-get install $t)"; done
if [ -n "${REGISTRY_AUTH_FILE:-}" ]; then
	auth=$REGISTRY_AUTH_FILE
elif [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -f "$XDG_RUNTIME_DIR/containers/auth.json" ]; then
	auth=$XDG_RUNTIME_DIR/containers/auth.json
else
	auth=$HOME/.config/containers/auth.json
fi
case $auth in /*) ;; *) auth=$PWD/$auth ;; esac
[ -f "$auth" ] || fail "no podman login file at $auth: run podman login ghcr.io first"
# read here, not with `podman login --get-login`: on macOS that needs the podman machine running, cosign does not
jq -e '(.auths // {})["ghcr.io"] or (.credHelpers // {})["ghcr.io"]' "$auth" >/dev/null 2>&1 || fail "no ghcr.io login in $auth: run podman login ghcr.io first"

dir=$(mktemp -d) # 0700, removed on exit
trap 'rm -rf "$dir"' EXIT
ln -s "$auth" "$dir/config.json"
rc=0
DOCKER_CONFIG=$dir "$@" || rc=$?
exit "$rc"
