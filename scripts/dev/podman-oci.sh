# shellcheck shell=bash
# Sourced by supply-chain.sh and install-artifacts.sh (not run on its own): podman_oci_push, a `podman manifest push` or `podman push` to
# an OCI layout folder on THIS machine.
# Why: on macOS podman is a remote client of a `podman machine` VM, and the server writes an oci:<dir> destination inside the VM, not on
# the Mac (the v0.1.0-beta.1 release needed a PATH shim around podman for it). There
# the same command runs inside the VM with `podman machine ssh`, on the same absolute path: the machine mounts $HOME (and /private,
# /var/folders) at the same path (podman's default volumes on macOS), so the layout lands in this checkout. Measured with podman 6.2 and
# a two-platform list: the plain push fails (exit 125), this one writes the index of both platforms here. A local podman (Linux) runs
# the command unchanged.
# Needs: podman (and, for a remote one, a podman machine that is running and mounts the destination's folder).

# podman_oci_push PODMAN ARGS... — ARGS is the push command (manifest push … / push …) with exactly one oci:<dir> argument (relative to
# $PWD or absolute). Returns non-zero, with the reason on stderr, when the push fails or no layout appeared at <dir>.
podman_oci_push() {
	local c=$1 a dest='' remote
	shift
	local args=()
	for a in "$@"; do
		case $a in
		oci:/*) dest=${a#oci:} ;;
		oci:*) dest=$PWD/${a#oci:} ;;
		*) args+=("$a") && continue ;;
		esac
		args+=("oci:$dest")
	done
	[ -n "$dest" ] || { echo "podman_oci_push: no oci:<dir> argument" >&2; return 2; }
	remote=$("$c" info --format '{{.Host.ServiceIsRemote}}') || { echo "podman_oci_push: '$c info' failed (on macOS: podman machine start)" >&2; return 1; }
	if [ "$remote" != true ]; then
		"$c" "${args[@]}" || return
	else
		mkdir -p "$(dirname "$dest")"
		# ssh joins its arguments into one command line for the VM's shell: quote each one for that shell (bash, %q)
		"$c" machine ssh -- "test -d $(printf '%q' "$(dirname "$dest")")" || {
			echo "podman_oci_push: $(dirname "$dest") is not visible inside the podman machine (it mounts \$HOME at the same path by default): run from a checkout under \$HOME" >&2
			return 1
		}
		"$c" machine ssh -- "$(printf '%q ' podman "${args[@]}")" || return
	fi
	[ -f "$dest/index.json" ] || { echo "podman_oci_push: the push succeeded but $dest/index.json is not on this machine" >&2; return 1; }
}
