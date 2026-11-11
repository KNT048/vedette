#!/usr/bin/env bash
# The release key ceremony (D-256), on the maintainer's Mac. Makes the release signing keys the box trusts:
#   minisign         the active minisign key: signs index.json and every release manifest
#   minisign-backup  the offline backup minisign key: signs the index that revokes a key, and the rescue release after one (D-108, D-258)
#   cosign           the cosign key (ECDSA P-256): signs the images (legacy format, D-103)
# Usage: scripts/release/keygen.sh [name...]   (default: all three; a rotation passes only the key it replaces, after moving the old one away)
#
# For each key: a fresh random passphrase (256 bits, `openssl rand`) goes straight from a shell variable into the login Keychain
# (service vedette-release-<name>, account $USER) through `security -i` on stdin, so it is never an argument, never printed and never
# in a file. The item trusts no application (`-T ""`): every later read, by any program, raises a macOS dialog that needs the login
# password, so a process running as you cannot take the passphrase silently (click "Allow", never "Always Allow"); the script checks
# the item's access list says so (scripts/release/keychain-acl.sh) before it makes the key. The key is then
# made by the tools (minisign from your PATH, version-checked against deploy/tools.env, not hash-pinned on macOS; cosign hash-pinned
# by scripts/release/cosign.sh) and encrypted with that passphrase (minisign: scrypt; cosign: scrypt + secretbox; cosign gets it in
# COSIGN_PASSWORD, visible to your own processes while it runs). Files land in $VEDETTE_RELEASE_KEYS (default ~/.vedette-release-keys,
# mode 0700): <name>.key and <name>.pub (both 0600). Last, the passphrase is read back from the Keychain (one dialog per key), each key
# signs a throwaway file with it and the signature is verified with the public key, which proves the Keychain item, the private key
# and the public key belong together; the throwaway is removed.
# It refuses to overwrite: an existing key file or Keychain item stops it before anything is made. When it fails half-way it names
# what it left, which must be deleted before a rerun.
# stdout: the public keys and their ids (public data). Nothing secret is ever written to stdout or stderr.
set -euo pipefail
umask 077
cd "$(dirname "$0")/../.."

[ "$(uname -s)" = Darwin ] || { echo "keygen.sh: the passphrases go into the macOS Keychain; run this on the maintainer's Mac" >&2; exit 1; }
set -a
# shellcheck disable=SC1091
. deploy/tools.env
set +a
command -v minisign > /dev/null || { echo "keygen.sh: install minisign $MINISIGN_VERSION first (brew install minisign)" >&2; exit 1; }
[ "$(minisign -v)" = "minisign $MINISIGN_VERSION" ] || { echo "keygen.sh: minisign is not $MINISIGN_VERSION, the version deploy/tools.env pins" >&2; exit 1; }
cosign=$(scripts/release/cosign.sh)

dir=${VEDETTE_RELEASE_KEYS:-$HOME/.vedette-release-keys}
account=${USER:?}
names=("$@")
[ ${#names[@]} -gt 0 ] || names=(minisign minisign-backup cosign)
for n in "${names[@]}"; do
	case $n in
		minisign | minisign-backup | cosign) ;;
		*) echo "keygen.sh: unknown key $n (minisign, minisign-backup, cosign)" >&2; exit 1 ;;
	esac
	if [ -e "$dir/$n.key" ] || [ -e "$dir/$n.pub" ]; then
		echo "keygen.sh: $dir/$n.key or .pub exists; refusing to overwrite a release key" >&2
		exit 1
	fi
	if security find-generic-password -s "vedette-release-$n" -a "$account" > /dev/null 2>&1; then
		echo "keygen.sh: the Keychain already holds vedette-release-$n; refusing to overwrite its passphrase" >&2
		exit 1
	fi
done
mkdir -p "$dir"
chmod 0700 "$dir"
work=$(mktemp -d "$dir/selftest.XXXXXX")
current=
cleanup() {
	local rc=$?
	rm -rf "$work"
	if [ $rc -ne 0 ] && [ -n "$current" ]; then
		echo "keygen.sh: failed while making $current; it is not usable. Before a rerun delete $dir/$current.key, $dir/$current.pub" \
			"and the Keychain item (security delete-generic-password -s vedette-release-$current -a $account)" >&2
	fi
}
trap cleanup EXIT
echo "throwaway file of the Vedette release key self-test" > "$work/blob"

passphrase() { security find-generic-password -s "vedette-release-$1" -a "$account" -w; }

for n in "${names[@]}"; do
	current=$n
	echo "keygen.sh: making $n" >&2
	pass=$(openssl rand -hex 32)
	[ ${#pass} -eq 64 ] || { echo "keygen.sh: openssl did not give a passphrase" >&2; exit 1; }
	# security -i reads the command from stdin: the passphrase is never in argv (ps) or shell history
	printf 'add-generic-password -s vedette-release-%s -a %s -l "Vedette release key passphrase (%s)" -T "" -w %s\n' "$n" "$account" "$n" "$pass" | security -i > /dev/null
	kc=$(security find-generic-password -s "vedette-release-$n" -a "$account" 2> /dev/null | sed -n 's/^keychain: "\(.*\)"$/\1/p')
	[ -n "$kc" ] || { echo "keygen.sh: the Keychain did not keep vedette-release-$n" >&2; exit 1; }
	# -T "" must leave the item trusting no application; a security(1) that ignored it would let any process read it silently (D-259).
	# dump-keychain -a prints access lists only (no -d: no secret); keychain-acl.sh fails closed on anything but an empty app list.
	security dump-keychain -a "$kc" | scripts/release/keychain-acl.sh "vedette-release-$n" "$account" \
		|| { echo "keygen.sh: vedette-release-$n does not have an empty application list (-T \"\" was not kept)" >&2; exit 1; }
	case $n in
		minisign*)
			label=active
			[ "$n" = minisign-backup ] && label="offline backup"
			printf '%s\n%s\n' "$pass" "$pass" | minisign -G -s "$dir/$n.key" -p "$dir/$n.pub" -c "Vedette release minisign key ($label)" > /dev/null 2>&1
			;;
		cosign)
			COSIGN_PASSWORD=$pass "$cosign" generate-key-pair --output-key-prefix "$dir/cosign" > /dev/null 2>&1
			;;
	esac
	[ -s "$dir/$n.key" ] && [ -s "$dir/$n.pub" ] || { echo "keygen.sh: $n was not written" >&2; exit 1; }
	chmod 0600 "$dir/$n.key"
	chmod 0600 "$dir/$n.pub"

	# self-test with the passphrase read back from the Keychain (one dialog)
	echo "keygen.sh: macOS asks to let security read vedette-release-$n: click Allow (not Always Allow)" >&2
	back=$(passphrase "$n")
	[ "$back" = "$pass" ] || { echo "keygen.sh: the Keychain did not keep the passphrase of $n" >&2; exit 1; }
	unset pass
	case $n in
		minisign*)
			printf '%s\n' "$back" | minisign -S -s "$dir/$n.key" -m "$work/blob" -x "$work/$n.minisig" -t "self-test" > /dev/null 2>&1
			minisign -V -q -m "$work/blob" -x "$work/$n.minisig" -p "$dir/$n.pub" > /dev/null
			;;
		cosign)
			COSIGN_PASSWORD=$back "$cosign" sign-blob --yes --key "$dir/cosign.key" --tlog-upload=false \
				--output-signature "$work/cosign.sig" "$work/blob" > /dev/null 2>&1
			"$cosign" verify-blob --key "$dir/cosign.pub" --signature "$work/cosign.sig" --insecure-ignore-tlog=true "$work/blob" > /dev/null 2>&1
			;;
	esac
	unset back
	echo "keygen.sh: $n signs and verifies" >&2
done
current=

for n in "${names[@]}"; do
	echo "== $n.pub"
	cat "$dir/$n.pub"
done
