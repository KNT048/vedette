#!/usr/bin/env bash
# Checks that a Keychain item trusts no application (D-256, D-259): reads `security dump-keychain -a <keychain>` on stdin (access
# lists only; without -d no secret is in it) and exits 0 only when the generic password of service $1 and account $2 is there and
# every access entry that can read the secret (authorizations decrypt or export_clear) lists "applications (0):". Anything else
# fails closed: "applications: <null>" (every application), a listed application, a missing item, or a format it does not know.
# Usage: security dump-keychain -a "$keychain" | scripts/release/keychain-acl.sh <service> <account>
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: keychain-acl.sh <service> <account>" >&2; exit 2; }
LC_ALL=C awk -v svc="$1" -v acct="$2" '
function flush() {
	if (insvc && inacct) {
		found++
		if (readers == 0) bad = bad " no-reader-entry"
	}
	insvc = 0; inacct = 0; readers = 0; reader = 0
}
/^keychain: / { flush(); next }
$0 == "    \"svce\"<blob>=\"" svc "\"" { insvc = 1; next }
$0 == "    \"acct\"<blob>=\"" acct "\"" { inacct = 1; next }
/^        authorizations / { reader = ($0 ~ / decrypt( |$)/ || $0 ~ / export_clear( |$)/); if (reader) readers++; next }
/^        applications/ {
	if (reader && insvc && inacct && $0 != "        applications (0):") bad = bad " " $0
	next
}
END {
	flush()
	if (found != 1) { printf "keychain-acl.sh: found %d items %s/%s, want 1\n", found, svc, acct > "/dev/stderr"; exit 1 }
	if (bad != "") { printf "keychain-acl.sh: %s trusts applications:%s\n", svc, bad > "/dev/stderr"; exit 1 }
}'
