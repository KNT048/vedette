#!/usr/bin/env bash
# Checks that a Keychain item trusts no application (D-256, D-259): reads `security dump-keychain -a <keychain>` on stdin (access
# lists only; without -d no secret is in it) and exits 0 only when the generic password of service $1 and account $2 is there once,
# has at least one access entry that can read the secret, and every entry whose authorizations go beyond encrypt, change_acl,
# partition_id and integrity (so decrypt, export_clear, any, ...) has exactly one applications line, "applications (0):". Anything
# else fails closed: "applications: <null>" (every application), a listed application, a missing line, a missing or doubled item.
# Usage: security dump-keychain -a "$keychain" | scripts/release/keychain-acl.sh <service> <account>
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: keychain-acl.sh <service> <account>" >&2; exit 2; }
LC_ALL=C awk -v svc="$1" -v acct="$2" '
function endentry() {
	if (inentry && reader) {
		readers++
		if (apps != 1 || !appsok) bad = bad " [" auth ": " (apps == 1 ? appsline : apps " applications lines") "]"
	}
	inentry = 0; reader = 0; apps = 0; appsok = 0
}
function endrecord() {
	endentry()
	if (insvc && inacct) {
		found++
		if (readers == 0) bad = bad " [no entry that reads the secret]"
		itembad = itembad bad
	}
	insvc = 0; inacct = 0; readers = 0; bad = ""
}
/^keychain: / { endrecord(); next }
$0 == "    \"svce\"<blob>=\"" svc "\"" { insvc = 1; next }
$0 == "    \"acct\"<blob>=\"" acct "\"" { inacct = 1; next }
/^    entry [0-9]+:$/ { endentry(); inentry = 1; next }
/^        authorizations / {
	auth = $0; sub(/^ *authorizations \([0-9]+\): */, "", auth)
	n = split(auth, a, " ")
	for (i = 1; i <= n; i++) if (a[i] != "encrypt" && a[i] != "change_acl" && a[i] != "partition_id" && a[i] != "integrity") reader = 1
	if (n == 0) reader = 1
	next
}
/^        applications/ { apps++; appsline = $0; sub(/^ */, "", appsline); appsok = (appsline == "applications (0):"); next }
END {
	endrecord()
	if (found != 1) { printf "keychain-acl.sh: found %d items %s/%s, want 1\n", found, svc, acct > "/dev/stderr"; exit 1 }
	if (itembad != "") { printf "keychain-acl.sh: %s may be read by applications:%s\n", svc, itembad > "/dev/stderr"; exit 1 }
}'
