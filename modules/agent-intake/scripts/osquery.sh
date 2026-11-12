#!/bin/sh
# Vedette osquery installer for Linux (Debian/Ubuntu and RHEL/Rocky/Alma). Served by your Vedette box: @@BOX@@
# Run as root. Safe to run again: it upgrades or repairs. Remove everything with: --uninstall
# What it does, in order:
#   1. writes the Vedette box CA certificate (embedded below) to /etc/osquery/vedette-ca.pem
#   2. downloads osquery @@VERSION@@ and SHA256SUMS from the box (the box mirrors the official osquery release; servers need no Internet),
#      checks the SHA-256 of the package, installs it with dpkg or rpm
#   3. writes the enroll secret (mode 600) and /etc/osquery/osquery.flags
#   4. enables and starts the osqueryd service, then waits until this machine has enrolled (not for its first report, due within about an hour) and exits 0
set -eu
BOX='@@BOX@@'
OSQ_VERSION='@@VERSION@@'
TOKEN=''
ACTION=install
while [ $# -gt 0 ]; do
  case "$1" in
    --token) TOKEN="$2"; shift 2 ;;
    --uninstall) ACTION=uninstall; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "Run as root (for example: sudo sh $0 ...)." >&2; exit 1; }
DIR=/etc/osquery
CA=$DIR/vedette-ca.pem

if [ "$ACTION" = uninstall ]; then
  systemctl disable --now osqueryd 2>/dev/null || true
  if command -v dpkg >/dev/null 2>&1; then dpkg -r osquery 2>/dev/null || true; else rpm -e osquery 2>/dev/null || true; fi
  rm -f "$DIR/osquery.flags" "$DIR/enroll.secret" "$CA"
  echo "osquery and the Vedette settings were removed from this machine."
  exit 0
fi

[ -n "$TOKEN" ] || { echo "Missing --token. Copy the install command from Vedette, Devices, Scope and sensors." >&2; exit 2; }
ARCH=$(uname -m)
[ "$ARCH" = x86_64 ] || { echo "Only x86_64 servers are supported for now (this one is $ARCH)." >&2; exit 1; }
# os-release is read in subshells: sourced here it would overwrite this script's own variables (VERSION, NAME, ...)
OSF=/etc/os-release; [ -r "$OSF" ] || OSF=/usr/lib/os-release
OS_IDS=$( . "$OSF" 2>/dev/null; printf ' %s %s ' "${ID:-}" "${ID_LIKE:-}" ) || OS_IDS=
OS_NAME=$( . "$OSF" 2>/dev/null; printf '%s' "${PRETTY_NAME:-unknown}" ) || OS_NAME=unknown
case "$OS_IDS" in
  *" debian "*|*" ubuntu "*) FMT=deb; FILE="osquery_${OSQ_VERSION}-1.linux_amd64.deb" ;;
  *" rhel "*|*" centos "*|*" fedora "*|*" rocky "*|*" almalinux "*) FMT=rpm; FILE="osquery-${OSQ_VERSION}-1.linux.x86_64.rpm" ;;
  *) echo "Unsupported Linux distribution: ${OS_NAME}. Supported: Debian, Ubuntu, RHEL, Rocky, AlmaLinux." >&2; exit 1 ;;
esac

mkdir -p "$DIR"
cat > "$CA" <<'VEDETTE_CA'
@@CA@@
VEDETTE_CA
chmod 644 "$CA"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -fsS --cacert "$CA" "$BOX/api/v1/install/osquery/SHA256SUMS" -o "$TMP/SHA256SUMS"
curl -fsS --cacert "$CA" "$BOX/api/v1/install/osquery/$FILE" -o "$TMP/$FILE"
( cd "$TMP" && grep " $FILE\$" SHA256SUMS | sha256sum -c - ) || { echo "Checksum of $FILE does not match. Nothing was installed." >&2; exit 1; }
if [ "$FMT" = deb ]; then dpkg -i "$TMP/$FILE"; else rpm -Uvh --replacepkgs "$TMP/$FILE"; fi

( umask 077; printf '%s' "$TOKEN" > "$DIR/enroll.secret" )
[ -f "$DIR/osquery.conf" ] || echo '{}' > "$DIR/osquery.conf"
HOSTPORT=${BOX#https://}
cat > "$DIR/osquery.flags" <<FLAGS
--config_plugin=tls
--logger_plugin=tls
--host_identifier=hostname
--enroll_secret_path=$DIR/enroll.secret
--tls_server_certs=$CA
--tls_hostname=$HOSTPORT
--enroll_tls_endpoint=/api/v1/intake/osquery/enroll
--config_tls_endpoint=/api/v1/intake/osquery/config
--logger_tls_endpoint=/api/v1/intake/osquery/log
FLAGS
# status answers {"enrolled":..,"hosts":N}: hosts counts the machines that enrolled with this token. Success = this machine enrolled (hosts
# grew past what it was before the restart, or the first report is already in); the first report itself comes later and is not waited for.
vstatus() { curl -fsS --cacert "$CA" -X POST -H "Authorization: Bearer $TOKEN" "$BOX/api/v1/intake/osquery/status" 2>/dev/null || true; }
BASE=$(vstatus | sed -n 's/.*"hosts":\([0-9][0-9]*\).*/\1/p'); BASE=${BASE:-0}
systemctl enable osqueryd
systemctl restart osqueryd

echo "Waiting for this machine to enrol with Vedette (up to 2 minutes)..."
i=0
while [ $i -lt 24 ]; do
  ST=$(vstatus)
  NOW=$(printf '%s' "$ST" | sed -n 's/.*"hosts":\([0-9][0-9]*\).*/\1/p'); NOW=${NOW:-0}
  if [ "$NOW" -gt "$BASE" ] || printf '%s' "$ST" | grep -q '"enrolled":true'; then
    echo "Installed and enrolled; the first report arrives within about an hour."; exit 0
  fi
  i=$((i+1)); sleep 5
done
echo "osquery is installed, but this machine did not enrol with Vedette within 2 minutes. Check that the box address is reachable from here and the token is still valid, then: systemctl status osqueryd" >&2
exit 3
