#!/bin/sh
# Vedette osquery installer for Linux (any glibc distribution with dpkg or rpm: Debian, Ubuntu, RHEL, Rocky, Alma, Fedora, Amazon Linux, SUSE; x86_64 or arm64). Served by your Vedette box: @@BOX@@
# Run as root. Safe to run again: it upgrades or repairs. Remove everything with: --uninstall
# What it does, in order:
#   1. writes the Vedette box CA certificate (embedded below) to /etc/osquery/vedette-ca.pem
#   2. downloads osquery @@VERSION@@ and SHA256SUMS from the box (the box mirrors the official osquery release; servers need no Internet),
#      checks the SHA-256 of the package, installs it with dpkg or rpm (chosen by what this machine has, not by its name)
#   3. writes the enroll secret (mode 600) and /etc/osquery/osquery.flags; with a token this machine does not hold yet, it first removes
#      osquery's database (/var/osquery/osquery.db: the old node key and unsent results) so that the machine enrols under the new token
#   4. enables and starts the osqueryd service (systemd, else the SysV init script), then waits until this machine has enrolled (not for its first report, due within a few minutes) and exits 0
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
DB=/var/osquery/osquery.db # osqueryd's default --database_path: its node key and its unsent results

# Service manager, by capability: systemd only when it is the running init (not merely installed), else the SysV init script that both
# osquery packages ship (/etc/init.d/osqueryd, run directly: Rocky and others have no 'service' command). That script needs ps and
# pkill (checked on debian:12 and rockylinux:9 with the real packages: status exits 0 while running and 7 when stopped, stop exits 0
# when not running; without procps its stop hangs), so SysV is used only where both exist.
SYSV=/etc/init.d/osqueryd
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then INIT=systemd
elif [ -d /etc/init.d ] && command -v ps >/dev/null 2>&1 && command -v pkill >/dev/null 2>&1; then INIT=sysv
else INIT=none; fi
svc_known() { if [ "$INIT" = systemd ]; then systemctl cat osqueryd >/dev/null 2>&1; else [ -x "$SYSV" ]; fi; }
# Stopping something that is not running is not a failure (set -e): a SysV stop may exit non-zero then; it fails only if osqueryd still runs.
svc_stop() { if [ "$INIT" = systemd ]; then systemctl stop osqueryd; else "$SYSV" stop >/dev/null 2>&1 || ! svc_active; fi; }
svc_disable_stop() {
  if [ "$INIT" = systemd ]; then systemctl disable --now osqueryd 2>/dev/null || true
  else
    "$SYSV" stop >/dev/null 2>&1 || true
    if command -v update-rc.d >/dev/null 2>&1; then update-rc.d -f osqueryd remove >/dev/null 2>&1 || true
    elif command -v chkconfig >/dev/null 2>&1; then chkconfig osqueryd off >/dev/null 2>&1 || true; fi
  fi
}
svc_enable_restart() {
  if [ "$INIT" = systemd ]; then systemctl enable --quiet osqueryd; systemctl restart osqueryd; return; fi
  if command -v update-rc.d >/dev/null 2>&1; then update-rc.d osqueryd defaults >/dev/null 2>&1 || true
  elif command -v chkconfig >/dev/null 2>&1; then chkconfig osqueryd on >/dev/null 2>&1 || true; fi
  "$SYSV" restart >/dev/null 2>&1
}
svc_active() { if [ "$INIT" = systemd ]; then systemctl is-active --quiet osqueryd; else "$SYSV" status >/dev/null 2>&1; fi; }

if [ "$ACTION" = uninstall ]; then
  [ "$INIT" = none ] || svc_disable_stop
  if command -v dpkg >/dev/null 2>&1 && dpkg -s osquery >/dev/null 2>&1; then dpkg -r osquery 2>/dev/null || true
  elif command -v rpm >/dev/null 2>&1; then rpm -e osquery 2>/dev/null || true; fi
  rm -f "$DIR/osquery.flags" "$DIR/enroll.secret" "$CA"
  rm -rf "$DB"
  echo "osquery and the Vedette settings were removed from this machine."
  exit 0
fi

[ -n "$TOKEN" ] || { echo "Missing --token. Copy the install command from Vedette, Devices, Scope and sensors." >&2; exit 2; }
# The package must match the userland, not the kernel: a 32-bit system on a 64-bit kernel (Raspberry Pi OS armhf) says aarch64 in uname -m.
ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
case "$ARCH" in
  x86_64|amd64) DEB_ARCH=amd64; RPM_ARCH=x86_64; GLIBC_LOADER=/lib64/ld-linux-x86-64.so.2 ;;
  aarch64|arm64) DEB_ARCH=arm64; RPM_ARCH=aarch64; GLIBC_LOADER=/lib/ld-linux-aarch64.so.1 ;;
  *) echo "osquery from this box runs on x86_64 and arm64 (aarch64) servers only; this one is $ARCH." >&2; exit 1 ;;
esac
# os-release is read in subshells: sourced here it would overwrite this script's own variables (VERSION, NAME, ...). It only names the
# system in messages; what to do is decided by what the machine has.
OSF=/etc/os-release; [ -r "$OSF" ] || OSF=/usr/lib/os-release
# shellcheck disable=SC1090 # the file is os-release, read on purpose
OS_NAME=$( . "$OSF" 2>/dev/null; printf '%s' "${PRETTY_NAME:-unknown}" ) || OS_NAME=unknown
# osquery's official Linux builds are dynamically linked against glibc (they do not run on musl systems such as Alpine, with or without gcompat).
[ -e "$GLIBC_LOADER" ] || { echo "Cannot install osquery on ${OS_NAME}: its official build needs glibc ($GLIBC_LOADER is missing; this looks like a musl system such as Alpine)." >&2; exit 1; }
if command -v dpkg >/dev/null 2>&1 && [ -e /var/lib/dpkg/status ]; then FMT=deb; FILE="osquery_${OSQ_VERSION}-1.linux_${DEB_ARCH}.deb"
elif command -v rpm >/dev/null 2>&1; then FMT=rpm; FILE="osquery-${OSQ_VERSION}-1.linux.${RPM_ARCH}.rpm"
else echo "Cannot install osquery on ${OS_NAME}: neither dpkg nor rpm is present, and the osquery package of this box is a .deb or .rpm." >&2; exit 1; fi
[ "$INIT" != none ] || { echo "Cannot install osquery on ${OS_NAME}: no service manager found (systemd, or SysV init scripts with ps and pkill installed)." >&2; exit 1; }
for NEED in curl sha256sum mktemp; do
  command -v "$NEED" >/dev/null 2>&1 || { echo "Cannot install osquery on ${OS_NAME}: '$NEED' is required and is not installed." >&2; exit 1; }
done

# The name this machine enrols under is chosen here (--host_identifier=specified), so the status check below asks for exactly that name;
# osquery's own hostname lookup can be the short or the full name depending on the machine.
HOSTID=$(uname -n | tr -cd 'A-Za-z0-9._-')
[ -n "$HOSTID" ] || { echo "Cannot read this machine's host name (uname -n)." >&2; exit 1; }

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
# The package manager's output (and whatever osquery's own package scripts print, such as a bare line of numbers) goes to a log shown
# only when the install fails, so a normal run prints Vedette's lines only.
echo "Installing osquery $OSQ_VERSION..."
if [ "$FMT" = deb ]; then set -- dpkg -i "$TMP/$FILE"; else set -- rpm -Uvh --replacepkgs "$TMP/$FILE"; fi
"$@" >"$TMP/install.log" 2>&1 || { cat "$TMP/install.log" >&2; echo "Installing $FILE failed (output above)." >&2; exit 1; }

# osqueryd keeps the node key of its enrolment in its database and does not enrol again while the box accepts that key. Unless this
# machine already holds this very token (a repair keeps its key), its database is removed so that it enrols under this token.
if [ "$(cat "$DIR/enroll.secret" 2>/dev/null || true)" != "$TOKEN" ]; then
  [ ! -s "$DIR/enroll.secret" ] || echo "This machine was enrolled with another token; it enrols again under this one. The old token lists it until it has been silent for 90 days or you revoke that token in Vedette."
  # stopped whenever the unit exists (also while it is activating or restarting); a failed stop ends the script: a running osqueryd keeps its key
  if svc_known; then svc_stop || { echo "osqueryd is still running and could not be stopped; stop it and run this command again." >&2; exit 1; }; fi
  rm -rf "$DB"
fi
( umask 077; printf '%s' "$TOKEN" > "$DIR/enroll.secret" )
[ -f "$DIR/osquery.conf" ] || echo '{}' > "$DIR/osquery.conf"
HOSTPORT=${BOX#https://}
cat > "$DIR/osquery.flags" <<FLAGS
--config_plugin=tls
--logger_plugin=tls
--host_identifier=specified
--specified_identifier=$HOSTID
--enroll_secret_path=$DIR/enroll.secret
--tls_server_certs=$CA
--tls_hostname=$HOSTPORT
--enroll_tls_endpoint=/api/v1/intake/osquery/enroll
--config_tls_endpoint=/api/v1/intake/osquery/config
--config_refresh=300
--logger_tls_endpoint=/api/v1/intake/osquery/log
FLAGS
# status answers for THIS machine: sent its name (the host_identifier set above), it returns host_last_seen, when
# the box last heard from a machine of this token with that name (null = none yet). Success = osqueryd runs and that value appeared or moved
# since before the restart; the first report itself comes later and is not waited for. Other machines of the token do not count.
vstatus() { curl -fsS --cacert "$CA" -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"host_identifier\":\"$HOSTID\"}" "$BOX/api/v1/intake/osquery/status" 2>/dev/null || true; }
seen_of() { sed -n 's/.*"host_last_seen":"\([^"]*\)".*/\1/p'; }
BASE=$(vstatus | seen_of)
svc_enable_restart

echo "Waiting for this machine to enrol with Vedette (up to 2 minutes)..."
i=0
while [ $i -lt 24 ]; do
  NOW=$(vstatus | seen_of)
  if [ -n "$HOSTID" ] && [ -n "$NOW" ] && [ "$NOW" != "$BASE" ] && svc_active; then
    echo "Installed and enrolled; this machine's operating system and packages appear in Vedette within a few minutes."; exit 0
  fi
  i=$((i+1)); sleep 5
done
if [ "$INIT" = systemd ]; then STATUS_CMD='systemctl status osqueryd'; else STATUS_CMD="$SYSV status"; fi
echo "osquery is installed, but this machine did not enrol with Vedette within 2 minutes. Check that the box address is reachable from here and the token is still valid, then: ${STATUS_CMD}" >&2
exit 3
