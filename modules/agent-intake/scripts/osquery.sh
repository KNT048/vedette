#!/bin/sh
# Vedette installer for Linux (one command for every common distribution). Served by your Vedette box: @@BOX@@
# Where osquery runs (glibc with dpkg or rpm: Debian, Ubuntu, RHEL, Rocky, Alma, Fedora, Amazon Linux, SUSE; x86_64 or arm64) it installs osquery.
# Where it cannot (Alpine and other musl systems, Arch, other architectures) it installs a small package reporter instead: a shell script that
# enrols with the same token and sends the installed packages (apk, pacman, dpkg or rpm) and the operating system to the same box endpoints.
# Run as root. Safe to run again: it upgrades or repairs. Remove everything with: --uninstall
# What the osquery path does, in order:
#   1. writes the Vedette box CA certificate (embedded below) to /etc/osquery/vedette-ca.pem
#   2. downloads osquery @@VERSION@@ and SHA256SUMS from the box (the box mirrors the official osquery release; servers need no Internet),
#      checks the SHA-256 of the package, installs it with dpkg or rpm (chosen by what this machine has, not by its name)
#   3. writes the enroll secret (mode 600) and /etc/osquery/osquery.flags; with a token this machine does not hold yet, it first removes
#      osquery's database (/var/osquery/osquery.db: the old node key and unsent results) so that the machine enrols under the new token
#   4. enables and starts the osqueryd service (systemd, else the SysV init script), then waits until this machine has enrolled (not for its first report, due within a few minutes) and exits 0
# What the reporter path does: writes the box CA, the enrol secret (mode 600) and the reporter (/usr/local/sbin/vedette-reporter), runs it once
# (it enrols, then sends the package list), and schedules it hourly (systemd timer, else cron.d, else busybox crond).
set -eu
umask 022 # files this installer writes do not depend on root's umask; secrets are written in their own 077 subshell
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
# An osqueryd is Vedette's when this installer wrote its CA, or its flags point at this box.
osq_ours() { [ -f "$CA" ] || { [ -f "$DIR/osquery.flags" ] && grep -q "^--tls_hostname=${BOX#https://}\$" "$DIR/osquery.flags"; }; }
svc_disable_stop() {
  if [ "$INIT" = systemd ]; then systemctl disable --now osqueryd 2>/dev/null || true
  else
    "$SYSV" stop >/dev/null 2>&1 || true
    if command -v update-rc.d >/dev/null 2>&1; then update-rc.d -f osqueryd remove >/dev/null 2>&1 || true
    elif command -v chkconfig >/dev/null 2>&1; then chkconfig osqueryd off >/dev/null 2>&1 || true; fi
  fi
}
svc_enable_restart() {
  if [ "$INIT" = systemd ]; then
    # A crashed osqueryd comes back by itself. The drop-in is read back from systemd, and the install fails if it did not apply.
    mkdir -p /etc/systemd/system/osqueryd.service.d
    printf '[Service]\nRestart=on-failure\nRestartSec=10\n' > /etc/systemd/system/osqueryd.service.d/vedette-restart.conf
    systemctl daemon-reload
    [ "$(systemctl show -p Restart osqueryd 2>/dev/null)" = Restart=on-failure ] || { echo "systemd did not apply Restart=on-failure to osqueryd (see /etc/systemd/system/osqueryd.service.d/vedette-restart.conf); osquery is installed but was not started, because it would not come back after a crash." >&2; exit 1; }
    systemctl enable --quiet osqueryd; systemctl restart osqueryd; return
  fi
  if command -v update-rc.d >/dev/null 2>&1; then update-rc.d osqueryd defaults >/dev/null 2>&1 || true
  elif command -v chkconfig >/dev/null 2>&1; then chkconfig osqueryd on >/dev/null 2>&1 || true; fi
  "$SYSV" restart >/dev/null 2>&1
}
svc_active() { if [ "$INIT" = systemd ]; then systemctl is-active --quiet osqueryd; else "$SYSV" status >/dev/null 2>&1; fi; }

RDIR=/etc/vedette-reporter
RSTATE=/var/lib/vedette-reporter
RBIN=/usr/local/sbin/vedette-reporter
CRON_D=/etc/cron.d/vedette-reporter
BB_CRON=/etc/crontabs/root
# Takes this installer's line out of the busybox crontab. A grep that finds nothing (exit 1) is fine; a grep that fails (exit 2) must never
# leave root's crontab empty, so the file is replaced only after grep ran.
cron_strip() {
  rc=0; grep -v '# vedette-reporter$' "$BB_CRON" > "$BB_CRON.vedette-new" || rc=$?
  if [ "$rc" -le 1 ]; then cat "$BB_CRON.vedette-new" > "$BB_CRON"; fi
  rm -f "$BB_CRON.vedette-new"
  [ "$rc" -le 1 ]
}
# The reporter's schedule is removed wherever it was put (also when the machine has since changed init).
reporter_remove() {
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then systemctl disable --now vedette-reporter.timer >/dev/null 2>&1 || true; fi
  rm -f /etc/systemd/system/vedette-reporter.timer /etc/systemd/system/vedette-reporter.service "$CRON_D" "$RBIN"
  if [ -f "$BB_CRON" ]; then cron_strip || true; fi
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
  rm -rf "$RDIR" "$RSTATE"
}

if [ "$ACTION" = uninstall ]; then
  reporter_remove
  [ "$INIT" = none ] || svc_disable_stop
  rm -f /etc/systemd/system/osqueryd.service.d/vedette-restart.conf
  rmdir /etc/systemd/system/osqueryd.service.d 2>/dev/null || true
  if [ "$INIT" = systemd ]; then systemctl daemon-reload >/dev/null 2>&1 || true; fi
  if command -v dpkg >/dev/null 2>&1 && dpkg -s osquery >/dev/null 2>&1; then dpkg -r osquery 2>/dev/null || true
  elif command -v rpm >/dev/null 2>&1; then rpm -e osquery 2>/dev/null || true; fi
  rm -f "$DIR/osquery.flags" "$DIR/enroll.secret" "$CA"
  rm -rf "$DB"
  echo "osquery, the package reporter and the Vedette settings were removed from this machine."
  exit 0
fi

# The package reporter: for systems osquery cannot run on. It needs a way to run every hour (systemd, cron.d or busybox crond) and curl
# (installed with apk where it is missing: Alpine has none by default); everything else it uses is in busybox and coreutils.
install_reporter() {
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then SCHED=systemd
  elif [ -d /etc/cron.d ]; then SCHED=cron.d
  elif [ -d /etc/crontabs ]; then SCHED=busybox
  else echo "Cannot install the package reporter on ${OS_NAME}: no scheduler found (systemd, /etc/cron.d or /etc/crontabs). Install cron and run this command again." >&2; return 1; fi
  if ! command -v curl >/dev/null 2>&1; then
    if command -v apk >/dev/null 2>&1; then
      echo "Installing curl with apk (the reporter needs curl to talk to the box over TLS; this needs access to your apk repositories)..."
      apk add --no-cache curl >/dev/null 2>&1 || { echo "apk could not install curl: install curl and run this command again." >&2; return 1; }
    else echo "Cannot install the package reporter on ${OS_NAME}: 'curl' is required and is not installed." >&2; return 1; fi
  fi
  for NEED in awk sed grep mktemp ip; do
    command -v "$NEED" >/dev/null 2>&1 || { echo "Cannot install the package reporter on ${OS_NAME}: '$NEED' is required and is not installed." >&2; return 1; }
  done
  # With a token this machine does not hold yet the reporter's node key is dropped, so that it enrols under the new token.
  if [ "$(cat "$RDIR/enroll.secret" 2>/dev/null || true)" != "$TOKEN" ]; then rm -f "$RSTATE/node-key"; fi
  # osquery and the reporter never both enrol this machine: the box keeps one node per host name, so each enrolment would replace the other's.
  mkdir -p "$RDIR" "$RSTATE" "$RDIR/capath" /usr/local/sbin
  chmod 700 "$RDIR" "$RSTATE"
  chmod 755 "$RDIR/capath"
  cat > "$RDIR/ca.pem" <<'VEDETTE_CA'
@@CA@@
VEDETTE_CA
  chmod 644 "$RDIR/ca.pem"
  printf '%s\n' "$BOX" > "$RDIR/box"
  printf '%s\n' "$HOSTID" > "$RDIR/host-id"
  ( umask 077; printf '%s\n' "$TOKEN" > "$RDIR/enroll.secret" )
  RTMP=$(mktemp "$RBIN.XXXXXX") # created exclusively in the target directory: no name another user can plant a link at
  cat > "$RTMP" <<'VEDETTE_REPORTER'
#!/bin/sh
# Vedette package reporter. Installed by the Vedette install command on Linux systems osquery cannot run on (Alpine and other musl
# systems, Arch, other architectures). It enrols with the box like an osquery node, then sends this machine's operating system, network
# addresses and installed packages (apk, pacman, dpkg or rpm) to the box's osquery endpoints. Run by the system's scheduler; safe to run by hand.
# The enrol secret is read from a file (mode 600) and every request body is a file: nothing secret is ever an argument or is printed.
set -eu
umask 077
# A scheduler's PATH can be short (cron.d: /usr/bin:/bin), and ip lives in /usr/sbin on some systems; the job runs as root, so PATH is fixed.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
D=/etc/vedette-reporter
S=/var/lib/vedette-reporter
MAXROWS=5000
mkdir -p "$S"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
say() { printf '%s\n' "$*" >&2; }
fail() { printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "failed: $*" > "$S/last-run"; say "vedette-reporter: $*"; exit "${2:-1}"; }
for NEED in curl awk sed uname mktemp grep ip; do command -v "$NEED" >/dev/null 2>&1 || fail "'$NEED' is required and is not installed"; done
read -r BOX < "$D/box" || fail "cannot read $D/box"
read -r HOSTID < "$D/host-id" || fail "cannot read $D/host-id"
read -r TOKEN < "$D/enroll.secret" || fail "cannot read $D/enroll.secret"
printf '%s' "$TOKEN" | grep -Eq '^vdt_[a-z]+_[a-z0-9]{32}$' || fail "the enrol secret in $D/enroll.secret is not a Vedette token"
printf '%s' "$BOX" | grep -Eq '^https://[]A-Za-z0-9.:[-]+$' && [ "${#BOX}" -le 270 ] || fail "$D/box is not an https address"
printf '%s' "$HOSTID" | grep -Eq '^[A-Za-z0-9._-]{1,200}$' || fail "$D/host-id is not a host name"

# One HTTPS call to the box with the box's own certificate pinned. The body is $TMP/req and the answer $TMP/resp.
# --capath points at an empty directory: --cacert alone leaves the system's CA directory trusted too (Debian and Ubuntu curl), so any public CA
# could stand in for the box. HTTPCODE is 000 when the box could not be reached at all.
post() {
  HTTPCODE=$(curl -sS --proto '=https' --max-time 120 --cacert "$D/ca.pem" --capath "$D/capath" -H 'Content-Type: application/json' --data-binary @"$TMP/req" -o "$TMP/resp" -w '%{http_code}' "$BOX/api/v1/intake/osquery/$1") || HTTPCODE=000
  case "$HTTPCODE" in 2??) return 0 ;; esac
  return 1
}
# why says what a failed call was: no answer (address, certificate), or the box's HTTP status (429: asked again within a minute; wait and retry).
why() { if [ "$HTTPCODE" = 000 ]; then printf 'cannot reach the box at %s (is the address reachable and its certificate the one in %s/ca.pem?)' "$BOX" "$D"; else printf 'the box at %s answered HTTP %s' "$BOX" "$HTTPCODE"; fi; }

# ---- what this machine is ----
# os-release is read in a subshell (its VERSION, NAME, ... must not overwrite this script's variables).
OSF=/etc/os-release; [ -r "$OSF" ] || OSF=/usr/lib/os-release
# shellcheck disable=SC1090 # the file is os-release, read on purpose
OSROW=$( . "$OSF" 2>/dev/null; printf '%s\t%s\t%s' "${NAME:-}" "${VERSION_ID:-${BUILD_ID:-}}" "${ID:-linux}" ) || OSROW=''
OS_NAME=$(printf '%s' "$OSROW" | cut -f1)
OS_VERSION=$(printf '%s' "$OSROW" | cut -f2)
OS_ID=$(printf '%s' "$OSROW" | cut -f3)
ARCH=$(uname -m)
# The host name is read at every run (a renamed machine reports its new name); the identifier it enrolled under stays the stored one.
LIVEHOST=$(uname -n | tr -cd 'A-Za-z0-9._-' | cut -c1-200); [ -n "$LIVEHOST" ] || LIVEHOST=$HOSTID
# Free text becomes a JSON string only after it has been cut to a plain character set: nothing in it needs escaping.
plain() { printf '%s' "$1" | tr -cd 'A-Za-z0-9 ._+()/:-' | cut -c1-"$2"; }
OS_NAME=$(plain "$OS_NAME" 80); OS_VERSION=$(plain "$OS_VERSION" 60); OS_ID=$(plain "$OS_ID" 32 | tr 'A-Z ' 'a-z-'); ARCH=$(plain "$ARCH" 32)
[ -n "$OS_NAME" ] || OS_NAME=Linux

# ---- network addresses: IPv4 and MAC of each card; the address this machine reaches the box from comes first ----
# The box accepts a report only from an address the report itself lists, so that address must be in the first eight rows.
BOXHOST=${BOX#https://}; BOXHOST=${BOXHOST%:*}
SRCIP=''
if printf '%s' "$BOXHOST" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then BOXIP=$BOXHOST
elif command -v getent >/dev/null 2>&1; then BOXIP=$(getent ahostsv4 "$BOXHOST" 2>/dev/null | awk 'NR==1{print $1}')
else BOXIP=''; fi
if printf '%s' "$BOXIP" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
  SRCIP=$(ip -4 route get "$BOXIP" 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n 1)
fi
ip -o -4 addr show scope global 2>/dev/null | while read -r _ IFACE _ ADDR _; do
  IFACE=${IFACE%%@*}; ADDR=${ADDR%%/*}
  printf '%s' "$ADDR" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' || continue
  printf '%s' "$IFACE" | grep -Eq '^[A-Za-z0-9._-]{1,32}$' || continue
  MAC=''; read -r MAC 2>/dev/null < "/sys/class/net/$IFACE/address" || continue
  printf '%s' "$MAC" | grep -Eq '^[0-9a-f]{2}(:[0-9a-f]{2}){5}$' || continue
  if [ "$ADDR" = "$SRCIP" ]; then printf '0 '; else printf '1 '; fi
  printf '{"mac":"%s","address":"%s"}\n' "$MAC" "$ADDR"
done | sort | head -n 8 | cut -d' ' -f2- | paste -sd, - > "$TMP/ifaces" || true
[ -s "$TMP/ifaces" ] || fail "no IPv4 address with a hardware address was found on this machine"

# ---- installed packages ----
# Each package manager's output is read with a strict shape per line; a line that does not fit is dropped and counted, and when nothing fits
# at all the report is refused (the output is of a shape this script does not know), never guessed.
PKQ=''
if command -v apk >/dev/null 2>&1 && [ -d /lib/apk/db ]; then
  PKQ=apk_packages
  apk list -I > "$TMP/raw" 2>/dev/null || fail "apk list failed"
  # openssh-10.2_p1-r1 x86_64 {openssh} (BSD-2-Clause) [installed]
  awk -v max="$MAXROWS" '
    $1 == "" { next }
    { bad_line = 1 }
    NF >= 3 && $3 ~ /^\{[a-z0-9][a-z0-9+._-]*\}$/ && $2 ~ /^[a-z0-9_]+$/ && match($1, /-[0-9][0-9A-Za-z._]*-r[0-9]+$/) && RSTART > 1 {
      name = substr($1, 1, RSTART - 1); ver = substr($1, RSTART + 1); origin = substr($3, 2, length($3) - 2)
      if (name ~ /^[a-z0-9][a-z0-9+._-]*$/ && length(name) <= 100 && length(ver) <= 60 && length(origin) <= 100) {
        bad_line = 0
        if (good < max) { printf "%s{\"name\":\"%s\",\"version\":\"%s\",\"arch\":\"%s\",\"origin\":\"%s\"}", (good ? "," : ""), name, ver, $2, origin; good++ }
      }
    }
    bad_line { bad++ }
    END { if (good == 0) exit 4; if (bad > 0) print bad " apk lines were not read" > "/dev/stderr" }' "$TMP/raw" > "$TMP/pkgs" || fail "apk list printed nothing this script can read" 4
elif command -v pacman >/dev/null 2>&1 && [ -d /var/lib/pacman/local ]; then
  PKQ=pacman_packages
  pacman -Q > "$TMP/raw" 2>/dev/null || fail "pacman -Q failed"
  # linux 6.12.1.arch1-1
  awk -v max="$MAXROWS" '
    $1 == "" { next }
    { bad_line = 1 }
    NF == 2 && $1 ~ /^[a-z0-9][a-z0-9+._-]*$/ && length($1) <= 100 && $2 ~ /^([0-9]+:)?[A-Za-z0-9._+~]+-[A-Za-z0-9._+]+$/ && length($2) <= 60 {
      bad_line = 0
      if (good < max) { printf "%s{\"name\":\"%s\",\"version\":\"%s\"}", (good ? "," : ""), $1, $2; good++ }
    }
    bad_line { bad++ }
    END { if (good == 0) exit 4; if (bad > 0) print bad " pacman lines were not read" > "/dev/stderr" }' "$TMP/raw" > "$TMP/pkgs" || fail "pacman -Q printed nothing this script can read" 4
elif command -v dpkg-query >/dev/null 2>&1 && [ -e /var/lib/dpkg/status ]; then
  PKQ=deb_packages
  dpkg-query -W -f '${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${Source}\n' > "$TMP/raw" 2>/dev/null || fail "dpkg-query failed"
  awk -F '\t' -v max="$MAXROWS" '
    $1 !~ /^[hi]i/ { next }
    { bad_line = 1; src = $5 }
    $2 ~ /^[a-z0-9][a-z0-9+.-]*$/ && length($2) <= 100 && $3 ~ /^[A-Za-z0-9.+~:-]+$/ && length($3) <= 100 && $4 ~ /^[a-z0-9-]+$/ && (src == "" || (src ~ /^[a-z0-9][a-z0-9+.-]*( \([A-Za-z0-9.+~:-]+\))?$/ && length(src) <= 150)) {
      bad_line = 0
      if (good < max) { printf "%s{\"name\":\"%s\",\"version\":\"%s\",\"arch\":\"%s\",\"source\":\"%s\"}", (good ? "," : ""), $2, $3, $4, src; good++ }
    }
    bad_line { bad++ }
    END { if (good == 0) exit 4; if (bad > 0) print bad " dpkg lines were not read" > "/dev/stderr" }' "$TMP/raw" > "$TMP/pkgs" || fail "dpkg-query printed nothing this script can read" 4
elif command -v rpm >/dev/null 2>&1; then
  PKQ=rpm_packages
  rpm -qa --qf '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\n' > "$TMP/raw" 2>/dev/null || fail "rpm -qa failed"
  awk -F '\t' -v max="$MAXROWS" '
    $1 == "gpg-pubkey" { next }
    { bad_line = 1 }
    $1 ~ /^[A-Za-z0-9][A-Za-z0-9._+-]*$/ && length($1) <= 100 && $2 ~ /^[0-9]+$/ && $3 ~ /^[A-Za-z0-9._+~^]+$/ && length($3) <= 100 && $4 ~ /^[A-Za-z0-9._+~^]+$/ && length($4) <= 100 && $5 ~ /^[A-Za-z0-9_]+$/ {
      bad_line = 0
      if (good < max) { printf "%s{\"name\":\"%s\",\"epoch\":\"%s\",\"version\":\"%s\",\"release\":\"%s\",\"arch\":\"%s\"}", (good ? "," : ""), $1, $2, $3, $4, $5; good++ }
    }
    bad_line { bad++ }
    END { if (good == 0) exit 4; if (bad > 0) print bad " rpm lines were not read" > "/dev/stderr" }' "$TMP/raw" > "$TMP/pkgs" || fail "rpm printed nothing this script can read" 4
else
  fail "no package manager this script reads (apk, pacman, dpkg, rpm) was found" 4
fi

# ---- enrol, once: the node key is kept; it is asked for again only when the box no longer knows it ----
KEYF=$S/node-key
keyval() { sed -n 's/.*"node_key" *: *"\([A-Za-z0-9_-]*\)".*/\1/p' "$1" | head -n 1; }
enrol() {
  printf '{"enroll_secret":"%s","host_identifier":"%s","host_details":{"system_info":{"hostname":"%s"},"os_version":{"platform":"%s"}}}' "$TOKEN" "$HOSTID" "$HOSTID" "$OS_ID" > "$TMP/req"
  post enroll || fail "$(why)"
  NODEKEY=$(keyval "$TMP/resp")
  printf '%s' "$NODEKEY" | grep -Eq '^[A-Za-z0-9_-]{43}$' || fail "the box did not accept this enrol secret (revoked or expired token: run the install command again)" 2
  printf '%s\n' "$NODEKEY" > "$KEYF"
}
NODEKEY=''
# read returns 1 at the end of a file without a final newline although it set the variable: the key is written with one and read either way
[ ! -s "$KEYF" ] || read -r NODEKEY < "$KEYF" || [ -n "$NODEKEY" ] || NODEKEY=''
printf '%s' "$NODEKEY" | grep -Eq '^[A-Za-z0-9_-]{43}$' || { NODEKEY=''; enrol; }

send() {
  {
    printf '{"node_key":"%s","log_type":"result","data":[' "$NODEKEY"
    printf '{"name":"os_version","action":"snapshot","snapshot":[{"name":"%s","version":"%s","platform":"%s","arch":"%s"}]},' "$OS_NAME" "$OS_VERSION" "$OS_ID" "$ARCH"
    printf '{"name":"system_info","action":"snapshot","snapshot":[{"hostname":"%s"}]},' "$LIVEHOST"
    printf '{"name":"interfaces","action":"snapshot","snapshot":[%s]},' "$(cat "$TMP/ifaces")"
    printf '{"name":"%s","action":"snapshot","snapshot":[' "$PKQ"; cat "$TMP/pkgs"; printf ']}]}'
  } > "$TMP/req"
  post log || fail "sending the report failed: $(why)"
}
send
if grep -q '"node_invalid" *: *true' "$TMP/resp"; then NODEKEY=''; enrol; send; fi
if grep -q '"node_invalid" *: *true' "$TMP/resp"; then fail "the box refused this machine's node key twice" 2; fi
printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "sent $PKQ to $BOX" > "$S/last-run"
VEDETTE_REPORTER
  chmod 755 "$RTMP"; mv -f "$RTMP" "$RBIN"
  # osquery and the reporter never both enrol this machine (the box keeps one node per host name). Only an osqueryd that Vedette's own install
  # set up is stopped; one that belongs to the customer (Fleet, Kolide, a hand-built one) is left running.
  if [ "$INIT" != none ] && svc_known; then
    if osq_ours; then svc_disable_stop; else echo "osqueryd is installed here and is not managed by Vedette; the reporter was installed next to it and osqueryd was left as it is."; fi
  fi
  # one minute of the hour per machine, so that a fleet does not report in the same second
  MIN=$(printf '%s' "$HOSTID" | cksum | awk '{ print $1 % 60 }')
  case "$SCHED" in
    systemd)
      cat > /etc/systemd/system/vedette-reporter.service <<UNIT
[Unit]
Description=Vedette package reporter
After=network-online.target

[Service]
Type=oneshot
ExecStart=$RBIN
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
UNIT
      cat > /etc/systemd/system/vedette-reporter.timer <<UNIT
[Unit]
Description=Vedette package reporter, every hour

[Timer]
OnCalendar=*-*-* *:$MIN:00
RandomizedDelaySec=60
Persistent=true

[Install]
WantedBy=timers.target
UNIT
      systemctl daemon-reload
      if ! systemctl enable --now vedette-reporter.timer >/dev/null 2>&1 || ! systemctl is-active --quiet vedette-reporter.timer; then
        echo "systemd did not start vedette-reporter.timer: the hourly report would not run." >&2; return 1
      fi ;;
    cron.d)
      printf '%s * * * * root %s >/dev/null 2>&1\n' "$MIN" "$RBIN" > "$CRON_D"
      chmod 644 "$CRON_D" ;;
    busybox)
      touch "$BB_CRON"
      cron_strip || { echo "Could not read $BB_CRON; the crontab was left as it is." >&2; return 1; }
      printf '%s * * * * %s >/dev/null 2>&1 # vedette-reporter\n' "$MIN" "$RBIN" >> "$BB_CRON"
      if command -v rc-service >/dev/null 2>&1; then rc-update add crond default >/dev/null 2>&1 || true; rc-service crond start >/dev/null 2>&1 || true; fi
      if command -v pgrep >/dev/null 2>&1 && ! pgrep crond >/dev/null 2>&1; then echo "Note: crond is not running on this machine, so the hourly report will not run until it is started (Alpine: rc-service crond start)." >&2; fi ;;
  esac
  # The schedule is in place before the first report, so a failure of the first one (a network that is not up yet) does not leave a reporter that never runs.
  echo "Sending this machine's packages to Vedette..."
  "$RBIN" || { echo "The package reporter was installed and scheduled every hour (minute $MIN, $SCHED), but its first report failed (see above and $RSTATE/last-run). Check that the box address is reachable from here and the token is still valid, then run: $RBIN" >&2; return 3; }
  echo "Installed. This machine's operating system and packages appear in Vedette now and are refreshed every hour (minute $MIN, $SCHED)."
}

[ -n "$TOKEN" ] || { echo "Missing --token. Copy the install command from Vedette, Devices › Setup › Agents." >&2; exit 2; }
# The package must match the userland, not the kernel: a 32-bit system on a 64-bit kernel (Raspberry Pi OS armhf) says aarch64 in uname -m.
ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)
# WHY stays empty while osquery can be installed here; the first thing it cannot do is named in it and the reporter is installed instead.
WHY=
case "$ARCH" in
  x86_64|amd64) DEB_ARCH=amd64; RPM_ARCH=x86_64; GLIBC_LOADER=/lib64/ld-linux-x86-64.so.2 ;;
  aarch64|arm64) DEB_ARCH=arm64; RPM_ARCH=aarch64; GLIBC_LOADER=/lib/ld-linux-aarch64.so.1 ;;
  *) DEB_ARCH=''; RPM_ARCH=''; GLIBC_LOADER=''; WHY="osquery from this box runs on x86_64 and arm64 (aarch64) servers only; this one is $ARCH" ;;
esac
# os-release is read in subshells: sourced here it would overwrite this script's own variables (VERSION, NAME, ...). It only names the
# system in messages; what to do is decided by what the machine has.
OSF=/etc/os-release; [ -r "$OSF" ] || OSF=/usr/lib/os-release
# shellcheck disable=SC1090 # the file is os-release, read on purpose
OS_NAME=$( . "$OSF" 2>/dev/null; printf '%s' "${PRETTY_NAME:-unknown}" ) || OS_NAME=unknown
# osquery's official Linux builds are dynamically linked against glibc (they do not run on musl systems such as Alpine, with or without gcompat).
if [ -z "$WHY" ] && [ ! -e "$GLIBC_LOADER" ]; then WHY="its official build needs glibc ($GLIBC_LOADER is missing; this looks like a musl system such as Alpine)"; fi
FMT=; FILE=
if [ -n "$WHY" ]; then :
elif command -v dpkg >/dev/null 2>&1 && [ -e /var/lib/dpkg/status ]; then FMT=deb; FILE="osquery_${OSQ_VERSION}-1.linux_${DEB_ARCH}.deb"
elif command -v rpm >/dev/null 2>&1; then FMT=rpm; FILE="osquery-${OSQ_VERSION}-1.linux.${RPM_ARCH}.rpm"
else WHY="neither dpkg nor rpm is present, and the osquery package of this box is a .deb or .rpm"; fi
if [ -z "$WHY" ] && [ "$INIT" = none ]; then WHY="no service manager found (systemd, or SysV init scripts with ps and pkill installed)"; fi

HOSTID=$(uname -n | tr -cd 'A-Za-z0-9._-')
[ -n "$HOSTID" ] || { echo "Cannot read this machine's host name (uname -n)." >&2; exit 1; }

if [ -n "$WHY" ]; then
  echo "osquery cannot be installed on ${OS_NAME}: ${WHY}."
  echo "Installing the Vedette package reporter instead (same token, same box; it reports this machine's packages every hour)."
  install_reporter
  exit $?
fi
for NEED in curl sha256sum mktemp; do
  command -v "$NEED" >/dev/null 2>&1 || { echo "Cannot install osquery on ${OS_NAME}: '$NEED' is required and is not installed." >&2; exit 1; }
done

# The name this machine enrols under is chosen here (--host_identifier=specified), so the status check below asks for exactly that name;
# osquery's own hostname lookup can be the short or the full name depending on the machine.
mkdir -p "$DIR"
cat > "$CA" <<'VEDETTE_CA'
@@CA@@
VEDETTE_CA
chmod 644 "$CA"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/capath" # empty: --cacert alone leaves the system's CA directory trusted too (Debian and Ubuntu curl), so only the box's own certificate is accepted
curl -fsS --cacert "$CA" --capath "$TMP/capath" "$BOX/api/v1/install/osquery/SHA256SUMS" -o "$TMP/SHA256SUMS"
curl -fsS --cacert "$CA" --capath "$TMP/capath" "$BOX/api/v1/install/osquery/$FILE" -o "$TMP/$FILE"
( cd "$TMP" && grep " $FILE\$" SHA256SUMS | sha256sum -c - ) || { echo "Checksum of $FILE does not match. Nothing was installed." >&2; exit 1; }
# The package manager's output (and whatever osquery's own package scripts print, such as a bare line of numbers) goes to a log shown
# only when the install fails, so a normal run prints Vedette's lines only.
# One machine runs one agent: a reporter from an earlier run is removed, since both enrol under this machine's name and would replace each other's node.
# Only now, after the package is downloaded and its checksum matched, so a failed download leaves what the machine had.
reporter_remove
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
vstatus() { curl -fsS --cacert "$CA" --capath "$TMP/capath" -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d "{\"host_identifier\":\"$HOSTID\"}" "$BOX/api/v1/intake/osquery/status" 2>/dev/null || true; }
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
