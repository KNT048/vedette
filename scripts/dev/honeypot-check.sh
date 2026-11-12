#!/usr/bin/env bash
# make honeypot-check (WP-08e, D-162): build the honeypot image, run it the way the unit does and check BY EFFECT, not by the exit code of the build:
#   * OpenCanary starts with the files core's own code writes (honeypot.RenderConfig / RenderTokens, through a Go test), and a connection to
#     each trap writes a JSON line into the mounted log/ that modules/honeypot's parser accepts (a Go test runs ParseLine on the log);
#   * Samba serves the planted file token, and opening it reaches OpenCanary as a log type 5000 line whose file name is the token and whose source is
#     the real client (a client user name with `|` in it cannot forge another source);
#   * `/vedette honeypot healthcheck` (the unit's HealthCmd) passes;
#   * every process is uid 1000 gid 0 with all five capability sets empty and NoNewPrivs; config/ is read-only, the root is read-only, log/ is writable;
#   * no GPL Python package is in the image (hpfeeds is a stub).
# Runs rootless podman (CONTAINER=podman) with the unit's flags (host/ops/quadlet.go honeypotUnitText): read-only root, tmpfs /tmp, all capabilities
# dropped, no-new-privileges, the log volume with :U. What a rootless run cannot show (UserNS=auto, the macvlan namespace, packet capture) is in
# .ai/deferred/feat-honeypot.md. Removes the containers, the network and the image at the end (rules/build-artifacts.md); the work folder is
# under ~/.cache/vedette-honeypot, never /tmp. VEDETTE_HP_REUSE=1 skips the build and uses an image already tagged localhost/vedette-honeypot:hpcheck.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
c=${CONTAINER:-podman}
tag=hpcheck
img=localhost/vedette-honeypot:$tag
id=$$
name=vedette-hp-check-$id
vol=vedette-hp-log-check-$id
client=vedette-hp-client-$id
net=vedette-hp-net-$id
# shellcheck disable=SC1091
set -a; . deploy/containers/pins.env; set +a
root=${VEDETTE_HP_WORK:-$HOME/.cache/vedette-honeypot}
mkdir -p "$root"
work=$(mktemp -d "$root/check.XXXXXX")
cleanup() {
	$c rm -f "$name" "$client" >/dev/null 2>&1 || true
	$c network rm -f "$net" >/dev/null 2>&1 || true
	$c volume rm -f "$vol" >/dev/null 2>&1 || true
	[ "${VEDETTE_HP_KEEP_IMAGE:-0}" = 1 ] || $c rmi -f "$img" >/dev/null 2>&1 || true
	# the log files belong to the container's user (podman's :U): remove them from inside the user namespace
	$c unshare rm -rf "$work" 2>/dev/null || rm -rf "$work"
}
trap cleanup EXIT
fail() { echo "honeypot-check: FAIL $*" >&2; { $c logs --tail 40 "$name" 2>&1 || true; } | sed 's/^/    container: /' >&2; exit 1; }
ok() { echo "honeypot-check: ok   $*"; }

if [ "${VEDETTE_HP_REUSE:-0}" != 1 ]; then
	make --no-print-directory honeypot-image CONTAINER="$c" IMAGE_TAG=$tag
fi

# 1. the files core writes
mkdir -p "$work/config" "$work/log"
chmod 0755 "$work/config" "$work/log"
VEDETTE_HP_OUT="$work/config" go test ./deploy/containers -run '^TestHoneypotWriteFixture$' -count=1 >/dev/null || fail "writing the fixture with honeypot.RenderConfig"
[ -s "$work/config/opencanary.conf" ] && [ -s "$work/config/honeytokens.json" ] || fail "fixture files missing"
ok "opencanary.conf and honeytokens.json written by modules/honeypot"

# 2. run it as the unit does. log/ is the size-capped tmpfs volume of the unit (D-318): its options are read from the golden file of
# vedette-hp-log.volume, so this check and the shipped unit cannot drift apart.
volfile=host/ops/testdata/units/vedette-hp-log.volume
grep -qx 'Type=tmpfs' "$volfile" && grep -qx 'Device=tmpfs' "$volfile" || fail "$volfile is not a tmpfs volume"
volopts=$(sed -n 's/^Options=//p' "$volfile")
[ -n "$volopts" ] || fail "no Options= in $volfile"
$c volume create --opt device=tmpfs --opt type=tmpfs --opt "o=$volopts" "$vol" >/dev/null
# what core does: read the log through a second container, another uid, read-only (the "other" bits of init.py's mode 0755)
snap() { $c run --rm --user 10001:10002 --entrypoint /bin/cat -v "$vol:/var/lib/vedette/honeypot/log:ro,noexec" "$img" /var/lib/vedette/honeypot/log/opencanary.jsonl >"$work/log/opencanary.jsonl" 2>/dev/null || true; }
$c network create "$net" >/dev/null
$c run -d --name "$name" --network "$net" --read-only --tmpfs /tmp --cap-drop=ALL --security-opt no-new-privileges \
	--sysctl net.ipv4.ip_unprivileged_port_start=0 --memory 256m --memory-swap 256m --pids-limit 128 \
	-v "$work/config:/var/lib/vedette/honeypot/config:ro" -v "$vol:/var/lib/vedette/honeypot/log:U,noexec" "$img" >/dev/null
ip=
for _ in $(seq 1 90); do
	[ "$($c inspect -f '{{.State.Running}}' "$name")" = true ] || fail "the container stopped"
	ip=$($c inspect -f '{{(index .NetworkSettings.Networks "'"$net"'").IPAddress}}' "$name")
	case "$($c logs "$name" 2>&1)" in *'vedette-hp: up'*) [ -n "$ip" ] && break ;; esac
	sleep 1
done
case "$($c logs "$name" 2>&1)" in *'vedette-hp: up'*) ;; *) fail "init.py did not report up" ;; esac
ok "container up at $ip: $($c logs "$name" 2>&1 | grep 'vedette-hp:' | head -3 | tr '\n' ' ')"
for _ in $(seq 1 30); do
	$c exec "$name" /vedette honeypot healthcheck >/dev/null 2>&1 && break
	sleep 1
done
hc=$($c exec "$name" /vedette honeypot healthcheck 2>&1; echo "exit=$?")
echo "$hc" | tail -1 | grep -qx 'exit=0' || fail "/vedette honeypot healthcheck: $hc"
ok "/vedette honeypot healthcheck exits 0 (the unit's HealthCmd, read from opencanary.conf)"

# 3. privileges: every process is uid 1000 with no capability; the filesystems are what the unit asks for
procs=$($c exec "$name" /usr/bin/python3 -I -c '
import os
for p in sorted(int(x) for x in os.listdir("/proc") if x.isdigit()):
    if p == os.getpid():  # this probe itself (it runs as the image user too, like the unit health command)
        continue
    try:
        s = dict(l.split(":\t", 1) for l in open("/proc/%d/status" % p).read().splitlines() if ":\t" in l)
    except OSError:
        continue
    caps = "".join(s[k].strip() for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
    print(p, s["Name"], "uid=" + "/".join(s["Uid"].split()), "gid=" + "/".join(s["Gid"].split()), "groups=" + (s["Groups"].strip() or "-").replace(" ", ","),
          "caps=" + ("none" if set(caps) <= {"0"} else caps), "nonewprivs=" + s["NoNewPrivs"].strip())
')
echo "$procs" | sed 's/^/    /'
[ "$(echo "$procs" | wc -l)" -ge 3 ] || fail "fewer than three processes"
echo "$procs" | grep -v ' uid=1000/1000/1000/1000 gid=0/0/0/0 groups=-\| uid=1000/1000/1000/1000 gid=0/0/0/0 groups=0 ' | grep -q . && fail "a process is not uid 1000, gid 0, without supplementary groups"
echo "$procs" | grep -v ' caps=none ' | grep -q . && fail "a process has a capability in a set (inheritable, permitted, effective, bounding or ambient)"
echo "$procs" | grep -v ' nonewprivs=1$' | grep -q . && fail "a process lacks NoNewPrivs"
echo "$procs" | awk '{print $2}' | grep -qx smbd || fail "smbd is not running"
echo "$procs" | awk '{print $2}' | grep -q python || fail "no python (init, OpenCanary)"
ok "every process is uid 1000 gid 0 (no extra groups), all five capability sets empty, NoNewPrivs 1: nothing in the container ever ran as root"
case "$($c image inspect "$img" --format '{{.Config.User}}')" in 1000:0) ;; *) fail "the image user is not 1000:0" ;; esac
if $c exec "$name" /usr/bin/python3 -I -c 'open("/var/lib/vedette/honeypot/config/x", "w")' 2>/dev/null; then fail "config/ is writable"; fi
if $c exec "$name" /usr/bin/python3 -I -c 'open("/usr/x", "w")' 2>/dev/null; then fail "the root filesystem is writable"; fi
$c exec "$name" /usr/bin/python3 -I -c 'open("/var/lib/vedette/honeypot/log/probe", "w").close()' 2>/dev/null || fail "log/ is not writable by the container's user"
$c exec "$name" /usr/bin/python3 -I -c 'import os; os.unlink("/var/lib/vedette/honeypot/log/probe")'
ok "config/ and the root are read-only, log/ is writable"

# 4. a client on the same network connects to each trap (a source that is not loopback, as in production)
$c run -d --name "$client" --network "$net" "$DEBIAN_IMAGE" sleep 600 >/dev/null
$c exec "$client" bash -c 'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq --no-install-recommends smbclient python3 >/dev/null 2>&1' || fail "installing the test client"
cip=$($c inspect -f '{{(index .NetworkSettings.Networks "'"$net"'").IPAddress}}' "$client")
$c exec "$client" python3 -c '
import socket, sys
ip = sys.argv[1]
s = socket.create_connection((ip, 22), 5); print("ssh:", s.recv(100).decode().strip()); s.close()
for p in ("/", "/index.html"):
    s = socket.create_connection((ip, 80), 5); s.sendall(b"GET " + p.encode() + b" HTTP/1.1\r\nHost: x\r\n\r\n"); print("http", p, s.recv(100).decode().splitlines()[0]); s.close()
' "$ip" > "$work/client.out"
grep -q 'http / HTTP/1.1 302' "$work/client.out" || fail "GET / on the web trap: $(cat "$work/client.out")"
grep -q 'http /index.html HTTP/1.1 200' "$work/client.out" || fail "GET /index.html on the web trap: $(cat "$work/client.out")"
sed 's/^/    /' "$work/client.out"
out=$($c exec "$client" smbclient -N "//$ip/Shared" -c 'ls; get passwords.txt /dev/null' 2>&1) || fail "smbclient: $out"
echo "$out" | grep -q 'passwords.txt' || fail "the share does not list the planted token: $out"
ok "SMB share lists the planted token; SSH and HTTP traps answered"
# a client user name carrying `|` and a fake address reaches no field of the audit line
$c exec "$client" smbclient -U 'x|6.6.6.6|7.7.7.7%y' "//$ip/Shared" -c 'get "Q4 payroll.xlsx" /dev/null' >/dev/null 2>&1 || true

# 5. the lines in the mounted log/
want=4000,3000,5000
for _ in $(seq 1 30); do
	snap
	n=$(grep -c '"logtype": 5000' "$work/log/opencanary.jsonl" 2>/dev/null || true)
	h=$(grep -c '"logtype": 3000' "$work/log/opencanary.jsonl" 2>/dev/null || true)
	s=$(grep -c '"logtype": 4000' "$work/log/opencanary.jsonl" 2>/dev/null || true)
	[ "${n:-0}" -ge 2 ] && [ "${h:-0}" -ge 1 ] && [ "${s:-0}" -ge 1 ] && break
	sleep 1
done
snap
[ -s "$work/log/opencanary.jsonl" ] || fail "no opencanary.jsonl in the mounted log/ (read through a second container, uid 10001, read-only)"
python3 -I -c '
import json, sys
for l in open(sys.argv[1]):
    d = json.loads(l)
    if d["logtype"] >= 2000:
        x = d["logdata"]
        print("    log: type=%d src=%s dst=%s:%s %s" % (d["logtype"], d["src_host"], d["dst_host"], d["dst_port"], {k: x[k] for k in ("AUDITACTION", "FILENAME", "STATUS", "PATH", "USERAGENT") if k in x}))
' "$work/log/opencanary.jsonl"
smb_lines=$(grep '"logtype": 5000' "$work/log/opencanary.jsonl")
case "$smb_lines" in *'"FILENAME": "/passwords.txt"'*) ;; *) fail "no SMB hit for passwords.txt" ;; esac
case "$smb_lines" in *'"FILENAME": "/Q4 payroll.xlsx"'*) ;; *) fail "no SMB hit for the second token" ;; esac
grep '"logtype": 5000' "$work/log/opencanary.jsonl" | grep -v "\"src_host\": \"$cip\"" | grep -q . && fail "an SMB line whose source is not the client $cip"
grep -q '6\.6\.6\.6' "$work/log/opencanary.jsonl" && fail "a forged source address reached the log"
ok "log/opencanary.jsonl holds log types 4000, 3000 and 5000 (file tokens), every SMB source is the client $cip, no forged address"
VEDETTE_HP_LOGFILE="$work/log/opencanary.jsonl" VEDETTE_HP_WANT=$want go test ./deploy/containers -run '^TestHoneypotLogFileParses$' -count=1 -v 2>&1 | grep -vE '^(=== RUN|PASS$)' | cut -c1-600 | sed 's/^/    /' || true
VEDETTE_HP_LOGFILE="$work/log/opencanary.jsonl" VEDETTE_HP_WANT=$want go test ./deploy/containers -run '^TestHoneypotLogFileParses$' -count=1 >/dev/null || fail "honeypot.ParseLine does not accept the log"
ok "modules/honeypot ParseLine accepts every line"

# 5b. the cap (D-318): the mount has the unit's options, and a container that writes past size= gets ENOSPC (and so does the 1025th file);
# the second container still cannot write (:ro). Done last: log/ is full for a moment, so OpenCanary could lose a line meanwhile.
mnt=$($c exec "$name" /usr/bin/python3 -I -c 'print([l for l in open("/proc/mounts") if " /var/lib/vedette/honeypot/log " in l][0].strip())')
echo "    log mount: $mnt"
for need in 'tmpfs ' size=65536k nr_inodes=1024 nosuid nodev noexec; do
	case "$mnt" in *"$need"*) ;; *) fail "the log mount lacks $need: $mnt" ;; esac
done
res=$($c exec "$name" /usr/bin/python3 -I -c '
import errno, os
d = "/var/lib/vedette/honeypot/log/"
fd = os.open(d + "fill", os.O_WRONLY | os.O_CREAT, 0o644)
chunk = b"x" * (1 << 20)
n = 0
try:
    while n < 200:
        os.write(fd, chunk); n += 1
    print("no ENOSPC after", n, "MiB")
except OSError as e:
    print("ENOSPC" if e.errno == errno.ENOSPC else "errno %d" % e.errno, "after", n, "MiB")
os.close(fd); os.unlink(d + "fill")
made = []
try:
    for i in range(5000):
        os.close(os.open(d + "n%d" % i, os.O_WRONLY | os.O_CREAT, 0o644)); made.append(i)
    print("no ENOSPC for files")
except OSError as e:
    print("files:", "ENOSPC" if e.errno == errno.ENOSPC else "errno %d" % e.errno, "after", len(made))
for i in made:
    os.unlink(d + "n%d" % i)
')
echo "$res" | sed 's/^/    /'
echo "$res" | grep -q '^ENOSPC after 6[0-9] MiB$' || fail "writing past the 64 MiB cap did not end in ENOSPC: $res"
echo "$res" | grep -q '^files: ENOSPC after ' || fail "creating files past nr_inodes did not end in ENOSPC: $res"
if $c run --rm --user 10001:10002 --entrypoint /usr/bin/python3 -v "$vol:/var/lib/vedette/honeypot/log:ro,noexec" "$img" -I -c 'open("/var/lib/vedette/honeypot/log/x", "w")' 2>/dev/null; then fail "log/ is writable through the read-only mount"; fi
ok "log/ is a tmpfs capped at 64 MiB and 1024 files: past the cap the container gets ENOSPC; the :ro reader (uid 10001) sees the log and cannot write"

# 6. size and contents
$c image inspect "$img" --format 'honeypot image: {{.Size}} bytes, user {{.Config.User}}, arch {{.Architecture}}'
inv=$($c run --rm --entrypoint /bin/cat "$img" /usr/share/vedette/honeypot-inventory.txt)
echo "$inv" | awk '{print $1}' | sort | uniq -c | sed 's/^/    inventory: /'
# no GPL Python package ships (hpfeeds is a stub, D-162); Debian packages (Samba) are a separate process and keep their licences
if echo "$inv" | grep -E '^pip ' | grep -iE 'GPL|GNU General'; then fail "a GPL Python package is in the image (see above)"; fi
if echo "$inv" | grep -qi '^pip hpfeeds'; then fail "hpfeeds is in the image, not the stub"; fi
ok "no GPL Python package in the image (hpfeeds is the stub)"
echo "honeypot-check: all checks passed"
