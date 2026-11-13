#!/usr/bin/env bash
# make honeypot-check (WP-08e, D-162): build the honeypot image, run it the way the unit does and check BY EFFECT, not by the exit code of the build:
#   * OpenCanary starts with the files core's own code writes (honeypot.RenderConfig / RenderTokens, through a Go test), and a connection to
#     each trap writes a JSON line into the mounted log/ that modules/honeypot's parser accepts (a Go test runs ParseLine on the log);
#   * every enabled trap is proven: OpenCanary reports it started (its start_mod only logs a module that fails to start), and a client gets the
#     trap's own log type: an SSH password login is 4002 with the default key exchange AND with diffie-hellman-group-exchange only (the start-up fix
#     in init.py, without which the trap crashed before logging the login), RDP 14001, MSSQL 9001, HTTP 3000, SMB 5000; and every service D-467
#     added: HTTPS 3000 on 443 with core's certificate, FTP 2000, Telnet 6002/6001, MySQL 9003/8001, MongoDB 20001, Redis 17001, VNC 12001,
#     Git 16001, HTTP proxy 7001, SMTP banner 18001, TFTP 10001, NTP 11001, SIP 15001; no Twisted traceback;
#   * Samba serves the planted file token, and opening it reaches OpenCanary as a log type 5000 line whose file name is the token and whose source is
#     the real client (a client user name with `|` in it cannot forge another source);
#   * `/vedette honeypot healthcheck` (the unit's HealthCmd) passes;
#   * every process is uid 1000 gid 0 with all five capability sets empty and NoNewPrivs; config/ is read-only, the root is read-only, log/ is writable;
#   * a stop (SIGTERM) ends init.py with exit 0 in under 8 s and no traceback;
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
$c exec "$client" bash -c 'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq --no-install-recommends smbclient python3 openssh-client >/dev/null 2>&1' || fail "installing the test client"
cip=$($c inspect -f '{{(index .NetworkSettings.Networks "'"$net"'").IPAddress}}' "$client")
$c exec "$client" python3 -c '
import socket, struct, sys
ip = sys.argv[1]
s = socket.create_connection((ip, 22), 5); print("ssh:", s.recv(100).decode().strip()); s.close()
for p in ("/", "/index.html"):
    s = socket.create_connection((ip, 80), 5); s.sendall(b"GET " + p.encode() + b" HTTP/1.1\r\nHost: x\r\n\r\n"); print("http", p, s.recv(100).decode().splitlines()[0]); s.close()
# RDP: an X.224 connection request with the mstshash cookie mstsc sends (TPKT + X.224 CR)
cookie = b"Cookie: mstshash=vedette-check-rdp\r\n"
x224 = bytes([6 + len(cookie), 0xE0, 0, 0, 0, 0, 0]) + cookie
s = socket.create_connection((ip, 3389), 5); s.sendall(b"\x03\x00" + struct.pack(">H", 4 + len(x224)) + x224); print("rdp: reply", s.recv(100)[:4].hex()); s.close()
# MSSQL: a TDS LOGIN7 with SQL authentication (user name and password in UTF-16LE, the password obfuscated as MS-TDS 2.2.6.4 says)
user, pw = "vedette-check-mssql".encode("utf-16le"), "x".encode("utf-16le")
pw = bytes((((b << 4) | (b >> 4)) & 0xFF) ^ 0xA5 for b in pw)
hl = 94
ib = [hl, 0, hl, len(user) // 2, hl + len(user), len(pw) // 2] + [hl + len(user) + len(pw), 0] * 6
body = struct.pack("<6I4BlI18H6s6HI", hl + len(user) + len(pw), 0x74000004, 4096, 7, 1, 0, 0, 0, 0, 0, 0, 0x409, *ib, b"\0" * 6, 0, 0, 0, 0, 0, 0, 0) + user + pw
s = socket.create_connection((ip, 1433), 5); s.sendall(struct.pack(">BBHHBB", 0x10, 1, 8 + len(body), 0, 1, 0) + body); print("mssql: reply type", s.recv(100)[:1].hex()); s.close()
# D-467: every service added in B3, once each, the way a scanner or a script tries it
import ssl, time
def tcp(port):
    s = socket.create_connection((ip, port), 5); s.settimeout(5); return s
def rd(s):
    try:
        return s.recv(4096)
    except OSError:
        return b""
c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
t = c.wrap_socket(tcp(443)); der = t.getpeercert(binary_form=True)
t.sendall(b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n"); print("https:", t.recv(100).decode().splitlines()[0], "cert", "nas-archive" in der.decode("latin1")); t.close()
s = tcp(21); print("ftp:", rd(s).decode().strip()); s.sendall(b"USER vedette-check-ftp\r\n"); rd(s); s.sendall(b"PASS x\r\n"); print("ftp: reply", rd(s).decode().strip()); s.close()
def telnet_talk(s, send=None):  # answers the option negotiation as a real client does: WILL x -> DO x, DO x -> WONT x, WONT x -> DONT x
    if send:
        s.sendall(send)
    s.settimeout(0.7)
    got = b""
    while True:
        try:
            d = s.recv(4096)
        except OSError:
            break
        if not d:
            break
        got += d
        i = d.find(b"\xff")
        while 0 <= i and i + 2 < len(d):
            reply = {251: b"\xfd", 253: b"\xfc", 252: b"\xfe"}.get(d[i + 1])
            if reply:
                s.sendall(b"\xff" + reply + d[i + 2:i + 3])
            i = d.find(b"\xff", i + 3)
    return got
s = tcp(23); print("telnet:", b"Username:" in telnet_talk(s)); telnet_talk(s, b"vedette-check-telnet\r\n"); print("telnet: reply", telnet_talk(s, b"x\r\n").strip()[-30:]); s.close()
s = tcp(3306); print("mysql:", rd(s)[5:28]); b = struct.pack("<IIB", 0x000fa685, 1 << 24, 33) + b"\x00" * 23 + b"vedette-check-mysql\x00\x00"
s.sendall(struct.pack("<I", len(b))[:3] + b"\x01" + b); print("mysql: reply", rd(s)[4:5].hex()); s.close()
def bson(fields):
    out = b""
    for k, v in fields:
        kb = k.encode() + b"\x00"
        if isinstance(v, int):
            out += b"\x10" + kb + struct.pack("<i", v)
        elif isinstance(v, str):
            vb = v.encode() + b"\x00"; out += b"\x02" + kb + struct.pack("<i", len(vb)) + vb
        else:
            out += b"\x05" + kb + struct.pack("<i", len(v)) + b"\x00" + v
    return struct.pack("<i", len(out) + 5) + out + b"\x00"
q = bson([("saslStart", 1), ("mechanism", "SCRAM-SHA-1"), ("payload", b"n,,n=vedette-check-mongodb,r=abc")])
m = struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, -1) + q
s = tcp(27017); s.sendall(struct.pack("<iiii", 16 + len(m), 1, 0, 2004) + m); print("mongodb: reply", b"AuthenticationFailed" in rd(s)); s.close()
s = tcp(6379); s.sendall(b"CONFIG GET *\r\n"); print("redis:", rd(s).decode().strip()); s.close()
s = tcp(5900); print("vnc:", rd(s).decode().strip()); s.sendall(b"RFB 003.008\n"); rd(s); s.sendall(b"\x02"); rd(s); s.sendall(b"\x00" * 16); print("vnc: reply", rd(s)[8:]); s.close()
g = b"git-upload-pack /vedette-check.git\x00host=x\x00"
s = tcp(9418); s.sendall(b"%04x" % (len(g) + 4) + g); print("git:", rd(s).decode(errors="replace").strip()); s.close()
s = tcp(8080); s.sendall(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic dmVkZXR0ZS1jaGVjay1wcm94eTp4\r\n\r\n"); print("httpproxy:", rd(s).decode(errors="replace").splitlines()[0]); s.close()
s = tcp(25); print("smtp:", rd(s).decode().strip()); s.close()
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.sendto(b"\x00\x01vedette-check.cfg\x00octet\x00", (ip, 69)); u.sendto(b"\x17\x00\x03\x2a" + b"\x00" * 4, (ip, 123))
u.sendto(b"OPTIONS sip:100@" + ip.encode() + b" SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\nFrom: <sip:check@x>;tag=1\r\nTo: <sip:100@x>\r\nCall-ID: 1@x\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n", (ip, 5060))
print("udp: sent tftp, ntp monlist, sip")
' "$ip" > "$work/client.out"
grep -q 'http / HTTP/1.1 302' "$work/client.out" || fail "GET / on the web trap: $(cat "$work/client.out")"
grep -q 'http /index.html HTTP/1.1 200' "$work/client.out" || fail "GET /index.html on the web trap: $(cat "$work/client.out")"
grep -q '^rdp: reply 0300' "$work/client.out" || fail "the RDP trap did not answer the connection request: $(cat "$work/client.out")"
grep -q '^mssql: reply type 04$' "$work/client.out" || fail "the MSSQL trap did not answer LOGIN7: $(cat "$work/client.out")"
for want_line in '^https: HTTP/1.1 200 OK cert True$' '^ftp: 220 ' '^ftp: reply 530' '^telnet: True$' '^mysql: ' '^mongodb: reply True$' '^redis: -NOAUTH' '^vnc: RFB 003.008$' \
	'^git: .*ERR no such repository' '^httpproxy: HTTP/1.1 407' '^smtp: 220 '; do
	grep -q "$want_line" "$work/client.out" || fail "a D-467 trap did not answer ($want_line): $(cat "$work/client.out")"
done
sed 's/^/    /' "$work/client.out"
# SSH: a real OpenSSH client logs in with a password (SSH_ASKPASS, no terminal), once with its default key exchange and once offering only
# diffie-hellman-group-exchange-sha256 (OpenCanary 0.9.10 crashed there before the login was logged; init.py's start-up fix). The login fails by
# design (the trap accepts nobody); what counts is the 4002 line with this user name, checked in step 5.
$c exec "$client" sh -c 'printf "#!/bin/sh\necho vedette-check-password\n" > /tmp/askpass && chmod 0755 /tmp/askpass'
for kex in default gex; do
	opt=()
	[ "$kex" = gex ] && opt=(-o KexAlgorithms=diffie-hellman-group-exchange-sha256)
	sshout=$($c exec -e SSH_ASKPASS=/tmp/askpass -e SSH_ASKPASS_REQUIRE=force "$client" timeout 30 ssh -v -n "${opt[@]}" -o StrictHostKeyChecking=no \
		-o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PreferredAuthentications=password -o NumberOfPasswordPrompts=1 \
		-o ConnectTimeout=10 "vedette-check-ssh-$kex@$ip" true 2>&1 || true)
	echo "    ssh ($kex): $(echo "$sshout" | grep -E 'kex: algorithm:|Permission denied|Connection closed|Unable to negotiate|Authentications that can continue' | head -3 | tr '\n' ' ')"
done
out=$($c exec "$client" smbclient -N "//$ip/Shared" -c 'ls; get passwords.txt /dev/null' 2>&1) || fail "smbclient: $out"
echo "$out" | grep -q 'passwords.txt' || fail "the share does not list the planted token: $out"
ok "SMB share lists the planted token; SSH, HTTP, RDP, MSSQL and every D-467 TCP trap answered (HTTPS with core's certificate)"
# a client user name carrying `|` and a fake address reaches no field of the audit line
$c exec "$client" smbclient -U 'x|6.6.6.6|7.7.7.7%y' "//$ip/Shared" -c 'get "Q4 payroll.xlsx" /dev/null' >/dev/null 2>&1 || true

# 5. the lines in the mounted log/
want=4000,4002,3000,5000,14001,9001,2000,6001,6002,7001,8001,9003,10001,11001,12001,15001,16001,17001,18001,20001
# what each trap enabled in opencanary.conf must leave in the log: OpenCanary's own start line for its module (start_mod logs a failure and
# goes on, so a trap that did not start is otherwise silent) and the hit of the client above. Prints what is missing, nothing when all is there.
missing() {
	python3 -I -c '
import json, sys
conf, log = json.load(open(sys.argv[1])), []
try:
    log = [json.loads(l) for l in open(sys.argv[2]) if l.strip()]
except OSError:
    pass
started = " ".join(str(d.get("logdata")) for d in log if d.get("logtype", 0) < 2000)
def hit(t, user=None):
    return any(d["logtype"] == t and (user is None or user in (d["logdata"].get("USERNAME"), d["logdata"].get("UserName"), d["logdata"].get("username"))) for d in log)
need = {
    "ssh": ["Added service from class CanarySSH ", (4000, None), (4002, "vedette-check-ssh-default"), (4002, "vedette-check-ssh-gex")],
    "http": ["Added service from class CanaryHTTP ", (3000, None)],
    "rdp": ["Added service from class CanaryRDP ", (14001, "vedette-check-rdp")],
    "mssql": ["Added service from class MSSQL ", (9001, "vedette-check-mssql")],
    "smb": ["Ran startYourEngines on class CanarySamba ", (5000, None)],
    "https": ["Added service from class CanaryHTTPS ", (3000, None)],
    "ftp": ["Added service from class CanaryFTP ", (2000, "vedette-check-ftp")],
    "telnet": ["Added service from class Telnet ", (6002, None), (6001, "vedette-check-telnet")],
    "mysql": ["Added service from class CanaryMySQL ", (9003, None), (8001, "vedette-check-mysql")],
    "mongodb": ["Added service from class CanaryMongoDB ", (20001, "vedette-check-mongodb")],
    "redis": ["Added service from class CanaryRedis ", (17001, None)],
    "vnc": ["Added service from class CanaryVNC ", (12001, None)],
    "git": ["Added service from class CanaryGit ", (16001, None)],
    "httpproxy": ["Added service from class HTTPProxy ", (7001, "vedette-check-proxy")],
    "tcpbanner": ["Added service from class CanaryTCPBanner ", (18001, None)],
    "tftp": ["Added service from class CanaryTftp ", (10001, None)],
    "ntp": ["Added service from class CanaryNtp ", (11001, None)],
    "sip": ["Added service from class CanarySIP ", (15001, None)],
}
for svc, items in need.items():
    if conf.get(svc + ".enabled") is not True:
        continue
    for it in items:
        if isinstance(it, str):
            if it not in started:
                print("%s: no start line %r" % (svc, it.strip()))
        elif not hit(*it):
            print("%s: no log type %d%s" % (svc, it[0], " for user " + it[1] if it[1] else ""))
' "$work/config/opencanary.conf" "$work/log/opencanary.jsonl"
}
for _ in $(seq 1 30); do
	snap
	n=$(grep -c '"logtype": 5000' "$work/log/opencanary.jsonl" 2>/dev/null || true)
	[ -z "$(missing)" ] && [ "${n:-0}" -ge 2 ] && break
	sleep 1
done
snap
[ -s "$work/log/opencanary.jsonl" ] || fail "no opencanary.jsonl in the mounted log/ (read through a second container, uid 10001, read-only)"
gone=$(missing)
[ -z "$gone" ] || fail "a trap enabled in opencanary.conf is not proven: $(echo "$gone" | tr '\n' ';')"
# OpenCanary's start_mod swallows a module that fails to start; Twisted logs a crash inside a protocol (the group-exchange bug) and goes on
bad=$({ $c logs "$name" 2>&1; cat "$work/log/opencanary.jsonl"; } | grep -E 'Failed to (add service|instantiate|run startYourEngines|load class)|does not have any required starting method|Unhandled Error|Traceback' | cut -c1-300 || true)
[ -z "$bad" ] || fail "OpenCanary reported a failure: $bad"
ok "every enabled trap started and logged its client: SSH 4002 with the default key exchange and with group exchange only, RDP 14001, MSSQL 9001, HTTP 3000, SMB 5000, and each D-467 service; no start failure, no traceback"
python3 -I -c '
import json, sys
for l in open(sys.argv[1]):
    d = json.loads(l)
    if d["logtype"] >= 2000:
        x = d["logdata"]
        print("    log: type=%d src=%s dst=%s:%s %s" % (d["logtype"], d["src_host"], d["dst_host"], d["dst_port"], {k: x[k] for k in ("AUDITACTION", "FILENAME", "STATUS", "PATH", "USERAGENT", "USERNAME", "UserName") if k in x}))
' "$work/log/opencanary.jsonl"
smb_lines=$(grep '"logtype": 5000' "$work/log/opencanary.jsonl")
case "$smb_lines" in *'"FILENAME": "/passwords.txt"'*) ;; *) fail "no SMB hit for passwords.txt" ;; esac
case "$smb_lines" in *'"FILENAME": "/Q4 payroll.xlsx"'*) ;; *) fail "no SMB hit for the second token" ;; esac
grep '"logtype": 5000' "$work/log/opencanary.jsonl" | grep -v "\"src_host\": \"$cip\"" | grep -q . && fail "an SMB line whose source is not the client $cip"
grep -q '6\.6\.6\.6' "$work/log/opencanary.jsonl" && fail "a forged source address reached the log"
ok "log/opencanary.jsonl holds log types $want, both file tokens, every SMB source is the client $cip, no forged address"
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

# 5c. a normal stop (SIGTERM, what the unit's stop sends) ends init.py with exit 0 well within podman's 10 s and without a traceback, so the
# unit ends inactive, not failed. A rootless run has no AppArmor: the refused signal of Ubuntu 24.04 is covered by TestHoneypotInitStops*.
t0=$(date +%s)
$c stop -t 10 "$name" >/dev/null
took=$(($(date +%s) - t0))
code=$($c inspect -f '{{.State.ExitCode}}' "$name")
[ "$code" = 0 ] || fail "init.py exited $code on SIGTERM, want 0"
[ "$took" -lt 8 ] || fail "the stop took $took s (init.py gives its children at most 5 s; podman kills at 10 s)"
$c logs "$name" 2>&1 | grep -q 'vedette-hp: stopped on signal 15' || fail "init.py did not report its stop"
if $c logs "$name" 2>&1 | grep -q 'Traceback'; then fail "a traceback on stop"; fi
ok "a stop (SIGTERM) ends init.py with exit 0 in $took s"

# 6. size and contents
$c image inspect "$img" --format 'honeypot image: {{.Size}} bytes, user {{.Config.User}}, arch {{.Architecture}}'
inv=$($c run --rm --entrypoint /bin/cat "$img" /usr/share/vedette/honeypot-inventory.txt)
echo "$inv" | awk '{print $1}' | sort | uniq -c | sed 's/^/    inventory: /'
# no GPL Python package ships (hpfeeds is a stub, D-162); Debian packages (Samba) are a separate process and keep their licences
if echo "$inv" | grep -E '^pip ' | grep -iE 'GPL|GNU General'; then fail "a GPL Python package is in the image (see above)"; fi
if echo "$inv" | grep -qi '^pip hpfeeds'; then fail "hpfeeds is in the image, not the stub"; fi
ok "no GPL Python package in the image (hpfeeds is the stub)"
echo "honeypot-check: all checks passed"
