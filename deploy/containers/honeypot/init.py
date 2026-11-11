#!/usr/bin/python3 -I
"""The honeypot container's process 1 (WP-08e, D-162): sets the container up, drops to an unprivileged user, and keeps the traps alive.

Started as the container's root (the unit drops every capability except SETUID, D-162), it does the few things that need it,
then becomes uid 1000 for good (setuid() from root also clears the saved uid and every capability; the check below proves
root cannot be regained), and only then starts anything that touches the network or a byte an attacker sends:

1. /dev/log: Samba's audit module speaks syslog(3), whose path is fixed; /dev is a tmpfs owned by the container's root, so the
   socket can only be made before the drop. The socket's reader is this process (the sink below).
2. log/ (a volume the container writes and core reads, D-89): made group-writable by the owner, so uid 1000 (gid 0) can write it.
3. drop to uid 1000, gid unchanged (0: the group of the volume), no supplementary groups, umask 002.
4. plant the file tokens of config/honeytokens.json in the SMB share (a tmpfs folder), start Samba (only when smb is enabled in
   opencanary.conf) and OpenCanary (twistd, the config found through /etc/opencanaryd -> config/), then read the syslog socket.

The sink turns Samba's audit lines into the one fixed line OpenCanary's smb module parses. Everything in an audit line that the
network chose (the path, user, domain, client name) could carry `|` or `: ` and forge fields or a whole line (the module splits on
`|` and takes the text after the LAST `: `), so the prefix Samba is configured with (smb.conf) holds only values the server decides
(client address, server address, server name, protocol, client OS class, share), and the path, the only free text, has everything
outside printable ASCII, every `|` and every `: ` replaced. A line that does not have exactly that shape is dropped and counted.

If any child exits, the container exits (the unit restarts it): a half-running honeypot must not look healthy.
"""
import json
import os
import re
import selectors
import signal
import socket
import subprocess
import sys
import time

CONF_DIR = "/var/lib/vedette/honeypot/config"
LOG_DIR = "/var/lib/vedette/honeypot/log"
CONF = CONF_DIR + "/opencanary.conf"
TOKENS = CONF_DIR + "/honeytokens.json"
AUDIT = "/tmp/samba-audit.log"  # /var/log/samba-audit.log (the path core writes to opencanary.conf) is a symlink to it
SHARE = "/tmp/share"
SAMBA_DIRS = "/tmp/samba"
UID = 1000
MAX_JSON = 1 << 20
AUDIT_MAX = 1 << 20  # the audit file is a pipe to OpenCanary in memory (tmpfs): replaced when it grows past this
MAX_DGRAM = 4096
PATH_MAX = 200  # modules/honeypot keeps 200 characters of a file name

TOKEN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")  # tokenNameRE of modules/honeypot/personality.go
TOKEN_BODY = b"CONFIDENTIAL - internal use only\r\n"
IPV4 = re.compile(r"^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$")
WORD = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")
AUDIT_MSG = re.compile(r"smbd_audit(?:\[\d+\])?: (.*)\Z", re.S)
OPS = {"connect", "openat"}
CHILD_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/tmp/home", "PYTHONPATH": "/opt/opencanary/lib", "PYTHONDONTWRITEBYTECODE": "1",
             "PYTHONUNBUFFERED": "1", "GIT_PYTHON_REFRESH": "quiet", "LANG": "C.UTF-8"}

dropped = 0


def say(msg):
    print("vedette-hp: " + msg, file=sys.stderr, flush=True)


def die(msg):
    say("fatal: " + msg)
    sys.exit(1)


def read_json(path):
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_JSON + 1)
        if len(data) > MAX_JSON:
            die(path + " is too large")
        v = json.loads(data)
    except (OSError, ValueError) as e:
        die("%s: %s" % (path, e))
    if not isinstance(v, dict):
        die(path + " is not a JSON object")
    return v


def devlog_socket():
    path = "/dev/log"
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    s.bind(path)
    os.chmod(path, 0o666)
    s.setblocking(False)
    return s


def drop_privileges():
    os.setuid(UID)  # from root: real, effective and saved uid, and every capability
    if os.getresuid() != (UID, UID, UID):
        die("uid is %s after the drop" % (os.getresuid(),))
    try:
        os.setuid(0)
    except PermissionError:
        return
    die("root can be regained after the drop")


def clean_path(p):
    p = re.sub(r"[^\x20-\x7e]", "?", p).replace("|", "?").replace(": ", ":?")
    return p[:PATH_MAX]


def audit_line(data):
    """One OpenCanary smb line for one syslog datagram, or None. Pure: the tests drive it with hostile inputs."""
    m = AUDIT_MSG.search(data[:MAX_DGRAM].decode("utf-8", "replace"))
    if not m:
        return None
    f = m.group(1).rstrip("\n").split("|", 8)  # client, server, name, protocol, os class, share | op | status | path
    if len(f) != 9:
        return None
    src, dst, local, ver, arch, share, op, status, path = f
    src, dst = (re.sub(r"^::ffff:", "", x) for x in (src, dst))
    if not (IPV4.match(src) and IPV4.match(dst) and all(WORD.match(x) for x in (local, ver, arch, share))):
        return None
    if op not in OPS or status not in ("ok", "fail"):
        return None
    # Samba writes `openat|ok|<mode>|<absolute path>`: keep the path as the client sees it inside the share (core takes the base name)
    path = re.sub(r"^[a-z]{1,4}\|", "", path, count=1)
    if path == SHARE or path.startswith(SHARE + "/"):
        path = path[len(SHARE):] or "/"
    # the module's fields: user, client, server, client name, share, server name, protocol, os class, (unused), domain, action, status, path
    return "smbd_audit: |%s|%s|%s|%s|%s|%s|%s|||%s|%s|%s\n" % (src, dst, src, share, local, ver, arch, op, status, clean_path(path))


def write_audit(line):
    try:
        if os.stat(AUDIT).st_size > AUDIT_MAX:
            tmp = AUDIT + ".new"
            open(tmp, "wb").close()
            os.replace(tmp, AUDIT)  # a new inode: OpenCanary's watcher reopens it at its end
        with open(AUDIT, "ab") as f:
            f.write(line.encode("ascii"))
    except OSError as e:
        say("audit file: %s" % e)


def plant_tokens(names):
    os.makedirs(SHARE, mode=0o755, exist_ok=True)
    n = 0
    for name in names[:64]:
        if not isinstance(name, str) or not TOKEN_NAME.match(name):
            say("a token name was refused")
            continue
        fd = os.open(os.path.join(SHARE, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
        with os.fdopen(fd, "wb") as f:
            f.write(TOKEN_BODY)
        n += 1
    say("%d file tokens planted" % n)


def spawn(argv, env_extra=None):
    env = dict(CHILD_ENV)
    env.update(env_extra or {})
    return subprocess.Popen(argv, env=env, cwd="/tmp", stdin=subprocess.DEVNULL, close_fds=True)  # noqa: S603 - fixed argv, no shell


def stop(children):
    for c in children:
        if c.poll() is None:
            c.terminate()
    deadline = time.monotonic() + 5
    for c in children:
        try:
            c.wait(max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            c.kill()


def main():
    global dropped
    os.umask(0o022)
    if os.geteuid() != 0:
        die("must start as the container's root (it makes /dev/log and then drops to uid %d)" % UID)
    conf = read_json(CONF)
    tokens = read_json(TOKENS).get("files", [])
    if not isinstance(tokens, list):
        die(TOKENS + ": files is not a list")
    smb_on = conf.get("smb.enabled") is True

    sock = devlog_socket()
    try:
        os.chmod(LOG_DIR, 0o775)  # we own it (podman's :U option) or the unit is wrong: checked below
    except OSError as e:
        say("log dir: %s" % e)
    drop_privileges()
    os.umask(0o002)  # OpenCanary's log files: group-writable (the volume's group is ours), readable by core
    if not os.access(LOG_DIR, os.W_OK | os.X_OK):
        die("%s is not writable by uid %d gid %d" % (LOG_DIR, os.getuid(), os.getgid()))

    for d in ("home", "samba", "samba/lock", "samba/state", "samba/cache", "samba/pid", "samba/private", "samba/ncalrpc"):
        os.makedirs("/tmp/" + d, mode=0o700, exist_ok=True)
    open(AUDIT, "ab").close()  # must exist before OpenCanary starts watching it
    plant_tokens(tokens)

    children = []
    if smb_on:
        children.append(spawn(["/usr/sbin/smbd", "--foreground", "--no-process-group", "--debug-stdout", "--configfile=/etc/samba/smb.conf"]))
    children.append(spawn(["/usr/bin/python3", "-c", "from twisted.scripts.twistd import run; run()", "--nodaemon", "--pidfile=",
                           "--python=/opt/opencanary/lib/bin/opencanary.tac"]))

    def on_term(_sig, _frm):
        stop(children)
        sys.exit(0)

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    say("up: smb=%s, config %s" % (smb_on, CONF))

    sel = selectors.DefaultSelector()
    sel.register(sock, selectors.EVENT_READ)
    while True:
        for _key, _ in sel.select(timeout=1.0):
            for _ in range(100):  # bounded batch, so the children are checked even under a flood
                try:
                    data = sock.recv(MAX_DGRAM)
                except BlockingIOError:
                    break
                line = audit_line(data)
                if line is None:
                    dropped += 1
                    if dropped in (1, 10, 100) or dropped % 1000 == 0:
                        say("%d audit datagrams dropped (not the fixed shape)" % dropped)
                else:
                    write_audit(line)
        for c in children:
            if c.poll() is not None:
                stop(children)
                die("child %s exited with %s" % (c.args[0], c.returncode))


if __name__ == "__main__":
    main()
