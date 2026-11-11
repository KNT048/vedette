#!/usr/bin/python3 -I
"""The honeypot container's process 1 (WP-08e, D-162): sets the container up and keeps the traps alive. It runs as the image's own user,
uid 1000 gid 0, from the first instruction: no root, no capability (the unit adds none), nothing to drop.

1. log/ (a volume the container writes and core reads, D-89): podman's `:U` gives it to this user; the mode is made 0755 so core, which
   reads through the "other" bits, can list it.
2. plant the file tokens of config/honeytokens.json in the SMB share (a tmpfs folder), start Samba (only when smb is enabled in
   opencanary.conf) and OpenCanary (twistd, the config found through /etc/opencanaryd -> config/).
3. read smbd's standard output. Samba's audit module is told not to use syslog (`full_audit:syslog = false`), so its audit lines are
   printed on stdout, among Samba's own few log lines. init.py writes smb.conf's include file at start with a fresh random token as the
   first field of the audit prefix: only a line that begins with that token is an audit line, so nothing a client can make Samba print
   elsewhere (a user name with a newline in it, say) can pass for one. The line is then turned into the one fixed line OpenCanary's smb
   module parses.

Everything in an audit line that the network chose (the path) could carry `|` or `: ` and forge fields or a whole line (the module splits on `|`
and takes the text after the LAST `: `), so the prefix holds only values the server decides (client address, server address, server name,
protocol, client OS class, share), and the path, the only free text, has everything outside printable ASCII, every `|` and every `: ` replaced.
A line that does not have exactly that shape is dropped and counted.

If any child exits, the container exits (the unit restarts it): a half-running honeypot must not look healthy.
"""
import json
import os
import re
import secrets
import selectors
import signal
import subprocess
import sys
import time

CONF_DIR = "/var/lib/vedette/honeypot/config"
LOG_DIR = "/var/lib/vedette/honeypot/log"
CONF = CONF_DIR + "/opencanary.conf"
TOKENS = CONF_DIR + "/honeytokens.json"
AUDIT = "/tmp/samba-audit.log"  # /var/log/samba-audit.log (the path core writes to opencanary.conf) is a symlink to it
AUDIT_CONF = "/tmp/samba/audit.conf"  # included by smb.conf: the prefix with this run's token
AUDIT_FIELDS = "%I|%i|%L|%R|%a|%S"  # client address, server address, server name, protocol, client OS class, share: all decided by the server
SHARE = "/tmp/share"
UID = 1000
MAX_JSON = 1 << 20
AUDIT_MAX = 1 << 20  # the audit file is a pipe to OpenCanary in memory (tmpfs): replaced when it grows past this
MAX_LINE = 8192  # a longer line of smbd's output is dropped
PATH_MAX = 200  # modules/honeypot keeps 200 characters of a file name

TOKEN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")  # tokenNameRE of modules/honeypot/personality.go
TOKEN_BODY = b"CONFIDENTIAL - internal use only\r\n"
IPV4 = re.compile(r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}")
WORD = re.compile(r"[A-Za-z0-9_.-]{1,40}")
NONCE = re.compile(r"[0-9a-f]{32}")
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


def clean_path(p):
    p = re.sub(r"[^\x20-\x7e]", "?", p).replace("|", "?").replace(": ", ":?")
    return p[:PATH_MAX]


def audit_line(line, nonce):
    """One OpenCanary smb line for one line of smbd's output, or None. Pure: the tests drive it with hostile inputs."""
    if len(line) > MAX_LINE or not NONCE.fullmatch(nonce) or not line.startswith(nonce + "|"):
        return None
    f = line[len(nonce) + 1:].rstrip("\n").split("|", 8)  # client, server, name, protocol, os class, share | op | status | path
    if len(f) != 9:
        return None
    src, dst, local, ver, arch, share, op, status, path = f
    src, dst = (re.sub(r"^::ffff:", "", x) for x in (src, dst))
    if not (IPV4.fullmatch(src) and IPV4.fullmatch(dst) and all(WORD.fullmatch(x) for x in (local, ver, arch, share))):
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


def spawn(argv, stdout=None):
    # cwd is the root of the (read-only) image, so python's sys.path[0] for `-c` is not a folder this user can write
    return subprocess.Popen(argv, env=dict(CHILD_ENV), cwd="/", stdin=subprocess.DEVNULL, stdout=stdout,
                            stderr=subprocess.STDOUT if stdout else None, close_fds=True)  # noqa: S603 - fixed argv, no shell


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
    if os.geteuid() == 0:
        die("must not run as root: the image's user is %d:0" % UID)
    conf = read_json(CONF)
    tokens = read_json(TOKENS).get("files", [])
    if not isinstance(tokens, list):
        die(TOKENS + ": files is not a list")
    smb_on = conf.get("smb.enabled") is True

    try:
        os.chmod(LOG_DIR, 0o755)  # we own it (podman's :U option); core reads it through the "other" bits
    except OSError as e:
        say("log dir: %s" % e)
    if not os.access(LOG_DIR, os.W_OK | os.X_OK):
        die("%s is not writable by uid %d gid %d" % (LOG_DIR, os.getuid(), os.getgid()))

    for d in ("home", "samba", "samba/lock", "samba/state", "samba/cache", "samba/pid", "samba/private", "samba/ncalrpc"):
        os.makedirs("/tmp/" + d, mode=0o700, exist_ok=True)
    nonce = secrets.token_hex(16)
    with open(AUDIT_CONF, "w", encoding="ascii") as f:
        f.write("full_audit:prefix = %s|%s\n" % (nonce, AUDIT_FIELDS))  # parameters only: smb.conf includes it inside [global]
    os.chmod(AUDIT_CONF, 0o600)
    open(AUDIT, "ab").close()  # must exist before OpenCanary starts watching it
    plant_tokens(tokens)

    children = []
    smbd = None
    if smb_on:
        smbd = spawn(["/usr/sbin/smbd", "--foreground", "--no-process-group", "--debug-stdout", "--configfile=/etc/samba/smb.conf"], stdout=subprocess.PIPE)
        os.set_blocking(smbd.stdout.fileno(), False)
        children.append(smbd)
    children.append(spawn(["/usr/bin/python3", "-c", "from twisted.scripts.twistd import run; run()", "--nodaemon", "--pidfile=",
                           "--python=/opt/opencanary/lib/bin/opencanary.tac"]))

    def on_term(_sig, _frm):
        stop(children)
        sys.exit(0)

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    say("up: smb=%s, config %s" % (smb_on, CONF))

    sel = selectors.DefaultSelector()
    buf = b""
    skipping = False  # inside a line longer than MAX_LINE: dropped up to its newline
    if smbd:
        sel.register(smbd.stdout, selectors.EVENT_READ)
    while True:
        for _key, _ in sel.select(timeout=1.0):
            try:
                data = os.read(smbd.stdout.fileno(), 65536)
            except BlockingIOError:
                continue
            if not data:
                sel.unregister(smbd.stdout)  # smbd closed its output: the child check below ends the container
                continue
            buf += data
            while True:
                nl = buf.find(b"\n")
                if nl < 0:
                    if len(buf) > MAX_LINE:  # an endless line: keep nothing of it
                        buf, skipping = b"", True
                    break
                raw, buf = buf[:nl], buf[nl + 1:]
                if skipping:
                    skipping = False
                    continue
                text = raw.decode("utf-8", "replace")
                line = audit_line(text, nonce)
                if line is not None:
                    write_audit(line)
                elif not text.startswith(nonce):
                    say("smbd: " + re.sub(r"[^\x20-\x7e]", "?", text)[:300])  # Samba's own log line, made safe to print
                else:
                    dropped += 1  # begins with our token but is not the fixed shape
                    if dropped in (1, 10, 100) or dropped % 1000 == 0:
                        say("%d audit lines dropped (not the fixed shape)" % dropped)
        for c in children:
            if c.poll() is not None:
                stop(children)
                die("child %s exited with %s" % (c.args[0], c.returncode))


if __name__ == "__main__":
    main()
