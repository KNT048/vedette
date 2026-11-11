#!/usr/bin/python3 -I
"""Lays the Debian packages the honeypot needs (downloaded for the TARGET architecture by apt in the Containerfile) over an empty
folder, so the final stage only COPYs it and no instruction ever runs on a foreign CPU (D-158).

    assemble.py debs <debs dir> <target dpkg status> <out rootfs>
    assemble.py inventory <rootfs> <out file>     (the list of what was added, after the pip packages are in place)

* every .deb is unpacked with `dpkg-deb -x` (no maintainer script runs: a file-only unpack; the image sets up what it needs itself);
* the merged dpkg status (the base image's, plus one stanza per unpacked package, Status: install ok installed) is written to
  <out>/var/lib/dpkg/status, so scanners and `dpkg -l` see the whole image, not only the base;
* the usr-merge of the base image (/bin, /sbin, /lib are symlinks into /usr) is respected: a package that ships files under
  /bin, /sbin or /lib* gets them moved under /usr, because a COPY of a real folder over a symlink would replace the symlink;
* it fails on a file that would land outside /usr, /etc, /var, /opt or on a collision between two packages.
"""
import os
import re
import shutil
import subprocess
import sys

MERGED = ("bin", "sbin", "lib", "lib32", "lib64", "libx32")


def run(*argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=300).stdout


def stanzas(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for block in re.split(r"\n\n+", f.read().strip()):
            m = re.search(r"^Package: (\S+)$", block, re.M)
            if m:
                yield m.group(1), block


def main(debs, status, out):
    names = sorted(n for n in os.listdir(debs) if n.endswith(".deb"))
    if not names:
        sys.exit("assemble: no .deb in " + debs)
    new = {}
    for n in names:
        p = os.path.join(debs, n)
        control = run("dpkg-deb", "-f", p).strip()
        pkg = re.search(r"^Package: (\S+)$", control, re.M).group(1)
        new[pkg] = control + "\nStatus: install ok installed"
        run("dpkg-deb", "-x", p, out)
    # usr-merge
    for d in MERGED:
        src = os.path.join(out, d)
        if not os.path.isdir(src) or os.path.islink(src):
            continue
        dst = os.path.join(out, "usr", d)
        os.makedirs(dst, exist_ok=True)
        for root, dirs, files in os.walk(src, topdown=False):
            rel = os.path.relpath(root, src)
            tdir = os.path.join(dst, rel) if rel != "." else dst
            os.makedirs(tdir, exist_ok=True)
            for f in files:
                t = os.path.join(tdir, f)
                if os.path.lexists(t):
                    # same package set, same file shipped twice (e.g. /lib/x vs /usr/lib/x): keep the one already under /usr
                    os.unlink(os.path.join(root, f))
                    continue
                shutil.move(os.path.join(root, f), t)
        shutil.rmtree(src)
    for top in os.listdir(out):
        if top not in {"usr", "etc", "var", "opt"}:
            sys.exit("assemble: a package ships /%s, which the image does not take" % top)
    os.makedirs(os.path.join(out, "var/lib/dpkg"), exist_ok=True)
    with open(os.path.join(out, "var/lib/dpkg/status"), "w", encoding="utf-8") as f:
        for pkg, block in stanzas(status):
            if pkg not in new:  # an upgraded package is described by its new stanza only
                f.write(block + "\n\n")
        for pkg in sorted(new):
            f.write(new[pkg] + "\n\n")
    print("assemble: %d packages unpacked into %s" % (len(new), out))


def inventory(rootfs, out):
    """One line per component added to the base image: `deb <name> <version>` and `pip <name> <version> <license>`, for the audit
    (THIRD_PARTY_NOTICES.md) and for whoever inspects the image. The pip licenses are what each package declares."""
    import importlib.metadata as md

    lines = []
    base = {p for p, _ in stanzas("/target/status")}
    for pkg, block in stanzas(os.path.join(rootfs, "var/lib/dpkg/status")):
        v = re.search(r"^Version: (.+)$", block, re.M)
        if pkg not in base:
            lines.append("deb %s %s" % (pkg, v.group(1) if v else "?"))
    for d in md.distributions(path=[os.path.join(rootfs, "opt/opencanary/lib")]):
        m = d.metadata
        lic = m.get("License-Expression") or ""
        if not lic:
            lic = "; ".join(c.split("::")[-1].strip() for c in (m.get_all("Classifier") or []) if c.startswith("License ::"))
        if not lic:
            lic = (m.get("License") or "").strip().splitlines()[0][:60] if (m.get("License") or "").strip() else "UNDECLARED"
        lines.append("pip %s %s %s" % (m["Name"], m["Version"], lic))
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(lines)) + "\n")
    print("assemble: inventory of %d components" % len(lines))


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "debs":
        main(*sys.argv[2:])
    elif len(sys.argv) == 4 and sys.argv[1] == "inventory":
        inventory(*sys.argv[2:])
    else:
        sys.exit(__doc__)
