#!/usr/bin/env python3
"""Regenerates requirements.txt and requirements-sdist.txt, the hash-locked pip pins of the honeypot image (WP-08e, D-162).

How the lock is made (the only place a pip version of the image is chosen is requirements.in; this script resolves and hashes it):

  podman run --rm -v "$PWD/deploy/containers/honeypot:/w" -w /w "$DEBIAN_IMAGE" bash -c '
      apt-get update -qq && apt-get install -y -qq --no-install-recommends python3-pip python3-setuptools ca-certificates &&
      python3 lock.py'

DEBIAN_IMAGE is the digest of deploy/containers/pins.env, so the resolver sees the same Python (3.13) as the image. The script
1. asks pip for the full dependency set of requirements.in (`pip install --dry-run --report`), markers and Python version included;
2. for every name==version asks the PyPI JSON API (https://pypi.org/pypi/<name>/<version>/json) for the files of that release and
   keeps the SHA-256 of every wheel that can be installed on Debian 13 (CPython 3.13, glibc 2.41) for amd64 AND arm64, and of
   the source archive only when the release has no such wheel (those go to requirements-sdist.txt: pure Python, built at image build
   time, never compiled: the image build checks that the wheel it gets is py3-none-any);
3. refuses a release that has a wheel for one architecture and none for the other (the image is built for both, D-158).

The Containerfile installs with `pip install --require-hashes --no-deps --only-binary=:all:` (pip refuses any file whose hash is not
listed here). Review the diff of requirements.txt like code: a changed hash is a changed artifact.
"""
import json
import re
import subprocess
import sys
import tempfile
import urllib.request

ARCHS = ("x86_64", "aarch64")
MAX_GLIBC_MINOR = 41  # Debian 13 "trixie" ships glibc 2.41
# Resolved but never installed: replaced by hpfeeds_stub.py in the image (hpfeeds is GPL-3 and OpenCanary only imports it, D-162).
STUBBED = {"hpfeeds"}
HERE = __file__.rsplit("/", 1)[0] if "/" in __file__ else "."


def pip_report(requirements_in):
    """The resolved set of requirements_in. Lines ending in "# override" (name==version) are kept out of pip's input, which would refuse
    them against the exact pins of OpenCanary, and replace the version of that name in the result (requirements.in says why)."""
    lines = open(requirements_in).read().splitlines()
    overrides = {}
    for line in lines:
        m = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.]+)\s+#\s*override", line)
        if m:
            overrides[re.sub(r"[-_.]+", "-", m.group(1)).lower()] = m.group(2)
    with tempfile.NamedTemporaryFile("w", suffix=".in") as tmp:
        tmp.write("\n".join(l for l in lines if not l.endswith("# override")) + "\n")
        tmp.flush()
        out = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", "--dry-run", "--ignore-installed", "--quiet",
             "--report", "-", "-r", tmp.name],
            check=True, capture_output=True, text=True, timeout=600).stdout
    resolved = [(i["metadata"]["name"], i["metadata"]["version"]) for i in json.loads(out)["install"]]
    names = {re.sub(r"[-_.]+", "-", n).lower() for n, _ in resolved}
    if not set(overrides) <= names:
        sys.exit("override of a package that is not in the resolved set: %s" % sorted(set(overrides) - names))
    return [(n, overrides.get(re.sub(r"[-_.]+", "-", n).lower(), v)) for n, v in resolved]


def release_files(name, version):
    url = "https://pypi.org/pypi/%s/%s/json" % (name, version)
    with urllib.request.urlopen(url, timeout=60) as r:
        return [u for u in json.load(r)["urls"] if not u.get("yanked")]


def wheel_archs(filename):
    """The set of ARCHS (or {'any'}) a wheel of this file name serves on CPython 3.13 / Debian 13, empty when it serves none."""
    parts = filename[: -len(".whl")].split("-")
    py, abi, plat = parts[-3], parts[-2], parts[-1]
    ok_py = False
    for p in py.split("."):
        if p == "py3":
            ok_py = True
        elif p == "cp313" and abi in ("cp313", "abi3", "none"):
            ok_py = True
        elif re.fullmatch(r"cp3\d+", p) and abi == "abi3" and int(p[3:]) <= 13:
            ok_py = True
    if not ok_py:
        return set()
    archs = set()
    for p in plat.split("."):
        if p == "any":
            return {"any"}
        m = re.fullmatch(r"manylinux(?:_2_(\d+))?(?:1|2010|2014)?_(x86_64|aarch64)", p)
        if m and (m.group(1) is None or int(m.group(1)) <= MAX_GLIBC_MINOR):
            archs.add(m.group(2))
    return archs


def block(name, version, hashes):
    lines = ["%s==%s" % (name, version)] + ["    --hash=sha256:%s" % h for h in sorted(hashes)]
    return " \\\n".join(lines) + "\n"


def main():
    wheels, sdists = [], []
    for name, version in sorted(pip_report(HERE + "/requirements.in"), key=lambda x: x[0].lower()):
        if name.lower() in STUBBED:
            continue
        files = release_files(name, version)
        by_arch = {a: [] for a in ARCHS}
        anyw = []
        for f in files:
            if f["packagetype"] != "bdist_wheel":
                continue
            archs = wheel_archs(f["filename"])
            if archs == {"any"}:
                anyw.append(f)
            for a in archs & set(ARCHS):
                by_arch[a].append(f)
        if anyw or all(by_arch.values()):
            keep = {f["digests"]["sha256"] for f in anyw}
            for a in ARCHS:
                keep |= {f["digests"]["sha256"] for f in by_arch[a]}
            wheels.append(block(name, version, keep))
        elif not any(by_arch.values()):
            src = [f for f in files if f["packagetype"] == "sdist"]
            if not src:
                sys.exit("%s==%s: neither a usable wheel nor a source archive" % (name, version))
            sdists.append(block(name, version, {f["digests"]["sha256"] for f in src}))
        else:
            missing = [a for a in ARCHS if not by_arch[a]]
            sys.exit("%s==%s: no wheel for %s (the image is built for amd64 and arm64)" % (name, version, missing))
    header = ("# GENERATED by lock.py from requirements.in: do not edit by hand (WP-08e, D-162). %s\n")
    with open(HERE + "/requirements.txt", "w") as f:
        f.write(header % "Wheels for CPython 3.13 on Debian 13, amd64 and arm64 (and pure Python).")
        f.write("".join(wheels))
    with open(HERE + "/requirements-sdist.txt", "w") as f:
        f.write(header % "Pure-Python source archives with no wheel on PyPI; built into a py3-none-any wheel by the image build.")
        f.write("".join(sdists))


if __name__ == "__main__":
    main()
