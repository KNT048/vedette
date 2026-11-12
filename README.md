# Vedette

**Know early. Know exactly. Know what to do.**

Vedette is free, open-source software that tells a business, within an hour, when a device or application it uses appears on the list of vulnerabilities **being exploited in the wild**, what it has and where it is exposed, and exactly what to do about it. It does **not** sit in the network path, block traffic or replace your firewall.

*Vedette* (French): a mounted sentry posted ahead of an outpost to raise the alarm early. It watches and warns; it does not fight.

| | |
|---|---|
| Status | Web interface complete on a mock API; backend not started |
| License | Apache-2.0 for Vedette's own code; third-party components keep their own licenses (`THIRD_PARTY_NOTICES.md`) |
| Author | Kien Nguyen, as a personal project |
| Disclaimer | Provided as is, without warranty (Apache-2.0 §7–8). The author is not responsible for how you use it — only scan systems you own and are authorised to scan |

## Try it

```bash
make dev
```

Open http://localhost:5173. On first run choose **Use sample data** to look around, or set it up from scratch.

## Install on a box

For a real box: a fresh **Ubuntu 24.04, Ubuntu 26.04 or Debian 13** (amd64 or arm64) with systemd, at least 4 GB of memory (8 GB recommended), 6 GB of free disk under `/var`, a wired network port, and the free TCP ports **8443** (the interface), **8444** (the sensor link) and **8765** (the MCP server, on the machine's own 127.0.0.1). Run it as root, on a machine that has nothing else of Vedette on it:

```bash
curl -fsSL https://github.com/KNT048/vedette/releases/download/v<version>/install.sh | sudo sh
```

Use the `install.sh` of the release you want (the Releases page of this repository; it carries that release's version and package checksum inside it, which is why you do not get it from the source tree). To read it before running it, download it with `-o install.sh` and run `sudo sh install.sh`. At the end it prints `https://<address of the box>:8443` and a **one-time setup code**; open the address (the certificate is self-signed: accept it once), enter the code and follow the setup wizard.

What it does, in order, and it stops at the first thing it cannot do (a refusal in the first step changes nothing): checks the OS, architecture, systemd, disk, the two ports, that no other Vedette is there and that the clock is set; installs with `apt` the packages Vedette needs that are **missing** (podman, chrony, netplan.io, nftables, iptables, unattended-upgrades and what they depend on); a package that is already installed is not upgraded and an existing chrony configuration is not touched; downloads the `vedette-host` package of that release and refuses it unless its SHA-256 is the one written into the script; writes `/etc/vedette/host.conf` and the container network `vedette-int` (a `172.30.x.0/24` that clashes with nothing on the box); runs `vedette-host -bootstrap`, which checks the signed release (the signing keys are built into `vedette-host`, not into the script) and pulls the signed container images by digest; starts Vedette and waits up to 5 minutes for it to be healthy.

It does **not** touch your network settings. If you want Vedette's **Box network** screen to manage the address of the box, run it with `--network-handover` on a box whose management port is wired and gets its address by DHCP **and whose netplan holds nothing but that one card on DHCP** (no rename, other card, VLAN, lease identifier, name servers or routes): it then hands `netplan` to Vedette (your old file is kept in `/var/lib/vedette-install/netplan-moved`) and applies nothing until the next boot or until you confirm a change in the screen. On a Wi-Fi box, a static address, NetworkManager or a netplan with more in it, it says "Box network is not available on this box" and leaves everything alone.

What leaves the box while it installs (all of it is in `PRIVACY.md`: flow 6 and flow 10): `apt` to your distribution's package mirrors, GitHub (the install files of the release), `ghcr.io` (the signed images), `deb.debian.org` (to build the `scan` image, which needs `nmap`) and, once chrony runs, the time servers of your distribution's chrony configuration (flow 10, NTP). No Vedette data goes anywhere.

Run the same command again to repair (also after a run that stopped half way) or to upgrade the host package; it changes nothing that is already right. To remove Vedette and put the box back as it was (containers, images, units, the packages the installer added that nothing else needs, the IP-forwarding setting and nft tables the container network changed, the users, the data and the key; this cannot be undone):

```bash
sudo sh install.sh --uninstall --yes            # --keep-data keeps /var/lib/vedette*, /etc/vedette and the users
```

Until the first release exists, the script in this repository stops with "not tied to a release". To try the installer before that, see `docs/INSTALL-TEST.md` (a test install signed with throwaway keys; not for customers).

## What leaves your machine

Exactly what `PRIVACY.md` lists. Notably, an **anonymous signal is on by default** (counts of trap touches, connections to bad IPs/domains and devices by type; no names, no IP addresses, no logs). Turn it off under Settings → Privacy.

## Documentation

Product and design documents are in `docs/` (written in Vietnamese for now): `PRODUCT.md`, `USER_STORIES.md`, `MODULES.md`, `ARCHITECTURE.md`, `DATA_PIPELINE.md`, `AI_ASSISTANT.md`, `UPDATES.md`, `ROADMAP.md`, `FRONTEND.md`, `LEGAL.md`, `DECISIONS.md`. The API contract is `api/openapi.json`, generated from the web app's mock (`pnpm --dir web openapi`).

## For AI agents working in this repo

Read `CLAUDE.md` first; rules live in `.claude/rules/`.
