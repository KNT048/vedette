# Install Vedette on your own Docker or Podman (container-only)

For the person who already runs Docker or Podman and wants Vedette on it, without giving a machine to the Vedette installer. You get the same program as the appliance, run as containers from Docker Compose. You do not get the helper that manages the machine itself (`vedette-host`), so a few things stay with you. They are listed below; each of those screens in Vedette also says so.

Decision and plan: D-168, `docs/plans/2026-11-11-wp08m-container-only.md`. The appliance install is `install.sh` (`docs/DEPLOYMENT.md` section 8).

## What you get, and what stays with you

| | Container-only | Appliance (`install.sh`) |
|---|---|---|
| Web page, users, feeds, inventory (by hand or import), findings, notifications, AI (your key), osquery, response | yes | yes |
| Syslog receiver | yes, add `compose.syslog.yaml` | yes |
| Passive sensor (SPAN) and scan worker | yes, add `compose.sensors.yaml`: Linux, run as root (the sensor is uid 0 with only `NET_RAW`), you prepare the card | yes, set up in the page |
| Honeypot (traps) | **no** | yes |
| Nmap in the scan worker | **no** (nuclei only) | yes |
| Operating system updates, reboot | **you**, on your machine | in the page |
| Box network (card, SPAN, extra IP, NTP) | **you**, on your machine | in the page |
| Updating Vedette | **you** run `pull` and `up` (below) | in the page, in batches, with rollback |
| Backup | **you** back up the Docker volume (below) | snapshots and rotation by the helper |
| "This box" in the device list | present, without a package list | with the package list |

## What you need

- Docker Engine with Compose v2 (`docker compose`), or Podman with `podman compose` and a compose v2 provider (`podman compose version` names it). Tested here: Docker Engine 29.1.3 with Compose 2.40.3, Podman 5.7.0 with that provider. Older versions are not claimed to work until the lab matrix says so; Docker before 28 also let neighbours on your LAN reach ports published on `127.0.0.1` (here 8444, which is mutual TLS).
- Linux, macOS or Windows (WSL2). Docker Desktop on macOS and Windows has no host network, so there you get the web page and the modules that need no real network card, not the sensors.
- Rootless Docker or Podman: the web page and everything that is not a sensor. A rootless setup cannot publish port 514, cannot read a real network card from a container, and may show every syslog sender as one address.
- About 4 CPU cores and 8 GB of memory for a network of up to 1,000 devices (`docs/DEPLOYMENT.md` section 4). Core is limited to 2 GB, the sensor to 512 MB, the scan worker to 1 GB.
- For the sensors: a wired card on a switch port that mirrors traffic (SPAN), set promiscuous with no IP address, before you start. Vedette cannot do that for you here.

## 1. Get the files and check them

A release will publish `compose.yaml`, `compose.sensors.yaml`, `compose.syslog.yaml` and `vedette.env` next to its other files, each with a minisign signature, and the container images at `ghcr.io/knt048/vedette-core`, `-sensor` and `-scan`, signed with cosign. The release builder fills the image lines of `vedette.env` with the digest of each image. Until the first release exists (WP-08k) take the files from `deploy/compose/container-only/` of the repository and use images you built yourself (`make core-image sensor-image scan-base-image`, tagged `localhost/vedette-core:dev`, `localhost/vedette-sensor:dev` and `localhost/vedette-scan-base:dev`).

Check a downloaded release:

```sh
minisign -Vm vedette.env -p vedette.pub          # and the same for each compose file
cosign verify --key cosign.pub ghcr.io/knt048/vedette-core@sha256:<the digest in vedette.env>
```

The public keys will be on the release page and in the repository (WP-08k: they do not exist yet). The verifier of the appliance does the same two checks for you (`docs/DEPLOYMENT.md` section 5).

## 2. Say where it lives

Open `vedette.env` and fill two lines. In the repository copy the three image lines are empty on purpose; a release fills them.

```sh
VEDETTE_BIND_IP=192.168.10.5        # the address of THIS machine the web page is served on (127.0.0.1 to try it from this machine only)
VEDETTE_HOSTS=192.168.10.5          # the name or address you type in the browser; comma separated for several
```

Why two: Docker's `-p` opens the port itself, around UFW and similar tools: UFW rules do not apply to 8443 or 514 even on the address you name. So the compose file never publishes on all addresses (do not set `0.0.0.0` or `::`), and to limit *who* may connect, put the rule in Docker's `DOCKER-USER` chain or on your network firewall. And Vedette answers only to the names it was told (`VEDETTE_HOSTS`), which also go in its certificate; any other name gets `421`, a protection against DNS rebinding. Without `VEDETTE_BIND_IP` or `VEDETTE_HOSTS`, or with an empty image line, compose refuses to start and says which one.

Compose does not read `vedette.env` by itself (it reads only a file called `.env`), so every command carries `--env-file vedette.env`. A `VEDETTE_*` variable exported in your shell wins over the file: unset it if the page answers on an address you did not write there.

## 3. Start, and sign in the first time

```sh
docker compose --env-file vedette.env up -d          # or: podman compose --env-file vedette.env up -d
docker compose --env-file vedette.env ps             # core is "healthy" within about a minute
docker logs vedette-core 2>&1 | grep setup_code      # podman logs vedette-core ...
```

The log line holds the one-time setup code (`"setup_code":"..."`). It is printed again at every start while setup is open and stops when the first administrator exists. Open `https://<VEDETTE_HOSTS>:8443`, enter the code, and follow the setup. The certificate is self-signed and made by the box on first start, so your browser warns once; it is kept in the data volume. Opening the page by a name or address that is not in `VEDETTE_HOSTS` shows "This address is not one Vedette answers to": use the one you set, or change the line and run `up -d` again.

Check from another machine that only what you meant is open (`nmap` is yours to run on your own network): port 8443 on `VEDETTE_BIND_IP` and nothing else; port 8444 is on `127.0.0.1` only.

## 4. Add the sensors, or the syslog receiver (optional)

```sh
# Passive sensor and scan worker (Linux, Docker or Podman as root; not rootless, not Docker Desktop)
docker compose --env-file vedette.env -f compose.yaml -f compose.sensors.yaml up -d
# Syslog from your devices (UDP and TCP 514 on VEDETTE_BIND_IP)
docker compose --env-file vedette.env -f compose.yaml -f compose.syslog.yaml up -d
```

Keep the same `-f` list on every later command (`ps`, `down`, `pull`, `up`), or compose treats the other containers as strays. Then switch the modules on in Settings → Modules. The sensor runs as uid 0 with only `NET_RAW` (Docker gives an added capability only to root; Podman gives it to any user), read-only, on the host network; the scan worker runs as uid 65532 with no capability at all (there is no nmap here). The sensor reads the card you prepared; choose it under Sensors once the sensor has reported (the list is what the sensor sees).

## 5. Update, and check what you run

The page will show that a new version exists and the two blocks below (the page part waits for the update check of core and for the release keys, WP-08k). Until then read the release page.

```sh
curl -fLO <the vedette.env asset of the release page>            # keep the old one for the way back
minisign -Vm vedette.env -p vedette.pub
cosign verify --key cosign.pub ghcr.io/knt048/vedette-core@sha256:<digest>            # and -sensor, -scan
docker compose --env-file vedette.env pull
docker compose --env-file vedette.env up -d
```

To go back, put the old `vedette.env` back and run `pull` and `up -d` again. A version that changes the database may not be able to go back: the release notes say so; back up first.

## 6. Back up, stop, remove

Everything Vedette keeps, including the key that unlocks its secrets, is in the Docker volume `vedette_data` (the two small `creds-*` volumes hold the sensor credentials; they are rebuilt only if core does so, which the lab has not proved, so back them up the same way if you run sensors). There is no snapshot made by a helper in this install, so you copy the volume yourself, with core stopped, and keep the copy as safe as a password:

```sh
docker compose --env-file vedette.env stop core
docker run --rm --network none -v vedette_data:/data:ro -v "$PWD":/backup \
  docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 \
  sh -c 'umask 077 && tar czf /backup/vedette-data.tgz -C /data .'
docker compose --env-file vedette.env start core
```

The image is the Debian image the project pins for its own builds (`deploy/containers/pins.env`, `DEBIAN_IMAGE`; a test keeps the two in step); it runs without a network. The file `vedette-data.tgz` is owned by root with mode 0600: it holds the key, so keep it that way.

To restore into a fresh machine or after `down --volumes`: create the volume without starting core, unpack, then start (same image, core stopped).

```sh
docker compose --env-file vedette.env create core
docker run --rm --network none -v vedette_data:/data -v "$PWD":/backup:ro \
  docker.io/library/debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2 \
  sh -c 'cd /data && tar xzf /backup/vedette-data.tgz'
docker compose --env-file vedette.env start core
```

`down` stops and removes the containers and keeps the data. `down --volumes` deletes the data too. "Delete all data" in Settings → Data makes core exit; Docker restarts it as a fresh box (`restart: unless-stopped`), with a new setup code in the log.

## What each limit looks like in the page

Settings → Updates (operating system part), Settings → Box network and Settings → Data → Download backup answer with the title "Not available on this install" and the sentence "This install has no operating system helper (container-only install), so Vedette ...". The honeypot page and the package list of "This box" do not yet say why they are empty (planned: S-CORE-9 G5, S-INV-5 G3). Short sentences that tell you what to do instead are planned (S-CORE-9, criteria G1 to G6).

## Not tested yet (the lab does)

A real SPAN card, the source address of syslog through Docker's NAT, Docker Desktop, rootful Podman on Ubuntu 24.04 (Podman 4.9) with a real sensor, and a first run by someone who has never seen Vedette.
