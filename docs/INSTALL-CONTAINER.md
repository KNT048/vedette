# Install Vedette on your own Docker or Podman (container-only)

For the person who already runs Docker or Podman and wants Vedette on it, without giving a machine to the Vedette installer. You get the same program as the appliance, run as containers from Docker Compose. You do not get the helper that manages the machine itself (`vedette-host`), so a few things stay with you. They are listed below; each of those screens in Vedette also says so (D-381).

Decision and plan: D-168, `docs/plans/2026-11-11-wp08m-container-only.md`. The appliance install is `install.sh` (`docs/DEPLOYMENT.md` section 8).

## What you get, and what stays with you

| | Container-only | Appliance (`install.sh`) |
|---|---|---|
| Web page, users, feeds, inventory (by hand or import), findings, notifications, AI (your key), osquery, response | yes | yes |
| Syslog receiver | yes, add `compose.syslog.yaml` | yes |
| Passive sensor (SPAN) and scan worker | yes, add `compose.sensors.yaml`: Linux, run as root (the sensor is uid 0, group 65532, with only `NET_RAW`), you prepare the card | yes, set up in the page |
| Honeypot (traps) | **no** | yes |
| Nmap in the scan worker | **no** (nuclei only) | yes |
| Operating system updates, reboot | **you**, on your machine | in the page |
| Box network (card, SPAN, extra IP, NTP) | **you**, on your machine | in the page |
| Updating Vedette | **you** run `pull` and `up` (below) | in the page, in batches, with rollback |
| Backup | **you** back up the Docker volume (below) | snapshots and rotation by the helper |
| "This box" in the device list | present, without a package list | with the package list |
| MCP server (outside AI tools and SIEMs reading the box) | yes, on `127.0.0.1:8765` of the machine that runs Docker or Podman (`compose.yaml` publishes it there only, D-395); from another machine through an SSH tunnel to this one | yes, on the machine's localhost |

## What you need

- Docker Engine with Compose v2 (`docker compose`), or Podman with `podman compose` and a compose v2 provider (`podman compose version` names it). Tested here: Docker Engine 29.1.3 with Compose 2.40.3, Podman 5.7.0 with that provider. Older versions are not claimed to work until the lab matrix says so; Docker before 28 also let neighbours on your LAN reach ports published on `127.0.0.1` (here 8444, which is mutual TLS, and 8765, the MCP server, which needs a token).
- Podman only: `podman compose` hands the work to the compose provider (docker-compose), which talks to Podman's API socket. Rootless: run `systemctl --user enable --now podman.socket` once; rootful: `sudo systemctl enable --now podman.socket`. Without it every `podman compose` command fails with "Cannot connect to the Docker daemon at unix:///run/user/<uid>/podman/podman.sock".
- Linux, macOS or Windows (WSL2). Docker Desktop on macOS and Windows has no host network, so there you get the web page and the modules that need no real network card, not the sensors.
- Rootless Docker or Podman: the web page and everything that is not a sensor. A rootless setup cannot publish port 514, cannot read a real network card from a container, and may show every syslog sender as one address.
- About 4 CPU cores and 8 GB of memory for a network of up to 1,000 devices (`docs/DEPLOYMENT.md` section 4). Core is limited to 2 GB, the sensor to 512 MB, the scan worker to 1 GB.
- For the sensors: a wired card on a switch port that mirrors traffic (SPAN), set promiscuous with no IP address, before you start. Vedette cannot do that for you here.

## 1. Get the files and check them

Every release that offers this install publishes four files on its GitHub release page, `https://github.com/KNT048/vedette/releases/download/v<version>/`, each with a minisign signature `<file>.minisig`: `vedette.env`, `compose.yaml`, `compose.sensors.yaml` and `compose.syslog.yaml` (D-451). The container images are at `ghcr.io/knt048/vedette-core`, `-sensor` and `-scan`, signed with cosign. The release builder copies the compose files of `deploy/compose/container-only/` unchanged and fills only the three image lines of `vedette.env`, each exactly `ghcr.io/knt048/vedette-<service>@sha256:<64 hex>` (never a tag); `VEDETTE_BIND_IP` and `VEDETTE_HOSTS` stay empty for you to fill. Each signature's trusted comment names the file and the release (`file:vedette.env version:<version>`), so a signed file of another release shows for what it is.

No release is published yet (WP-08k). Until then take the files from `deploy/compose/container-only/` of the repository and use images you built yourself (`make core-image sensor-image scan-base-image`, tagged `localhost/vedette-core:dev`, `localhost/vedette-sensor:dev` and `localhost/vedette-scan-base:dev`).

Make an empty folder for Vedette and work in it from here on: it holds the two public keys, the four release files, and later the folders an update keeps. First save the two public keys there, from this repository rather than from the release page (two places an attacker would have to change). They are the keys compiled into Vedette (`internal/release/keys.go`, D-256); keep both files in this folder for every later update:

```sh
mkdir vedette && cd vedette
printf 'untrusted comment: minisign public key 7B78764E550D48D0\nRWTQSA1VTnZ4e4eM2iBmUKE1/t5l9pmrScK2+wR/EohjSfFEZQ8VwT/m\n' > vedette.pub
cat > cosign.pub <<'EOF'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEm91vgScv6zgXXBX6iJP5qaqydWIx
KTprVWOY3EIHh6AAysr2ncwvWLztYFqP1hoFK19WWSnT+svtyjSBL+2HZA==
-----END PUBLIC KEY-----
EOF
```

Then download the release into the same folder and check it. Put the version you install in place of `0.9.4` on both lines. `minisign -VQm` prints only the signed comment, which must be exactly `file:<that file> version:<version>`: a signed file of another release, or a signature of another file, prints FAILED. Every line must say `ok`; at the first FAILED or `download failed`, stop.

```sh
u=https://github.com/KNT048/vedette/releases/download/v0.9.4
for f in vedette.env compose.yaml compose.sensors.yaml compose.syslog.yaml; do curl -fsSLO "$u/$f" && curl -fsSLO "$u/$f.minisig" || { echo "download failed: $f"; break; }; done
for f in vedette.env compose.yaml compose.sensors.yaml compose.syslog.yaml; do [ "$(minisign -VQm "$f" -p vedette.pub)" = "file:$f version:0.9.4" ] && echo "$f ok" || { echo "$f FAILED: stop"; break; }; done
cosign verify --key cosign.pub ghcr.io/knt048/vedette-core@sha256:<the digest in vedette.env>    # and -sensor, -scan
```

The verifier of the appliance does the same checks for you (`docs/DEPLOYMENT.md` section 5).

## 2. Say where it lives

Open `vedette.env` and fill two lines. In the repository copy the three image lines are empty on purpose; a release fills them. These two lines are the only settings that are yours: do not edit the compose files, because every update replaces all four files (section 5) and you copy just these two lines across.

```sh
VEDETTE_BIND_IP=192.168.10.5        # the address of THIS machine the web page is served on (127.0.0.1 to try it from this machine only)
VEDETTE_HOSTS=192.168.10.5          # the name or address you type in the browser; comma separated for several
```

Why two: Docker's `-p` opens the port itself, around UFW and similar tools: UFW rules do not apply to 8443, 514 or 6514 even on the address you name. So the compose file never publishes on all addresses (do not set `0.0.0.0` or `::`), and to limit *who* may connect, put the rule in Docker's `DOCKER-USER` chain or on your network firewall. And Vedette answers only to the names it was told (`VEDETTE_HOSTS`), which also go in its certificate; any other name gets `421`, a protection against DNS rebinding. Without `VEDETTE_BIND_IP` or `VEDETTE_HOSTS`, or with an empty image line, compose refuses to start and says which one.

Compose does not read `vedette.env` by itself (it reads only a file called `.env`), so every command carries `--env-file vedette.env`. A `VEDETTE_*` variable exported in your shell wins over the file: unset it if the page answers on an address you did not write there.

## 3. Start, and sign in the first time

```sh
docker compose --env-file vedette.env up -d          # or: podman compose --env-file vedette.env up -d
docker compose --env-file vedette.env ps             # core is "healthy" within about a minute
docker logs vedette-core 2>&1 | grep setup_code      # podman logs vedette-core ...
```

The log line holds the one-time setup code (`"setup_code":"..."`). It is printed again at every start while setup is open and stops when the first administrator exists. Open `https://<VEDETTE_HOSTS>:8443`, enter the code, and follow the setup. The certificate is self-signed and made by the box on first start, so your browser warns once; it is kept in the data volume. Opening the page by a name or address that is not in `VEDETTE_HOSTS` shows "This address is not one Vedette answers to": use the one you set, or change the line and run `up -d` again.

Check from another machine that only what you meant is open (`nmap` is yours to run on your own network): port 8443 on `VEDETTE_BIND_IP` and nothing else; ports 8444 and 8765 are on `127.0.0.1` only.

## 4. Add the sensors, or the syslog receiver (optional)

```sh
# Passive sensor and scan worker (Linux, Docker or Podman as root; not rootless, not Docker Desktop)
docker compose --env-file vedette.env -f compose.yaml -f compose.sensors.yaml up -d
# Syslog from your devices (UDP and TCP 514, TLS 6514/tcp, on VEDETTE_BIND_IP)
docker compose --env-file vedette.env -f compose.yaml -f compose.syslog.yaml up -d
```

Keep the same `-f` list on every later command (`ps`, `down`, `pull`, `up`), or compose treats the other containers as strays. Then switch the modules on in Settings → Modules. The sensor runs as uid 0, group 65532 (to read its credentials), with only `NET_RAW` (Docker gives an added capability only to root; Podman gives it to any user), read-only, on the host network; the scan worker runs as uid 65532 with no capability at all (there is no nmap here). The sensor reads the card you prepared; choose it under Sensors once the sensor has reported (the list is what the sensor sees).

## 5. Update, and check what you run

Vedette looks for a new release every 6 hours (while the update check is on under Settings → Privacy). When it finds one, Settings → Updates names the version and its notes and shows these commands with the release's own image digests, for Docker or Podman; there is no Apply button. Until the first release is published (WP-08k) the page says there is no release information yet.

An update replaces all four files, not only `vedette.env`, so a release that changes a compose file reaches you (D-451). Run it in the folder of section 1, where `vedette.pub` and `cosign.pub` are. The page shows these commands with the real versions and digests, one block per step; here, updating from 0.9.3 to 0.9.4:

```sh
# 1. the way back: the four files you run now, in a NEW folder named after the release they run (mkdir refuses an existing folder,
#    so nothing kept is overwritten)
mkdir vedette-0.9.3 && mv -n vedette.env compose.yaml compose.sensors.yaml compose.syslog.yaml vedette-0.9.3/
#    only if vedette-0.9.3 is already there (an update you stopped, or a way back you took): it holds the good files, so first put them
#    back, then rename it, and run step 1 again (renaming it alone would keep the unchecked files of a stopped update as the way back)
cp vedette-0.9.3/* .
mv vedette-0.9.3 vedette-0.9.3-before
# 2. the four files of the new release and their signatures; each signed comment must be exactly "file:<that file> version:0.9.4"
u=https://github.com/KNT048/vedette/releases/download/v0.9.4
for f in vedette.env compose.yaml compose.sensors.yaml compose.syslog.yaml; do curl -fsSLO "$u/$f" && curl -fsSLO "$u/$f.minisig" || { echo "download failed: $f"; break; }; done
for f in vedette.env compose.yaml compose.sensors.yaml compose.syslog.yaml; do [ "$(minisign -VQm "$f" -p vedette.pub)" = "file:$f version:0.9.4" ] && echo "$f ok" || { echo "$f FAILED: stop"; break; }; done
# 3. the images, and that vedette.env names those same digests
cosign verify --key cosign.pub ghcr.io/knt048/vedette-core@sha256:<digest>            # and -sensor, -scan
grep -cF -e 'ghcr.io/knt048/vedette-core@sha256:<digest>' -e ... vedette.env         # prints 3, or do not go on
# 4. copy your VEDETTE_BIND_IP and VEDETTE_HOSTS lines from vedette-0.9.3/vedette.env into vedette.env (a release leaves them empty);
#    with the sensors or syslog, add -f compose.yaml -f compose.sensors.yaml -f compose.syslog.yaml after --env-file vedette.env (leave out the add-on you do not run)
docker compose --env-file vedette.env pull           # podman compose ... the same
docker compose --env-file vedette.env up -d
```

A release can also change the compose files (the one with D-395 publishes the MCP port `127.0.0.1:8765`; with an older `compose.yaml` the MCP server cannot be reached): download `compose.yaml`, `compose.sensors.yaml` and `compose.syslog.yaml` of the new release with their `.minisig`, check each with `minisign -Vm`, and replace yours before `pull` and `up -d`.

If any check fails, stop and put your files back. The same commands are the way back after the update (with the same `-f` files if you run the add-ons):

```sh
cp vedette-0.9.3/* .
docker compose --env-file vedette.env pull
docker compose --env-file vedette.env up -d
```

A version that changes the database may not be able to go back: the release notes say so; back up first.

Without an offered release, the page shows only `pull` and `up -d`: they pull again the images `vedette.env` names (the release you run) and start them, for example after you change a line of `vedette.env`. They never move you to a new release, because the image digests are fixed in `vedette.env`.

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

Vedette knows it is a container-only install from `-host-socket=` in `compose.yaml` (D-381), and the pages follow it:

- Settings → Updates says whether a newer release exists (version and notes) and shows the commands of section 5 for Docker or Podman, with one `cosign verify` line per image of that release; it says the operating system is yours; there is no Apply, spare slot, rollback, channel or package list.
- Settings → Data shows the backup and restore commands of section 6 instead of Download backup and "Backups on this box". Export, log downloads and Delete all data work as on the appliance.
- Settings → Box network says the network of the machine is yours to set up.
- Settings → Modules shows Honeypot (and Credentialed scans) as "Not on this install"; the setup bundles leave them out. A honeypot turned on before this version shows only why it cannot run; turn it off in Settings → Modules.
- The first-run setup names `docker logs vedette-core` for the setup code.
- Scans → Credentialed scan says the module is not on this install instead of inviting you to turn it on (D-420).
- Settings → MCP server says nothing outside the container can reach it yet (D-420); publishing the port safely is packaging work still to come.
- Settings → SIEM forwarding greys out "Honeypot touches": there is no honeypot to forward (D-420).

Still to come: the package list of "This box" says nothing about why it is empty (S-INV-5 G3).

## Not tested yet (the lab does)

A real SPAN card, the source address of syslog through Docker's NAT, Docker Desktop, rootful Podman on Ubuntu 24.04 (Podman 4.9) with a real sensor, and a first run by someone who has never seen Vedette.
