# WP-07b part 3 plan: vedette-host `net.*`, `decoy_ip.*`, `container.*` (Opus Plan agent, 2026-11-10; origin/main 0064c88)

This is read-only research. I opened every URL cited below during planning. Quick facts: the last decision is D-98, there is no minisign or cosign code anywhere in the repo yet, and the core endpoints `/core/network*` and `/core/updates*` (apart from the OS ones) return 501 through ogen's `UnimplementedHandler`.

## 0. Gaps between the specs and the code
1. **The framework has no `awaiting_confirm` path.**
   - A `Run` can only end in a terminal status.
   - `server.recover()` turns every non-terminal run into `failed host_restarted`. The comment there says "07b must decide".
   - Nothing lets `net.confirm` or `net.revert` get past the global write lock.
   - `Deps.NetPending` always returns `false`.
   - §4 asks for `409 pending_confirm`, but the framework only answers `busy`.
2. **Body limit.** It is 512 KiB for every command. `container.pull` carries index, manifest and both signatures in base64, up to about 700 KiB (update-manifest §12 allows 256 KiB per document).
3. **Docs drift.**
   - host-api §14.3 says the network backend is open; D-57(22) already chose netplan on Ubuntu and networkd on Debian.
   - host-api §14.2 says host self-update is open; D-57(21) decided it.
   - DEPLOYMENT §4 and ARCHITECTURE A1 still list Debian 12/13 as undecided, against D-57(1).
   - Host CONTRACT INV-7 says the host does cohort; core does that.
4. **§6.5 never says what is on disk during the confirm window.** A reboot inside the window is unspecified. The "systemd transient timer" would need a second root entry point.
5. **Three documents disagree on how decoys work.**
   - §6.6 describes "the honeypot container's macvlan network".
   - DEPLOYMENT §2.3/§6.1 uses one container per IP on a Podman macvlan network, plus mTLS to core:8444.
   - D-89/D-90 say one OpenCanary process, file channel, no core port.
   - A Podman macvlan attachment carries only one IP, so it cannot do D-90 together with "one MAC per IP" (§6.6).
6. **§5 `state/net` "other MACs seen" would make root capture and parse LAN traffic.** That breaks the D-87 rule that root never parses untrusted data. The sensor container already parses packets without privilege.
7. **`container.start` does not fit the honeypot.**
   - It requires `version`, but `honeypot.Host.StartContainer(ctx)` has none.
   - It is "idempotent, no restart", yet the honeypot needs a restart after core rewrites `opencanary.conf`.
8. **§6.9 `persist=true` says "systemctl disable".** That is impossible for Quadlet units: Podman says generated units cannot be `systemctl enable`d.
9. **§6.10 says that when `rollback.safe=false`, "core calls backup.restore".** Core cannot order that safely: both steps stop core, and a restore under the new image re-runs migrations. Also, nothing forces a `pre_update` backup before `container.start(core)`; D-53 enforces this for OS updates only.
10. **DEPLOYMENT §6.1 pins `PublishPort=<mgmt IP>:8443`.** After `net.apply`, the GUI is unreachable at the new address unless core restarts, so confirming would be impossible. The same template's `UserNS=auto` gives core a different host uid on each start, which breaks the `SO_PEERCRED` uid check and the D-87 owner checks. Whether core runs as a system or user unit is still open (`feat-host-os-commands.md`).
11. **§6.8 says "write a Quadlet drop-in".** Podman 4.9 on Ubuntu 24.04 does not document drop-ins; only newer Podman does.
12. **Cosign gaps.**
    - update-manifest §5.1 leaves "policy.json or sigstore-go" open.
    - Podman's `sigstoreSigned` needs registries.d attachments and has no path for `oci-archive` bundles.
    - Cosign v3 signs in the new bundle format by default.
    - The manifest has no field that carries the image signature.
13. **PRIVACY flow 6 does not list `ghcr.io`,** although D-57(3) says to add it. Flow 10 promises `pool.ntp.org`, but chrony ships its own distro pools.
14. **No release keys exist.** There is also no bootstrap path: the host cannot learn the initial digests (the installer is not core and fails the peer check).
15. **`honeypot.syncIPs` calls `AddDecoyIP` for every wanted IP on every `Apply`.** With one IP per command and 10 writes per minute, 32 decoys hit `rate_limited`.
16. **DEPLOYMENT §12 `RestrictAddressFamilies` lacks `AF_PACKET`,** which an ARP probe needs.
17. **Bundles.** The GUI uploads them as base64 JSON, but update-manifest §11 says uploads must stream. There is no core→host handoff contract for bundles like the D-87 snapshot contract.
18. **NTP.** netplan has no NTP key. Ubuntu 24.04 and Debian 13 default to timesyncd, Ubuntu 25.10+ to chrony, and ntpd-rs is planned for Ubuntu 27.04.
19. **Size check.** update-manifest asks for "bytes == `size`", but Podman does not expose downloaded byte counts. The digest pin already guarantees integrity.

## 1. Decisions (D-99 to D-107)

**D-99 One network stack: netplan with the networkd renderer on Ubuntu 24.04, Ubuntu 26.04 and Debian 13.**
- The host owns `/etc/netplan/90-vedette.yaml` (0600) and nothing else in netplan.
- The installer (WP-08):
  - installs `netplan.io` on Debian (1.1.2 in trixie, depends on systemd);
  - writes `/etc/cloud/cloud.cfg.d/99-vedette-network.cfg` with `network: {config: disabled}`;
  - moves every other `*.yaml` in `/etc/netplan` and `/run/netplan` aside;
  - stops ifupdown and NetworkManager from managing the interface.
- `Check` refuses `412 net_backend_unsupported` if any other netplan file exists or `/usr/sbin/netplan` is missing. The host never parses files it did not write.
- The YAML is marshalled from a typed struct with `go.yaml.in/yaml/v3`, which is already a direct requirement, so no new module.
- This replaces the Debian half of D-57(22). Two backends would mean two code paths and two lab matrices. Debian's own cloud images moved to networkd+netplan in bookworm.
- References:
  - https://netplan.readthedocs.io/en/stable/netplan-generate/ (`/run` shadows `/etc`, `--root-dir`)
  - https://lists.debian.org/debian-cloud/2023/07/msg00004.html
  - https://packages.debian.org/trixie/netplan.io
  - https://docs.cloud-init.io/en/latest/reference/network-config.html
- Rejected:
  - Raw networkd `.network` files: on Ubuntu they fight netplan and cloud-init, and `/etc` beats `/run`, so the overlay trick of D-100 is lost.
  - `netplan try`: it is interactive, does not survive a reboot or crash, and its docs warn you to check that the revert actually happened (https://netplan.readthedocs.io/en/stable/netplan-try/).
  - NetworkManager: desktop only.

**D-100 The confirm window is a volatile overlay: the new config is persisted only on confirm.**
- `net.apply`, when the management `mode`, `address`, `prefix`, `gateway` or `iface` changes:
  1. Check: interface known, `same_iface`, `gateway_outside_subnet`, no `pending_confirm`, backend present.
  2. Run: ARP-probe the new static address (`address_conflict` is a `*Refusal` returned from Run).
  3. Write the new file to `/run/netplan/90-vedette.yaml`, which shadows `/etc`.
  4. Write `net/pending.json` `{run_id, revert_at, boot_id, old_sha, new_sha}` (0600, atomic).
  5. Run `netplan apply`.
  6. Check the effect: the address is on the interface (DHCP: an IPv4 within 15 s) and the gateway answers ARP within 15 s. If not, revert at once (`reverted connectivity_check_failed`).
  7. Re-apply the decoys.
  8. Return `Awaiting{RevertAt}`. The run stays `awaiting_confirm` and keeps the write lock.
- **Confirm:** write `/etc/netplan/90-vedette.yaml` atomically via `os.Root`, remove the `/run` copy (runtime unchanged), delete `pending.json`, settle `succeeded`.
- **Revert** (`net.revert`, the timer through `Deps.AfterFunc`, or recovery): remove the `/run` copy, `netplan apply`, re-apply decoys, check the effect, settle `reverted not_confirmed|cancelled`. If `netplan apply` fails, settle `failed revert_failed`; the on-disk config is still the old one, so a reboot restores it, and the GUI says so.
- **Crash and reboot behaviour:**
  - A reboot inside the window brings back the old config by construction, because `/run` is tmpfs.
  - A host crash is handled in `Ops.Start` before `Listen`: a pending run on the same boot is re-armed, or reverted now if past `revert_at`. On a new boot it settles `reverted reverted_by_reboot`.
  - No systemd transient timer.
- **What applies at once:** DNS-only, SPAN and NTP changes write to `/etc` directly and finish `succeeded`, matching the GUI ("DNS-only changes apply at once"). Same desired state → `succeeded`, no change.
- **Framework additions:**
  - `server.Awaiting{RevertAt, Result}`.
  - `(*Server).Settle(runID, status, *RunError)`: exactly once (CAS); writes the run, the audit line and the final event, then releases the lock.
  - `Spec.WhileAwaiting`: only for `net.confirm` and `net.revert`, only when `args.run_id` equals the awaiting run.
  - `Options.Resume func(api.Run) bool`, called by `recover` for awaiting runs.
  - `409 pending_confirm` (with `run_id`) when a write arrives during an awaiting run.
  - `NetPending` wired to the real pending state.
  - An `awaiting_confirm` audit line.
- References: RFC 6241 §8.4 (on reboot the server MUST restore the prior config; default 600 s) https://datatracker.ietf.org/doc/html/rfc6241; MikroTik Safe Mode ("saved to disk only after safe mode is turned off", undone on abnormal end) https://help.mikrotik.com/docs/spaces/ROS/pages/328155/Configuration+Management; Junos commit confirmed (10 min default) https://networkingdocs.hpe.com/documentation/us/en/software/junos/netconf/topics/task/netconf-configuration-committing-with-confirmation.html; TrueNAS Test Changes / Save Changes (60 s) https://www.truenas.com/docs/scale/network/interfaces/configuringinterfaces/.
- Rejected: a transient timer (a reboot leaves the new config persisted; needs a second binary entry point); finishing the run `succeeded` with a "pending" flag (the GUI and spec already use `awaiting_confirm`).
- `net.apply` run timeout becomes 60 s (§10 says 30 s). The confirm window stays 30–600 s, default 120 s.

**D-101 Root sends and reads only fixed-size ARP frames; it never parses captured traffic.**
- `host/ops/arp` (Linux) opens an `AF_PACKET` socket through `golang.org/x/sys/unix` (already pinned at v0.49.0).
- Probe per RFC 5227: sender IP 0.0.0.0; 3 probes 1 s apart, then listen 2 s (about 4 s). This replaces §6.6's "3 s". Any ARP frame with sender IP equal to the probed address counts as a conflict; our own MAC is ignored.
- Gateway check: an ARP request from the new address, retried every 1 s up to 15 s.
- The encode/parse code is pure (exactly 42-byte frames) and fuzzed.
- `state/net` reports interface counters only, from `/sys/class/net/*`, `net.Interfaces` and `/proc/net/route`. `other_macs` and `last_packet_at` come from the `sensor` container through core. This changes §5.
- Add `AF_PACKET` to `vedette-host.service`.
- References: https://datatracker.ietf.org/doc/html/rfc5227
- Rejected: the `arping` binary (not installed by default; two incompatible implementations); ICMP (gateways often drop ping); counting MACs in root.

**D-102 Decoys live in a host-owned network namespace `vedette-hp`, one macvlan link and one MAC per IP.**
- **Created at `Ops.Start`** (`/run/netns` is tmpfs), before the honeypot unit starts. `vedette-host.service` becomes `Type=notify` and sends `READY=1` after `Start` (stdlib unixgram, about 15 lines).
- **Per decoy:**
  - `ip link add link <mgmt> name vdh<8 hex of IP> address <mac> type macvlan mode bridge`, then `ip link set … netns vedette-hp`.
  - Inside the namespace: address, link up, a per-IP routing table (100+i) with the subnet and `default via <gw>`, and `ip rule from <ip> lookup <t>`.
- **Namespace sysctls**, set once with `ip netns exec vedette-hp /usr/sbin/sysctl -w …`:
  - `arp_ignore=1` and `arp_announce=2`: no ARP flux between links on the same subnet;
  - `rp_filter=2`;
  - `ip_unprivileged_port_start=0`: this sysctl is per namespace, so the container needs no `NET_BIND_SERVICE`, i.e. `DropCapability=ALL`.
- **Egress block** inside the namespace: a constant nft ruleset (`ct state established,related accept; ct state new drop` on output). This answers DEPLOYMENT B5: macvlan traffic skips host netfilter but not the namespace's own.
- **Honeypot Quadlet:** `Network=ns:/run/netns/vedette-hp` (Quadlet `Network=` takes the same format as `podman run --network`, and podman-run documents `ns:path`).
- **Lifecycle:** decoys are re-applied after every `net.apply` or revert. Decoys that fall outside the current management subnet are removed and reported, and the honeypot shows `conflict`. Stored in `hp/decoys.json`.
- **MAC:**
  - A 32-byte per-install key (`hp/mac.key`, 0600).
  - Default: `HMAC-SHA256(key, ip)` with the locally-administered bit set and the multicast bit cleared. It is stable per IP and not recognisable across boxes, unlike a plain hash of the IP.
  - Optional arg `oui` (6 hex, globally administered unicast): MAC = OUI + 3 HMAC bytes. This answers §14.5 "yes, optionally". Core picks the vendor from the D-83 OUI table (data, so D-58 holds).
- **Tools:** iproute2 `ip`, `nft` and `sysctl` run through `core/exec` with fixed grammars. No new Go dependency.
- References: https://docs.podman.io/en/latest/markdown/podman-run.1.html ; https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html ; https://docs.kernel.org/networking/ip-sysctl.html ; Thinkst Canary custom MAC prefix ("Nmap will try to identify a device based on its MAC prefix") https://help.canary.tools/hc/en-gb/articles/18384536801693-How-can-I-set-a-custom-MAC-address-prefix-on-my-Canary
- Rejected:
  - A Podman macvlan network: one IP per attachment, a restart for every change, and its IPAM clashes with the LAN's DHCP.
  - ipvlan: decoys would share the box's own MAC.
  - One MAC for all decoys: 32 IPs on one MAC is a tell.
  - Adding links inside the container's own namespace: lost on every restart.
  - `vishvananda/netlink`: new modules in the root process.

**D-103 Signatures are verified in-tree with the standard library; the cosign signature travels inside the minisign-signed manifest.**
- **New package `internal/release`**, pure and shared by host and core: minisign, cosign, index and manifest parsing, SemVer, revocation.
- **minisign:**
  - `crypto/ed25519` plus `golang.org/x/crypto/blake2b` (x/crypto already pinned at v0.58.0).
  - Only the prehashed `ED` algorithm; legacy `Ed` is refused.
  - `key_id` must match an embedded key.
  - The global signature over `sig || trusted_comment` is verified too.
  - Two embedded keys: active, and an offline backup that kien holds, so rotation does not depend on a leaked key (update-manifest §15.1).
- **cosign:**
  - Release-manifest `images[]` gains `cosign: {payload, signature}` (base64), produced by a pinned cosign with `sign --key --new-bundle-format=false --use-signing-config=false` and still pushed to ghcr for people who want to verify.
  - The host checks ECDSA P-256 over SHA-256 (`ecdsa.VerifyASN1`) against the embedded cosign key.
  - The payload's `critical.type` must be "cosign container image signature", and `critical.image.docker-manifest-digest` must equal `images[].digest`.
  - Rekor is not checked: offline verification, per D-57(3).
  - JSON is decoded strictly: unknown fields, duplicate keys and case-folded duplicate keys are refused, reusing the host's existing rule.
- References: https://jedisct1.github.io/minisign/ ; https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md ; https://blog.sigstore.dev/cosign-3-0-available/ ; https://github.com/containers/image/blob/main/docs/containers-policy.json.5.md
- Rejected:
  - `sigstore-go`: 79 modules (protobuf, go-tuf, in-toto, rekor) in the only root process; built for keyless bundles (https://github.com/sigstore/sigstore-go/blob/main/go.mod).
  - The cosign CLI: a large binary run by root, with its own package and vulnerability stream.
  - Podman `policy.json` `sigstoreSigned`: system-wide config, needs `use-sigstore-attachments`, no path for `oci-archive` bundles, and ties us to Podman 4.9's support of cosign formats.
  - minisign libraries: about 100 lines are enough without a new dependency.
- `govulncheck` surface: unchanged.

**D-104 Rules for pull, start, rollback, downgrade and revocation.**
- **Pull reference:** always `ghcr.io/knt048/vedette-<service>@sha256:<64 hex>`, built from a compile-time constant and the manifest digest. The manifest `ref` must equal `<constant>:<version>`, otherwise `registry_not_allowed`.
- **Index:**
  - Required on every pull.
  - Signed by an embedded key that the stored index has not revoked.
  - `sequence ≥` the stored one (equal is allowed).
  - The highest-sequence index is stored and is the host's only revocation source.
  - Expiry gives a warning only (update-manifest §4.1).
- **Manifest:**
  - Signature valid, key not revoked, release and digest not revoked.
  - `install_modes` contains `appliance`; `platforms` contains `linux/$GOARCH`.
  - It does not have to be the channel's latest, so old releases can be pulled again.
  - The pulled record keeps `{version, digest, key_id, manifest}`.
  - `size` is used only for `low_disk` (2× size); the "bytes == size" rule is dropped because the digest pin covers integrity.
- **Start** (re-checks revocation and key):
  - Version lower than current → `downgrade_not_allowed`, using SemVer precedence via `golang.org/x/mod/semver` (indirect → direct dependency, BSD-3).
  - Current version below the manifest's `min_upgrade_from` → `upgrade_path_required`.
  - `version` optional: omitted means "enable and start the current version".
  - `restart: bool` optional, so the honeypot can reload its config.
  - For `core`, `snapshot` is required: the host makes the `pre_update` backup inside the run using the existing D-87 code. This is the HA Supervisor "backup before update" pattern (https://www.home-assistant.io/common-tasks/general/backups/).
- **Rollback:**
  - Only to the stored, previously verified `previous`.
  - Refused with `previous_revoked`, or `rollback_not_allowed` when previous is below the current manifest's `rollback.min_version`.
  - For core with `rollback.safe=false`, one run does: stop core → restore the transition's `pre_update` backup → write the previous unit → start → health. On failure both are put back (`reverted`). This replaces "core calls backup.restore" in §6.10.
  - The host never auto-rolls back on revocation; core decides (update-manifest §8).
- **Retention:** the host keeps current, previous and the newest pulled image, tagged `localhost/vedette-<service>:<version>`. Others are removed with `podman rmi <digest>` after a successful start. Never `prune -a`.
- References: https://theupdateframework.github.io/specification/latest/ (rollback and freeze attacks) ; https://semver.org/ (11.3: a prerelease is lower than the release).

**D-105 Quadlet units are code, and root writes them safely.**
- The host renders the whole `/etc/containers/systemd/vedette-<service>.container` from constant per-service Go templates. The only slots are the digest, whether `[Install] WantedBy=` is present (that is what `persist` stop/start does, since generated units cannot be enabled), and `core_uid`/`core_gid` from host.conf.
- No drop-ins: Podman 4.9 on noble does not document them (https://manpages.ubuntu.com/manpages/noble/man5/podman-systemd.unit.5.html).
- **Writing:**
  - Parent chain must be root-owned and not group/other-writable (the D-87 `checkChain` idea, adapted to root trees).
  - `os.OpenRoot`, temp file `O_CREATE|O_EXCL|O_NOFOLLOW` 0644, write, `f.Sync`, `Root.Rename`, fsync the directory.
  - The previous bytes are kept in `containers/units/<service>.prev`.
  - Then `systemctl daemon-reload` and `restart vedette-<service>.service`.
- **Effect check:** `podman container inspect` shows the expected `ImageDigest`, and `.State.Health.Status` is `healthy` within 120 s. Polled, because Podman 4.9 has no `Notify=healthy`.
- **Units are system, rootful** (DEPLOYMENT §12). This closes the user/system question in `feat-host-os-commands.md`.
- **Core:**
  - Runs with a fixed `User=<core_uid>:<core_gid>`, without `UserNS=auto`, so the peer uid and D-87 owner checks hold.
  - `PublishPort=8443:8443` with no IP: the box's only host address is the management one (SPAN has none, decoys are in `vedette-hp`), so `net.apply` never restarts core.
  - Other services use `UserNS=auto`.
- A contract test on the rendered units: no `--privileged`, capabilities per a service table, `Network=host` only for sensor and scan, the honeypot only `ns:/run/netns/vedette-hp`.
- **Transition journal** `containers/transition.json`, written before the swap: on `Start`, an unhealthy half-swap is put back (the `restore.json` pattern).
- References: https://go.dev/blog/osroot ; podman-systemd.unit(5) above (generated units cannot be enabled; `[Install]` is applied by the generator at daemon-reload).
- Rejected: installer-owned units with an Image-only drop-in (not on 4.9); `text/template` with free strings.

**D-106 NTP: chrony everywhere.**
- The installer installs chrony (Ubuntu's default since 25.10) and owns `chrony.conf`, with only `sourcedir /etc/chrony/sources.d` and no distro pools, so PRIVACY flow 10 stays true.
- The host writes `vedette.sources`: `pool pool.ntp.org iburst` by default, or up to 4 `server <name|ip> iburst` lines (names by regex, IPs via netip, no newlines).
- Then `chronyc reload sources`; effect check with `chronyc -N -c sources`. NTP changes never wait for confirmation.
- References: https://ubuntu.com/server/docs/explanation/networking/about-time-synchronisation ; https://chrony-project.org/doc/4.6/chrony.conf.html (sourcedir: only server/pool/peer, reloaded by `reload sources`) ; https://discourse.ubuntu.com/t/ntpd-rs-its-about-time/79154 (ntpd-rs planned for 27.04: one writer to adapt).
- Rejected: timesyncd drop-ins (Ubuntu moved away from it); detecting the daemon per distro.

**D-107 What can be tested without root, Podman or real networking.**
- **Test seams** (production may not use them, like `NewWithDeps`): `Deps.Root` (prefix for `/etc/netplan`, `/run/netplan`, `/etc/containers/systemd`, `/etc/chrony`, `/sys/class/net`, `/proc/net/route`, `boot_id`), `BinPaths`, `Probe` (ARP), `Interfaces`, `Now`, `AfterFunc`, `Keys` (test trust roots).
- **Fake binaries** (`netplan`, `ip`, `nft`, `sysctl`, `chronyc`, `podman`, `systemctl`) via `exectest` and `opstest` rules: they record argv and print fixtures.
- **Reboot simulation:** wipe `Root/run`, change `boot_id`, rebuild `Ops` and `Server` on the same state directory.
- **Linux CI only, no root:** real `netplan generate --root-dir <tmp>` on our YAML (skipped if absent); an `AF_PACKET` test only with `CAP_NET_RAW`.
- **Signature vectors:** generated once with the real `minisign` and `cosign` (legacy mode, `--upload=false --output-signature/--output-payload`) and committed; plus Go-made negative cases.
- **Lab checklist** on Ubuntu 24.04, Ubuntu 26.04 and Debian 13 VMs is deferred (§4).

## 2. Slices (one PR each)

**3-0 docs-first (Kiên).**
- DECISIONS D-99…D-107.
- host-api:
  - §5 `state/net`: counters only, decoys with MAC.
  - §6.5: overlay, `pending_confirm`, timeouts.
  - §6.6: netns, `oui`, RFC 5227 timing.
  - §6.7: `cosign` in the manifest, no size equality, body 1 MiB.
  - §6.8: `version`/`restart` optional, `snapshot` for core, timeout 15 min for core.
  - §6.9: `[Install]` instead of disable.
  - §6.10: restore inside the run, `rollback_not_allowed`.
  - §10, §11 codes, §14.3/§14.5 closed, new §18.
- update-manifest §4.2 (`images[].cosign`), §5.1, §10, §12.
- host CONTRACT: command table, INV-16 (overlay), INV-17 (units as code), INV-18 (root parses no traffic).
- honeypot CONTRACT: netns, `oui`, egress drop.
- DEPLOYMENT §2.3, §4, §6.1 (core PublishPort/User, honeypot `ns:`), §12 (`AF_PACKET`, `Type=notify`).
- ARCHITECTURE A1, A3, B5.
- PRIVACY flow 6 (`ghcr.io`, `pkg-containers.githubusercontent.com`) and flow 10, plus the Settings → Privacy text.
- THIRD_PARTY_NOTICES: iproute2, nftables, netplan, chrony, procps run as separate processes.
- USER_STORIES criteria for S-CORE-8, S-CORE-2 and S-HP-2.
- New `.ai/deferred/feat-host-net-containers.md`.

**3-1 Framework: awaiting, settle, per-command body limit, readers** (`host/server/{registry,handlers,server,readers}.go`, `host/api`).
- Adds `Awaiting`, `Settle`, `WhileAwaiting`, `Resume`, `Spec.MaxBody`, `pending_confirm`, `Readers.Net` and `Readers.Containers`.
- Tests:
  - the lock is held while awaiting;
  - confirm and revert get through only for the matching run; anything else → `409 pending_confirm`;
  - `Settle` runs once under concurrency (confirm against timer);
  - an awaiting run survives recovery when `Resume` returns true;
  - `MaxBody` is per command;
  - audit lines: accepted, awaiting, final;
  - the "not yet" contract list shrinks.
- Review must attack: lock bypass through `WhileAwaiting` (wrong run, after settle, after shutdown); double settle; `Settle` racing `Shutdown`; recovery ordering against `Listen`; idempotency replay of confirm.

**3-2 `internal/release`** (pure; runs in parallel with 3-1).
- Files: `minisign.go`, `cosign.go`, `index.go`, `manifest.go`, `semver.go`, `revoke.go`, `testdata/`.
- Tests: real-tool vectors; the legacy `Ed` downgrade; trusted comment tampering; key_id mismatch; high-S/DER edge cases; digest case; duplicate or case-folded keys; unknown `schema`; sequence regress; revoked key, release or digest; prerelease ordering. Fuzz every parser.
- Review must attack: signature confusion, smuggling through JSON decoding, base64 leniency, prehash bypass, revocation logic letting a revoked key revoke good keys.

**3-3 Net read side** (`host/ops/{netstate,netplan,arp_linux,arp_other,arpframe}.go`).
- `GET /v1/state/net`, the netplan renderer, the ARP prober, argv grammars for `netplan`, `ip` and `networkctl`.
- Tests: golden YAML; CI `netplan generate --root-dir`; ARP frame fuzz; sysfs fixtures; the refusal when other netplan files exist.
- Review must attack: YAML injection through interface, DNS or NTP values; the hostile-frame parser; leaks of the `AF_PACKET` socket; reading `/sys` through symlinks.

**3-4 `net.apply`, `net.confirm`, `net.revert` and NTP** (`host/ops/{net,netpending,ntp}.go`; needs 3-1 and 3-3).
- Tests:
  - management change → awaiting, then confirm writes `/etc`;
  - timer → reverted;
  - a reboot (`/run` wiped, new `boot_id`) → `reverted_by_reboot`;
  - a host crash before or after `revert_at`;
  - a failed connectivity check → reverted;
  - DNS/NTP/SPAN-only changes need no confirm;
  - same state → no-op;
  - `os.reboot` → `net_pending_confirm`;
  - chrony file content and effect check.
- Review must attack: the race between confirm and timer; tampered or symlinked `pending.json` or `/run/netplan`; a revert that leaves partial state; ARP spoofing of the gateway (accepted risk: it only keeps a config the admin chose); chrony directive injection.

**3-5 `decoy_ip.add` / `decoy_ip.remove`** (`host/ops/{decoy,hpns,mac}.go`; needs 3-3; re-apply hook into 3-4).
- Tests: the `ip`/`nft`/`sysctl` argv grammar plus fuzz; `ip_is_gateway|host|network|broadcast`, `ip_in_use`, `duplicate_decoy`, `limit_reached` 32; MAC bits and `oui` validation; stable MAC across restarts; namespace re-created at `Start`; idempotent remove; decoys outside the subnet dropped after `net.apply`.
- Review must attack: escaping the grammar, link-name collision with host links, `/run/netns` symlink tricks, an egress ruleset that is not actually loaded (check the effect with `nft list ruleset` inside the namespace), a multicast or locally-administered `oui`.

**3-6 Quadlet writer and lifecycle of the current version** (`host/ops/{quadlet,units,containers}.go`; needs 3-1).
- `GET /v1/state/containers`, `container.stop` (`persist`), `container.start` with no version or `restart`, health polling, the transition journal. This lets the honeypot run before `pull` exists.
- Tests: golden units; capability/network contract test; a symlink at the unit name or directory; a group-writable parent; `cannot_stop_core`; the `[Install]` toggle; an unhealthy start reverts the unit.
- Review must attack: writing the unit as root (TOCTOU, rename across a symlink), template injection, daemon-reload side effects, a compromised container faking health.

**3-7 `container.pull`** (`host/ops/pull.go`; needs 3-2 and 3-6).
- Podman grammar: `pull -q <ref>`, `image inspect --format json`, `tag`, `rmi`.
- Tests: `registry_not_allowed`, `sequence_regress`, `key_revoked`, `release_revoked`, `digest_not_in_manifest`, `platform_mismatch`, `low_disk`, idempotency when the digest is already present, the stored index is updated only when newer, `source=bundle` → `412 bundle_unsupported` (deferred).
- Review must attack: can core make the host pull any reference; replayed or frozen index; parsing of Podman output; leftovers from a partial pull.

**3-8 `container.start(version)`, `container.rollback`, retention, bootstrap CLI** (needs 3-7).
- Start for core with a `pre_update` backup from `snapshot`; rollback with the in-run restore when `safe=false`; `rmi` retention.
- `vedette-host -bootstrap` verifies a manifest and writes the first units, for install.sh (WP-08); it is not reachable from the socket.
- Tests: `downgrade_not_allowed`, `upgrade_path_required`, `previous_revoked`, `rollback_not_allowed`; rollback twice returns to where it started; a failed rollback stops without looping; a host crash mid-swap is put back at `Start`; the client restarts while core restarts.
- Review must attack: the stop → restore → swap → start ordering under failure; reuse of the D-87 descriptor path; whether retention can ever remove current or previous.

## 3. What `core` needs
- **The GUI already exists for both screens** (gui-first is met):
  - `NetworkSection`, `SpanCard`, `networkMock`, `useCountdown` cover S-CORE-8, including the confirm/revert endpoints and `pending`.
  - `UpdatesSection` covers S-CORE-2.
  - The backend returns 501 for both.
- **GUI and contract changes, before the backend:**
  - S-CORE-2: the rollback dialog must warn "data written since the update is lost" when `rollback.safe=false`. That means `UpdateComponent.rollback_restores_data` and a `409 confirm_required` until `confirm_data_loss: true` (the same pattern as network). Component ids become service names. Add the new error texts.
  - S-CORE-8: help text ("if the box restarts before you confirm, it comes back on the old address"); messages for `address_conflict`, `gateway_outside_subnet`, `net_backend_unsupported`.
  - S-HP-2: optionally show the decoy MAC (can be deferred).
- **Handlers for the network screen** (`modules/core/{nethost,handlers_network}.go`):
  - Merge each `PUT` into the full desired state and call `net.apply`.
  - Store the confirm `run_id`; on start-up, rebuild pending from `ListRuns`.
  - SPAN extraction, filters and CPU limits stay in core's database (sensor config); `span_status` combines host counters with sensor data.
  - After confirm, refresh the box IP for the inventory "This box" entry, honeypot INV-3 and response's never-touch list.
- **Honeypot adapter** (`cmd/vedette/honeypot.go`, replaces `notAnAppliance`):
  - `Status` from `/v1/info.commands`.
  - Diff against `state/net` decoys and add or remove only what differs (fixes gap 15).
  - Start with `restart: changed`; stop with `persist`.
  - Pass the `oui` of the personality.
- **Updates** (`modules/core/{updates,updatehost}.go`):
  - Fetch `index.json` and the manifest from GitHub (D-81) and verify them with `internal/release`.
  - Cohort, channel, mode, advisories, revocation banner.
  - Apply: snapshot → `container.pull` for each service → `container.start` (core last, with `snapshot`) → history (a new `core_update_*` table in DATA_MODEL).
  - Rollback calls `container.rollback`. Auto mode runs only inside the maintenance window.
  - Bundles are deferred.
- **Contract:** core CONTRACT INV for network and updates; a host-code → API-code table like INV-21.

## 4. Risks and deferred items
- **Risks:**
  - The installer must hand the host exclusive control of netplan, otherwise every `net.apply` is refused.
  - macvlan does not work on Wi-Fi or behind VMware/Hyper-V MAC policies (decoys stay silent): the GUI must say so, and the lab must check.
  - Mistakes in per-IP routing inside the namespace.
  - `netplan apply` can bounce other interfaces.
  - Field names in `podman inspect` differ between 4.9 and 5.4.
  - Cosign v4 will remove the legacy format: switch to verifying the new bundle (DSSE) in-tree before that.
  - Multi-arch: the manifest digest must be the index digest; check in the lab.
  - Writing 32 decoys takes 3 minutes or more at 10 writes per minute.
  - The root binary grows; keep the code in `host/ops` subfiles behind fixed grammars.
- **Deferred:**
  - Bundle source (core writes `<core_data>/imports/<id>/`, the host copies by descriptor as in D-87; streaming upload in the GUI).
  - `host.self_update` (D-57(21)).
  - IPv6 management.
  - Core choosing an `oui`.
  - Port-scan detection on decoys through nft `log` in `vedette-hp` (honeypot OQ1, no `net_raw` needed).
  - `firewall.*` (§14.1).
  - logind inhibitor.
  - `Notify=healthy` once Podman ≥ 5 is everywhere.
  - Lab checks: real `netplan apply` and reboot inside the window, macvlan in the namespace, nft egress, chrony, Quadlet on 4.9 and 5.4, ghcr pull by digest, `AF_PACKET` probe.

## 5. Owner questions
None meet the `decide-like-top-tier` bar:
- D-99 overrides the Debian half of D-57(22), but it is reversible and follows top-tier practice.
- ghcr.io in PRIVACY is already decided in D-57(3).
- Vendor OUIs on decoys follow Thinkst practice inside the customer's own LAN.

kien still has two prerequisites to do:
1. Generate offline the release keys: a minisign active key, a minisign offline backup key, and a cosign key. The private halves never go into the repo or onto a box; slice 3-2 embeds the public halves.
2. Provide or approve the Ubuntu 24.04, Ubuntu 26.04 and Debian 13 lab VMs for the checks in §4.

### Critical files for implementation
- /Users/kien/Desktop/vedette-wt/auth-stepup/host/server/handlers.go (on origin/main: lock and submit, awaiting/settle)
- /Users/kien/Desktop/vedette-wt/auth-stepup/host/server/server.go (on origin/main: the `recover()` resume hook)
- /Users/kien/Desktop/vedette-wt/auth-stepup/host/ops/bins.go (on origin/main: argv grammars for `ip`, `nft`, `netplan`, `podman`, `chronyc`)
- /Users/kien/Desktop/vedette-wt/auth-stepup/host/ops/ops.go (on origin/main: Deps seams, `Start` recovery, `Commands`/`Readers`)
- /Users/kien/Desktop/vedette-wt/auth-stepup/docs/specs/host-api.md (on origin/main: §6.5–§6.10, §10, §14, the new §18)