# Deferred — feat/feeds-lean-distro-mlee (D-570)

- [ ] LEAN-3 row "feeds | distro feeds without such a device" in `docs/DEPLOYMENT.md` §2.5: before and after numbers measured on the N100 (core `cpu.stat` around "Fetch now", feed pull time, daily download). The supervisor or Trưởng measures after deploy; Mlee writes the row.
- [ ] ponytail upgrade (D-570 (4); Opus r1 L1): on a box with one distribution, `feedsInventory.Distros` runs about 5 queries per device every 5 minutes, reading every software row. Two options:
  - an inventory call (Kiên-side, Trưởng): `SELECT DISTINCT os` over devices that have an agent's packaged row with both pkg_version and pkg_source;
  - an inventory event when a device's OS changes.
  Do it only if the N100 shows the per-tick cost.
