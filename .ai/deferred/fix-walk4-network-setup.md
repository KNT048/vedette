# Deferred: fix/walk4-network-setup (D-405)

- [ ] Opus LOW 1: when the `SetupDone` read fails at boot, the sensor/scan start run sits in its back-off and the setup's `inventory.settings.changed` is swallowed by `OffGuard.start` (a run is live): the containers then start at the next back-off step (≤ 10 min). Upgrade: a "look again after this attempt" flag in `core/modreg/offguard.go`.
- [ ] Opus LOW 4: Box network DNS (DHCP view and the static prefill of a box Vedette has not configured) comes from every resolver of the box (`resolvers`: per-link DNS of a Wi-Fi lease or VPN too). Upgrade: the management link's own DNS (resolved per-link state) in `state/net`.
- [ ] Opus note (pre-existing): `mgmtIface` falls back to the default-route card; on a box whose default route is on Wi-Fi the management card is `wlan0` and a DHCP Save writes it into the wired netplan file. Check `renderNetplan` with a wireless card (wifis: section) or refuse a wireless management card.
- [ ] Not verified on a real appliance: the `dynamic` flag on Ubuntu 24.04/26.04 with netplan + networkd (walk 5 should open Settings -> Box network on a DHCP box and see "From a DHCP server").
