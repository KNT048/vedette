# Deferred: feat/respond-block-from-incident (W1-16, D-509)

- [ ] Respond on non-trap incidents (bad_address: block the known-bad destination; unknown_device: block the device) still shows "no source to act on". Needs the destination/device in a structured field of the notify incident (owner: notify/Mlee) before response can offer it.
- [ ] Port shutdown / quarantine VLAN from an incident: needs the switch port of the source (no source gives it yet; `switch_port` is empty on honeypot events).
