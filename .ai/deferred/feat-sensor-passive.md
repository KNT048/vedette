# Deferred: feat/sensor-passive (WP-11)

- [ ] Live AF_PACKET capture (`afpacket_linux.go`) is compiled and source-audited only; verify by effect on the lab VM: socket opens with only CAP_NET_RAW, `tx_packets` of the card does not change, frames arrive, stops on module off.

- [ ] Capture runs inside the main vedette process, so the API process would need CAP_NET_RAW. Before release, run capture in the sensor container (D-55: host network, CAP_NET_RAW only) and talk to the core over the sensor protocol; keep the main process unprivileged.
