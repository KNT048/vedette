// Port-mirroring guides for Settings → Box network (D-56). Commands were checked against vendor documentation on 2026-11-09 by web search and fetch.
// `check` says how far: 'vendor' = found on the vendor's own documentation, 'partial' = found only in older manuals, third-party sites or forum posts, 'general' = common practice, no single source.
// Pages fetched were treated as data. Port names in the examples (24 = the port the Vedette box is plugged into, 1-4 = ports to watch) are placeholders to replace.
export type GuideId = 'cisco' | 'aruba-cx' | 'aruba-switch' | 'mikrotik' | 'omada' | 'unifi' | 'fortiswitch' | 'tap'
export type Check = 'vendor' | 'partial' | 'general'
export interface Guide {
  id: GuideId; vendor: string; check: Check
  /** Where the steps came from (also cited in the comment above each entry). */
  source: string | null
  steps?: string[]
  /** One block per variant, e.g. a RouterOS version. */
  commands?: { label: string; code: string }[]
  notes: string[]
}

export const GUIDES: Guide[] = [
  {
    // Source: https://www.firewall.cx/cisco/cisco-switches/cisco-switches-span-monitoring.html (monitor session source / destination / show monitor session; third-party tutorial),
    // same pattern on Catalyst 9000 in Cisco's TAC note 218111 (could not be fetched, not re-verified). Check the configuration guide of your model and IOS XE version.
    id: 'cisco', vendor: 'Cisco IOS / IOS-XE (Catalyst)', check: 'partial', source: 'https://www.firewall.cx/cisco/cisco-switches/cisco-switches-span-monitoring.html',
    commands: [{ label: 'Local SPAN, ports 1 to 4 watched, Vedette on port 24', code: 'configure terminal\nmonitor session 1 source interface GigabitEthernet1/0/1 - 4 both\nmonitor session 1 destination interface GigabitEthernet1/0/24\nend\nshow monitor session 1' }],
    notes: ['A whole VLAN can be the source instead: monitor session 1 source vlan 10 both (not verified on every model).', 'The destination port cannot also be a source and cannot be part of an EtherChannel. Older models allow only one session.', 'The destination port stops being a normal switch port: do not plug anything else into it.'],
  },
  {
    // Source: https://cray-hpe.github.io/docs-csm/en-13/operations/network/management_network/aruba/port_mirroring (HPE Cray docs for Aruba CX: mirror session, source interface IFACE both|tx|rx, destination interface IFACE, enable, show mirror).
    id: 'aruba-cx', vendor: 'Aruba CX (AOS-CX)', check: 'vendor', source: 'https://cray-hpe.github.io/docs-csm/en-13/operations/network/management_network/aruba/port_mirroring',
    commands: [{ label: 'Mirror session 1, ports 1/1/1 watched, Vedette on 1/1/24', code: 'configure terminal\nmirror session 1\n destination interface 1/1/24\n source interface 1/1/1 both\n enable\nexit\nshow mirror 1' }],
    notes: ['Add one "source interface" line per port to watch. Sessions are numbered 1 to 4.', 'The page is HPE documentation for Aruba CX switches, not the AOS-CX command reference itself; check that for your release.'],
  },
  {
    // Source: HPE/Aruba 2530 and 6120G manuals as reproduced on https://www.manualslib.com/manual/1536241/Aruba-2530.html?page=293 (mirror <1-4> port <port>; interface <ports> monitor all <in|out|both> mirror <n>; show monitor),
    // working line in https://airheads.hpe.com/discussion/port-mirroring-for-2930fm. Firmware-dependent.
    id: 'aruba-switch', vendor: 'ArubaOS-Switch / HPE ProCurve', check: 'partial', source: 'https://www.manualslib.com/manual/1536241/Aruba-2530.html?page=293',
    commands: [{ label: 'Mirror session 1, ports 1 to 4 watched, Vedette on port 24', code: 'configure\nmirror 1 port 24\ninterface 1-4 monitor all both mirror 1\nexit\nshow monitor' }],
    notes: ['If your firmware rejects this, try the older form: mirror-port 24 then interface 1-4 monitor (not verified).', 'Not for Aruba CX: that is a different command set, see the entry above.'],
  },
  {
    // Source: RouterOS 7.15+ per-port mirror-ingress/egress plus switch mirror-target, and the older switch mirror-source form, both as posted at
    // https://forum.mikrotik.com/t/crs312-4c-8xg-port-mirroring/178685 (forum post quoting the MikroTik help page; the official manual at manual.mikrotik.com was not fetched).
    id: 'mikrotik', vendor: 'MikroTik RouterOS (switch chip)', check: 'partial', source: 'https://forum.mikrotik.com/t/crs312-4c-8xg-port-mirroring/178685',
    commands: [
      { label: 'RouterOS 7.15 and newer', code: '/interface ethernet switch port\nset ether2 mirror-ingress=yes mirror-egress=yes\n/interface ethernet switch\nset switch1 mirror-target=ether8' },
      { label: 'Before RouterOS 7.15', code: '/interface ethernet switch\nset switch1 mirror-source=ether2 mirror-target=ether8' },
      { label: 'Turn mirroring off', code: '/interface ethernet switch\nset switch1 mirror-target=none' },
    ],
    notes: ['Works only for ports on the same switch chip, with bridge hardware offload on. Software-bridged ports are not mirrored this way.', 'Older releases mirror a single source port per switch.', 'Command to turn mirroring off is from a forum post; verify on your version.'],
  },
  {
    // Source: https://support.omadanetworks.com/us/document/13293/ (How to configure Switch Port Mirroring on Omada Controller; v5.9+, Omada Smart, L2+ and L3 switches).
    id: 'omada', vendor: 'TP-Link Omada', check: 'vendor', source: 'https://support.omadanetworks.com/us/document/13293/',
    steps: ['In the Omada controller open Devices and select the switch.', 'Open the switch details, Ports tab, and edit the port the Vedette box is plugged into.', 'Turn on Profile Overrides and set Operation to Mirroring.', 'Select the port or ports to monitor and click Apply.'],
    commands: [{ label: 'Optional: CLI profile on the controller (more flexible)', code: 'monitor session 1 destination interface gigabitEthernet 1/0/24\nmonitor session 1 source interface gigabitEthernet 1/0/1 both' }],
    notes: ['TP-Link documents rx, tx and both as the monitor modes. The menu names above follow the controller v5 article; newer controller versions may label them differently.'],
  },
  {
    // Source: https://help.ui.com/hc/en-us/articles/33402927617047-UniFi-Switch-Settings (port settings under Devices > switch > Ports > Port Manager; Operation: Switching / Mirroring / Aggregation).
    // Limits ("one source port", "not on Flex") are from community.ui.com threads and are not official.
    id: 'unifi', vendor: 'UniFi', check: 'partial', source: 'https://help.ui.com/hc/en-us/articles/33402927617047-UniFi-Switch-Settings',
    steps: ['In UniFi Network open Devices and select the switch.', 'Open Ports, then Port Manager, and select the port the Vedette box is plugged into.', 'Set Operation to Mirroring.', 'Choose the port to mirror to it and apply.'],
    notes: ['Reports from the community say many models mirror only one port to the destination, and Flex models may not offer mirroring at all (not from official documentation).', 'To see all traffic of a LAN, mirror the uplink port to the gateway; traffic between two other switch ports will not be seen.'],
  },
  {
    // Source: https://docs.fortinet.com/document/fortiswitch/7.4.1/fortilink-guide/173278 (managed by FortiGate: config switch-controller managed-switch / config mirror / set dst / src-ingress / src-egress / status active).
    // The standalone form (config switch mirror) is from search result snippets of the same Fortinet docs and is not fetched.
    id: 'fortiswitch', vendor: 'FortiSwitch', check: 'partial', source: 'https://docs.fortinet.com/document/fortiswitch/7.4.1/fortilink-guide/173278',
    commands: [
      { label: 'Managed by a FortiGate (FortiLink): run on the FortiGate', code: 'config switch-controller managed-switch\n edit <switch serial number>\n  config mirror\n   edit 1\n    set status active\n    set dst port24\n    set src-ingress port1 port2\n    set src-egress port1 port2\n   next\n  end\n next\nend' },
      { label: 'Standalone FortiSwitchOS (not verified)', code: 'config switch mirror\n edit "vedette"\n  set status active\n  set dst "port24"\n  set src-ingress "port1" "port2"\n  set src-egress "port1" "port2"\n next\nend' },
    ],
    notes: ['Fortinet\'s own example also sets switching-packet enable; Vedette does not need it.', 'Set the destination before the source ports. A port cannot be a source in more mirror sessions than the model allows.'],
  },
  {
    id: 'tap', vendor: 'Network TAP (no switch setup)', check: 'general', source: null,
    steps: ['Put a passive TAP in line on the link you want to watch, for example between the switch and the firewall.', 'Plug the TAP monitor output into the Vedette SPAN port (for example eth1). Use both outputs through an aggregating TAP, or one port per direction.', 'Nothing changes on the switch. If the TAP loses power, a passive TAP keeps the link up.'],
    notes: ['A TAP sees one link, not the whole switch. For a whole LAN, mirror the uplink or core port instead.', 'Full-duplex 1 Gb/s traffic can exceed 1 Gb/s on a single monitor port; busy links lose packets. This is general practice, not a vendor claim.'],
  },
]
