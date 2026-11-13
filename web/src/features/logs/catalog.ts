// Danh mục nguồn log (S-LOG-1): mỗi loại thiết bị có nhóm, giao thức gửi được, mức Vedette đọc được, các bước và đoạn dán.
// Cấu hình hiển thị cho người dùng bằng tiếng Anh (D-28). Mỗi mục ghi nguồn tài liệu hãng trong comment `Nguồn:`.
// Quy ước trung thực: `reads: 'parsed'` chỉ cho loại có profile thật (modules/logs/data/profiles, Go kiểm bằng TestCatalogReadsMatchProfiles); còn lại `stored` = lưu, tìm kiếm và digest đọc bằng bộ tìm mẫu chung, chưa đọc trường riêng của thiết bị.
// Cú pháp đã đối chiếu (2026-11) với tài liệu hãng cho: FortiOS, PAN-OS, Sophos Firewall, Check Point Log Exporter, Meraki, Synology,
// NetScaler, Wazuh, Suricata, NXLog, MikroTik, pfSense, OPNsense. Mục còn lại theo cú pháp ổn định đã công bố; phần menu có thể đổi theo phiên bản
// nên mỗi mục có ghi chú "đối chiếu tài liệu của hãng cho phiên bản của bạn" khi cần.
import type { KindId } from './kinds'
import type { Proto } from './types'

export type GroupId = 'firewall' | 'vpn' | 'server' | 'nas' | 'security' | 'web' | 'switch' | 'other'
export const GROUPS: GroupId[] = ['firewall', 'vpn', 'server', 'nas', 'security', 'web', 'switch', 'other']
export const GROUP_LABEL: Record<GroupId, string> = {
  firewall: 'Firewalls and routers',
  vpn: 'VPN and remote access',
  server: 'Servers and operating systems',
  nas: 'NAS and virtualisation',
  security: 'Security tools',
  web: 'Web, proxy, DNS and mail',
  switch: 'Switches and Wi-Fi',
  other: 'Other and generic',
}

export interface Snippet { label: string; code: string }
export interface Ctx { ip: string; port: number; proto: Proto }
export interface CatalogEntry {
  id: KindId
  group: GroupId
  name: string
  /** Từ khoá tìm kiếm thêm (tên cũ, model, tên gọi thông dụng). */
  keywords: string
  /** Giao thức thiết bị thật sự gửi được; phần tử đầu là mặc định. */
  protos: Proto[]
  reads: 'parsed' | 'stored'
  /** Vedette đọc gì từ nguồn này (parsed) hoặc vì sao chỉ lưu (stored). */
  readsNote: string
  intro: string
  steps: (c: Ctx) => string[]
  snippets: (c: Ctx) => Snippet[]
  notes: string[]
}

const STORED = 'Stored and searchable. The digest finds new and unusual lines with a generic pattern finder; it does not read the fields of this device yet, and the bad-connection check does not use these lines yet.'
const at = (c: Ctx) => `${c.ip}:${c.port}`
const rsyslogTarget = (c: Ctx, selector = '*.*') => `${selector} action(type="omfwd" target="${c.ip}" port="${c.port}" protocol="${c.proto === 'tcp' ? 'tcp' : 'udp'}")`
const restartRsyslog: Snippet = { label: 'Terminal', code: 'sudo systemctl restart rsyslog' }
const testLogger: Snippet = { label: 'Send a test line', code: 'logger -t vedette-test "hello from this machine"' }

/** Cisco IOS / IOS-XE: dùng chung cho router và switch Catalyst. */
function ciosSnippets(c: Ctx): Snippet[] {
  return [{
    label: 'IOS / IOS-XE CLI (configure terminal)',
    code: ['service timestamps log datetime msec', `logging host ${c.ip} transport ${c.proto === 'tcp' ? 'tcp' : 'udp'} port ${c.port}`, 'logging trap informational'].join('\n'),
  }]
}
const ciosSteps = (_c: Ctx) => ['Open the CLI (console or SSH) and enter configuration mode with configure terminal.', 'Paste the block, then leave with end and save with write memory.']

const E: CatalogEntry[] = [
  // ───────── Firewalls and routers ─────────
  {
    // Nguồn: FortiOS CLI Reference, "config log syslogd setting" và "config log syslogd filter" (docs.fortinet.com, 7.4).
    id: 'fortigate', group: 'firewall', name: 'FortiGate (FortiOS)', keywords: 'fortinet fortios fgt', protos: ['udp', 'tcp', 'tls'], reads: 'parsed',
    readsNote: 'Reads traffic logs (source, destination, port, action) for the digest and bad-connection checks.',
    intro: 'Paste into the FortiGate CLI (the CLI Console button in the web UI, or SSH).',
    steps: () => ['Sign in to the FortiGate as an administrator and open the CLI.', 'Paste the first block to turn on syslog to the box.', 'Paste the second block if you only want information level and above.'],
    snippets: (c) => [
      { label: 'FortiOS CLI', code: ['config log syslogd setting', '    set status enable', `    set server "${c.ip}"`, `    set port ${c.port}`, `    set mode ${c.proto === 'udp' ? 'udp' : 'reliable'}`, ...(c.proto === 'tls' ? ['    set enc-algorithm high'] : []), 'end'].join('\n') },
      { label: 'FortiOS CLI (severity sent)', code: ['config log syslogd filter', '    set severity information', 'end'].join('\n') },
    ],
    notes: [
      'Traffic logs exist only when the firewall policy logs: in the policy choose Log Allowed Traffic, All Sessions.',
      'Modes: udp is UDP; reliable is syslog over TCP (RFC 6587); adding enc-algorithm makes it TLS. Do not use legacy-reliable: that is the RFC 3195 protocol and the box does not accept it.',
      'Syntax follows FortiOS 7.x. Older releases may differ in a few options: check the Fortinet CLI Reference for your version.',
    ],
  },
  {
    // Nguồn: Sophos Firewall Help, "Add a syslog server" (Configure > System services > Log settings); API SyslogServers (docs.sophos.com).
    id: 'sophos', group: 'firewall', name: 'Sophos Firewall (XG / XGS)', keywords: 'sophos xg xgs sfos', protos: ['udp'], reads: 'stored', readsNote: STORED,
    intro: 'Sophos Firewall is set up in the web admin console; there is no command to paste.',
    steps: (c) => [
      'Go to Configure, System services, Log settings.',
      'Under Syslog servers press Add.',
      `Enter a name (vedette), the IP address ${c.ip}, port ${c.port}, facility DAEMON, severity Information and format Device standard format.`,
      'Press Save, then tick the Syslog box next to each log type you want to send (for example Firewall, Authentication, System).',
    ],
    snippets: (c) => [{ label: 'Syslog server settings', code: [`Name: vedette`, `IP address/domain: ${c.ip}`, `Port: ${c.port}`, 'Facility: DAEMON', 'Severity: Information', 'Format: Device standard format'].join('\n') }],
    notes: ['Menu labels differ slightly between firmware versions (the secure log transmission option is for TLS: leave it off for plain UDP).', 'Check the Sophos Firewall help for your version.'],
  },
  {
    // Nguồn: PAN-OS Administrator's Guide, "Configure Syslog Monitoring" (docs.paloaltonetworks.com).
    id: 'paloalto', group: 'firewall', name: 'Palo Alto Networks (PAN-OS)', keywords: 'palo alto pan-os panos ngfw', protos: ['udp', 'tcp', 'tls'], reads: 'stored', readsNote: STORED,
    intro: 'PAN-OS is set up in the web interface: a syslog server profile, then a log forwarding profile used by your security rules.',
    steps: (c) => [
      `Go to Device, Server Profiles, Syslog and press Add. Name it vedette, add a server: IP ${c.ip}, transport ${c.proto === 'tls' ? 'SSL' : c.proto.toUpperCase()}, port ${c.port}, format ${c.proto === 'udp' ? 'BSD' : 'IETF'}, facility LOG_USER.`,
      'Go to Objects, Log Forwarding, Add. For each log type (traffic, threat, url...) add a match list that uses the vedette syslog profile.',
      'Edit your security policy rules, tab Actions, and choose that log forwarding profile.',
      'For system and configuration logs go to Device, Log Settings and add the syslog profile for each severity.',
      'Commit.',
    ],
    snippets: (c) => [{ label: 'Syslog server profile', code: ['Name: vedette', `Syslog Server: ${c.ip}`, `Transport: ${c.proto === 'tls' ? 'SSL' : c.proto.toUpperCase()}`, `Port: ${c.port}`, `Format: ${c.proto === 'udp' ? 'BSD' : 'IETF'}`, 'Facility: LOG_USER'].join('\n') }],
    notes: ['SSL needs a certificate trusted by the firewall and TLS 1.2 on the receiver.', 'Traffic logs are only produced for rules that have a log forwarding profile.'],
  },
  {
    // Nguồn: Cisco ASA Series CLI Configuration Guide, "Logging" (cisco.com).
    id: 'cisco-asa', group: 'firewall', name: 'Cisco ASA', keywords: 'cisco asa adaptive security appliance firepower asa', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Paste into the ASA CLI in global configuration mode. Replace inside with the interface that can reach the box.',
    steps: () => ['Open the CLI (console or SSH) and enter configure terminal.', 'Paste the block, replacing inside with the name of the interface that reaches the box.', 'Save with write memory.'],
    snippets: (c) => [{ label: 'ASA CLI', code: ['logging enable', 'logging timestamp', 'logging trap informational', `logging host inside ${c.ip} ${c.proto === 'tcp' ? 'tcp' : 'udp'}/${c.port}`, 'logging device-id hostname'].join('\n') }],
    notes: ['With TCP the ASA stops passing traffic if the box is unreachable, unless you add logging permit-hostdown. UDP does not have this risk.'],
  },
  {
    // Nguồn: Cisco Secure Firewall Management Center Administration Guide, "Configure Syslog" (Platform Settings).
    id: 'cisco-ftd', group: 'firewall', name: 'Cisco Secure Firewall (FTD / FMC)', keywords: 'cisco ftd fmc firepower threat defense secure firewall', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Firepower Threat Defense is set up in the Management Center, not on the device.',
    steps: (c) => [
      'In the Management Center go to Devices, Platform Settings and edit the policy used by this firewall.',
      `Open Syslog, tab Syslog Servers, press Add: IP address ${c.ip}, protocol ${c.proto.toUpperCase()}, port ${c.port}, and the interface that reaches the box.`,
      'Tab Logging Setup: tick Enable logging, then in Logging Destinations choose Syslog Servers with level Informational.',
      'In your Access Control Policy rules open Logging and tick Send Connection Events to Syslog.',
      'Save and deploy.',
    ],
    snippets: (c) => [{ label: 'Syslog server settings', code: [`IP Address: ${c.ip}`, `Protocol: ${c.proto.toUpperCase()}`, `Port: ${c.port}`, 'Logging level: Informational'].join('\n') }],
    notes: ['Menu names follow FMC 7.x; check the Cisco documentation for your release.'],
  },
  {
    id: 'cisco-ios', group: 'firewall', name: 'Cisco IOS / IOS-XE router', keywords: 'cisco ios ios-xe isr asr catalyst router', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Paste into the router CLI in configuration mode.', steps: ciosSteps, snippets: ciosSnippets,
    notes: ['Add logging source-interface <interface> if the box only accepts logs from one address.'],
  },
  {
    // Nguồn: Meraki documentation, "Syslog Server Overview and Configuration" (documentation.meraki.com).
    id: 'meraki', group: 'firewall', name: 'Cisco Meraki (MX / MR / MS)', keywords: 'meraki mx mr ms dashboard', protos: ['udp'], reads: 'stored', readsNote: STORED,
    intro: 'Meraki is set up in the Dashboard; there is no command to paste.',
    steps: (c) => [
      'In the Dashboard open Network-wide, Configure, General (in single-type networks the section is called Logging).',
      `Under Syslog servers press Add a syslog server: server IP ${c.ip}, port ${c.port}.`,
      'Pick the roles to send: Event log and Security events (MX) are the useful ones; add Flows and URLs if you want them stored.',
      'Press Save.',
    ],
    snippets: (c) => [{ label: 'Syslog server', code: [`Server IP: ${c.ip}`, `Port: ${c.port}`, 'Roles: Event log, Security events'].join('\n') }],
    notes: ['Meraki sends syslog over UDP. The Dashboard needs a path from the device to the box; the box must be reachable from the Meraki device, not from the cloud.'],
  },
  {
    // Nguồn: MikroTik RouterOS manual, "Log" (manual.mikrotik.com): syslog luôn đi bằng UDP.
    id: 'mikrotik', group: 'firewall', name: 'MikroTik (RouterOS)', keywords: 'mikrotik routeros winbox ccr rb hap', protos: ['udp'], reads: 'parsed',
    readsNote: 'Reads firewall log lines (source, destination, port) for the digest and bad-connection checks.',
    intro: 'Paste into the Terminal in WinBox, or SSH to the router.',
    steps: () => ['Open Terminal.', 'Paste all four lines. The first creates the destination, the other three choose which logs to send.'],
    snippets: (c) => [{ label: 'RouterOS terminal', code: [`/system logging action add name=vedette target=remote remote=${c.ip} remote-port=${c.port}`, '/system logging add action=vedette topics=firewall', '/system logging add action=vedette topics=info', '/system logging add action=vedette topics=critical'].join('\n') }],
    notes: ['RouterOS syslog always goes over UDP.', 'Firewall logs exist only for rules with logging on: add log=yes to the rules you want to watch.', 'The info topic is chatty. Remove the topics=info line if it is too noisy.', 'RouterOS 7: if lines reach the box in an odd shape, add remote-log-format=syslog to the action to send proper syslog format.'],
  },
  {
    // Nguồn: Netgate pfSense documentation, "Remote Logging with Syslog": pfSense chỉ gửi UDP.
    id: 'pfsense', group: 'firewall', name: 'pfSense', keywords: 'pfsense netgate', protos: ['udp'], reads: 'stored', readsNote: STORED,
    intro: 'pfSense is set up in the web interface; there is no command to paste.',
    steps: (c) => [
      'Go to Status, System Logs, tab Settings.',
      'Scroll to Remote Logging Options and tick Send log messages to remote syslog server (older releases say Enable Remote Logging).',
      `In Remote log servers enter ${at(c)}.`,
      'In Remote Syslog Contents tick Firewall Events and System Events (or Everything).',
      'Press Save.',
    ],
    snippets: (c) => [{ label: 'Remote log server', code: at(c) }],
    notes: ['pfSense sends syslog over UDP only. For TCP or TLS use OPNsense, or install the syslog-ng package on pfSense.', 'A firewall rule only logs when Log packets matched by this rule is ticked in that rule.'],
  },
  {
    // Nguồn: OPNsense manual, "Settings, Logging, Remote" (docs.opnsense.org).
    id: 'opnsense', group: 'firewall', name: 'OPNsense', keywords: 'opnsense deciso', protos: ['udp', 'tcp', 'tls'], reads: 'stored', readsNote: STORED,
    intro: 'OPNsense is set up in the web interface; there is no command to paste.',
    steps: (c) => [
      'Go to System, Settings, Logging, tab Remote, and press the plus sign.',
      `Transport: ${c.proto === 'udp' ? 'UDP' : c.proto === 'tcp' ? 'TCP' : 'TLS'} (IPv4). Hostname: ${c.ip}. Port: ${c.port}.`,
      'Leave Applications empty to send everything, or choose only the firewall (filter) log. Leave Levels and Facilities empty to send all.',
      'Press Save, then Apply.',
    ],
    snippets: (c) => [{ label: 'Remote destination', code: [`Transport: ${c.proto.toUpperCase()}4`, `Hostname: ${c.ip}`, `Port: ${c.port}`].join('\n') }],
    notes: ['A firewall rule only logs when Log is ticked in that rule.', 'TLS needs a client certificate selected in the Certificate field and a TLS listener on the receiver.'],
  },
  {
    // Nguồn: SonicWall SonicOS 7 Administration Guide, "Log > Syslog" (sonicwall.com/support).
    id: 'sonicwall', group: 'firewall', name: 'SonicWall (SonicOS)', keywords: 'sonicwall tz nsa nsv sonicos', protos: ['udp'], reads: 'stored', readsNote: STORED,
    intro: 'SonicWall is set up in the web interface; there is no command to paste.',
    steps: (c) => [
      'Go to Device, Log, Syslog (SonicOS 6.5: Log, Syslog) and press Add.',
      `Name vedette, server IP ${c.ip}, server port ${c.port}, syslog format Default, syslog ID firewall.`,
      'Press Save. Then go to Device, Log, Settings and make sure the log categories you want are set to send to syslog.',
    ],
    snippets: (c) => [{ label: 'Syslog server', code: ['Name: vedette', `Server IP: ${c.ip}`, `Server port: ${c.port}`, 'Syslog format: Default'].join('\n') }],
    notes: ['Check the SonicOS administration guide for your version: menu names change between 6.5 and 7.'],
  },
  {
    // Nguồn: WatchGuard Fireware Help, "Configure Logging and Notification" (watchguard.com).
    id: 'watchguard', group: 'firewall', name: 'WatchGuard (Fireware)', keywords: 'watchguard firebox fireware', protos: ['udp'], reads: 'stored', readsNote: STORED,
    intro: 'WatchGuard is set up in Fireware Web UI; there is no command to paste.',
    steps: (c) => [
      'Go to System, Logging, tab Syslog Server.',
      `Tick Send log messages to the syslog server at this IP address and enter ${c.ip}. Set port ${c.port}.`,
      'Set Log format to Syslog.',
      'In the Syslog settings table choose a facility for each log type you want to send (Traffic, Alarm, Event, Diagnostic), then press Save.',
    ],
    snippets: (c) => [{ label: 'Syslog server', code: [`IP address: ${c.ip}`, `Port: ${c.port}`, 'Log format: Syslog'].join('\n') }],
    notes: ['Menu names differ in Policy Manager (Setup, Logging). Check the Fireware help for your version.'],
  },
  {
    // Nguồn: Check Point R81 CLI Reference Guide, "cp_log_export" (sc1.checkpoint.com).
    id: 'checkpoint', group: 'firewall', name: 'Check Point (Log Exporter)', keywords: 'check point checkpoint gaia smartconsole', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Run on the Check Point management server or log server (Gaia expert mode). Log Exporter sends the logs the server receives.',
    steps: () => ['Open an SSH session to the management or log server and enter expert mode.', 'Paste the block.', 'Check that it is running with cp_log_export show.'],
    snippets: (c) => [{ label: 'Gaia expert mode', code: [`cp_log_export add name vedette target-server ${c.ip} target-port ${c.port} protocol ${c.proto === 'tcp' ? 'tcp' : 'udp'} format syslog`, 'cp_log_export restart name vedette'].join('\n') }],
    notes: ['Log Exporter is built into R81 and later; older versions need the Log Exporter package from Check Point.'],
  },
  {
    // Nguồn: Juniper TechLibrary, "Configuring System Logging" và "Configure Security Log Stream" (juniper.net).
    id: 'juniper-srx', group: 'firewall', name: 'Juniper SRX (Junos)', keywords: 'juniper srx junos', protos: ['udp'], reads: 'stored', readsNote: STORED,
    intro: 'Paste into the Junos CLI in configuration mode. Replace <srx-interface-ip> with the SRX address the box should see.',
    steps: () => ['Open the CLI and enter configure.', 'Paste the first block for system logs and the second for traffic (security) logs.', 'Run commit.'],
    snippets: (c) => [
      { label: 'System logs', code: [`set system syslog host ${c.ip} any notice`, `set system syslog host ${c.ip} port ${c.port}`].join('\n') },
      { label: 'Traffic (security) logs', code: ['set security log mode stream', 'set security log format syslog', 'set security log source-address <srx-interface-ip>', `set security log stream vedette host ${c.ip}`, `set security log stream vedette host port ${c.port}`, 'set security log stream vedette severity info'].join('\n') },
    ],
    notes: ['Security policies only produce logs when they have then log session-init or session-close.', 'Stream mode needs source-address; the device refuses the commit without it.'],
  },
  {
    // Nguồn: Huawei USG / AR Configuration Guide, "Information Center" (info.support.huawei.com).
    id: 'huawei', group: 'firewall', name: 'Huawei USG / AR', keywords: 'huawei usg ar vrp eudemon', protos: ['udp'], reads: 'stored', readsNote: STORED,
    intro: 'Paste into the device CLI in system view.',
    steps: () => ['Open the CLI and enter system-view.', 'Paste the block, then save with save.'],
    snippets: (c) => [{ label: 'VRP CLI', code: ['info-center enable', `info-center loghost ${c.ip} port ${c.port} facility local5`].join('\n') }],
    notes: ['USG firewalls also need session logging turned on (policy logging) to produce traffic logs: see the Huawei documentation for your model.'],
  },
  {
    // Nguồn: DrayTek Vigor manual, "System Maintenance > SysLog / Mail Alert Setup" (draytek.com).
    id: 'draytek', group: 'firewall', name: 'DrayTek Vigor', keywords: 'draytek vigor 2865 2927 2962', protos: ['udp'], reads: 'stored', readsNote: STORED,
    intro: 'DrayTek Vigor is set up in the web interface; there is no command to paste.',
    steps: (c) => [
      'Go to System Maintenance, SysLog / Mail Alert Setup.',
      `Tick Enable under Syslog Access Setup, tick Syslog Server, and enter server IP address ${c.ip} and destination port ${c.port}.`,
      'Tick the log types you want (Firewall Log, VPN Log, User Access Log, Call Log, WAN Log, Router/DSL information).',
      'Press OK.',
    ],
    snippets: (c) => [{ label: 'Syslog server', code: [`Server IP Address: ${c.ip}`, `Destination Port: ${c.port}`].join('\n') }],
    notes: ['Firewall rules log only when Syslog is ticked in the rule (Firewall, Filter Setup).'],
  },
  {
    // Nguồn: Ubiquiti Help Center (UniFi Network, "Remote Logging") và EdgeOS User Guide, "System, Syslog".
    id: 'ubiquiti', group: 'firewall', name: 'Ubiquiti UniFi gateway / EdgeRouter', keywords: 'ubiquiti unifi udm usg ucg edgerouter edgeos', protos: ['udp'], reads: 'stored', readsNote: STORED,
    intro: 'A UniFi gateway sends logs through the UniFi Network application; an EdgeRouter has a CLI.',
    steps: (c) => [
      `UniFi: open Settings, System (some versions: Control Plane, Integrations) and find Remote Logging or Activity Logging (Syslog). Enable it, enter ${c.ip} and port ${c.port}.`,
      'Choose the log types to send (device logs, firewall logs) and apply.',
      'EdgeRouter: open the CLI and paste the block under it.',
    ],
    snippets: (c) => [{ label: 'EdgeRouter CLI', code: ['configure', `set system syslog host ${c.ip} facility all level notice`, 'commit', 'save', 'exit'].join('\n') }],
    notes: ['EdgeOS sends to the standard syslog port 514 only.', 'The menu name for remote logging changes between UniFi Network versions: check the Ubiquiti help center for yours.'],
  },
  {
    // Nguồn: Zyxel USG FLEX / ATP User's Guide, "Log and Report > Log Settings" (zyxel.com).
    id: 'zyxel', group: 'firewall', name: 'Zyxel USG / ATP', keywords: 'zyxel usg flex atp zywall', protos: ['udp'], reads: 'stored', readsNote: STORED,
    intro: 'Zyxel is set up in the web interface; there is no command to paste.',
    steps: (c) => [
      'Go to Configuration, Log & Report, Log Settings, tab Remote Server, and edit Remote Server 1.',
      `Tick Active, set Log Format to Default, Server Address ${c.ip}, Server Port ${c.port} and Log Facility Local 1.`,
      'In the table of log categories choose the ones to send to this server (for example Security Policy Control, Authentication, System).',
      'Press Apply.',
    ],
    snippets: (c) => [{ label: 'Remote server', code: [`Server Address: ${c.ip}`, `Server Port: ${c.port}`, 'Log Format: Default', 'Log Facility: Local 1'].join('\n') }],
    notes: ['Choose Default format. CEF and VRPT formats are stored as text only.'],
  },
  {
    // Nguồn: TP-Link Omada SDN Controller User Guide, "Log Settings / Remote Logging" (omadanetworks.com).
    id: 'omada', group: 'firewall', name: 'TP-Link Omada', keywords: 'tp-link omada tplink er605 oc200', protos: ['udp'], reads: 'stored', readsNote: STORED,
    intro: 'Omada is set up in the Omada controller; there is no command to paste.',
    steps: (c) => [
      'Open the Omada controller and go to Settings, then the Log Settings page (under Controller Settings, Maintenance in newer versions).',
      `Turn on Remote Logging (Syslog), enter server ${c.ip} and port ${c.port}, and apply.`,
    ],
    snippets: (c) => [{ label: 'Remote logging', code: [`Server: ${c.ip}`, `Port: ${c.port}`].join('\n') }],
    notes: ['Where the setting lives depends on the controller version. Check the Omada user guide for yours.'],
  },

  // ───────── VPN and remote access ─────────
  {
    // Nguồn: Ivanti Connect Secure Administration Guide, "Configuring Syslog Servers" (System > Log/Monitoring).
    id: 'ivanti', group: 'vpn', name: 'Ivanti Connect Secure', keywords: 'ivanti pulse secure connect secure ics vpn', protos: ['udp'], reads: 'stored', readsNote: STORED,
    intro: 'Ivanti Connect Secure is set up in the admin console; there is no command to paste.',
    steps: (c) => [
      'Go to System, Log/Monitoring, Events, tab Settings. Repeat later for User Access and Admin Access.',
      `Under Syslog servers enter server name/IP ${c.ip}, facility LOCAL0 and filter Standard, then press Add.`,
      'Press Save Changes.',
    ],
    snippets: (c) => [{ label: 'Syslog server', code: [`Server name/IP: ${c.ip}`, 'Facility: LOCAL0', 'Filter: Standard'].join('\n') }],
    notes: ['Edge VPN appliances are common targets for exploited vulnerabilities: keep these logs and patch quickly.', 'Check the Ivanti administration guide for your version.'],
  },
  {
    // Nguồn: NetScaler documentation, "Configuring NetScaler appliance for audit logging" (docs.netscaler.com).
    id: 'netscaler', group: 'vpn', name: 'Citrix NetScaler (ADC / Gateway)', keywords: 'citrix netscaler adc gateway', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Paste into the NetScaler CLI (SSH as nsroot or another super user).',
    steps: () => ['Open the CLI.', 'Paste the block. The first line creates the destination, the second a policy that matches everything, the third turns it on globally.'],
    snippets: (c) => [{ label: 'NetScaler CLI', code: [`add audit syslogAction vedette ${c.ip} -serverPort ${c.port} -logLevel ALL${c.proto === 'tcp' ? ' -transport TCP' : ''}`, 'add audit syslogPolicy vedette-policy true vedette', 'bind system global vedette-policy -priority 100', 'save ns config'].join('\n') }],
    notes: ['Releases that use the advanced policy framework bind the policy with bind audit syslogGlobal instead: see the NetScaler audit logging page for your release.'],
  },
  {
    // Nguồn: OpenVPN Access Server System Administration Guide, "Logging" (openvpn.net): AS ghi log vào /var/log/openvpnas.log.
    id: 'openvpn-as', group: 'vpn', name: 'OpenVPN Access Server', keywords: 'openvpn access server openvpnas', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Access Server writes its log to a file on its own Linux host. rsyslog on that host forwards the file to the box.',
    steps: () => ['SSH to the Access Server host.', 'Create the rsyslog file below.', 'Restart rsyslog.'],
    snippets: (c) => [
      { label: '/etc/rsyslog.d/60-vedette.conf', code: ['module(load="imfile")', 'input(type="imfile" File="/var/log/openvpnas.log" Tag="openvpnas" Severity="info" Facility="local6")', rsyslogTarget(c, 'local6.*')].join('\n') },
      restartRsyslog,
    ],
    notes: ['Confirm the log path on your install (openvpnas.log is the default).'],
  },

  // ───────── Servers and operating systems ─────────
  {
    // Nguồn: NXLog Documentation, "Collecting logs from Windows Event Log" và "xm_syslog" (docs.nxlog.co).
    id: 'windows', group: 'server', name: 'Windows (via NXLog Community Edition)', keywords: 'windows server event log nxlog active directory domain controller', protos: ['udp', 'tcp'], reads: 'parsed',
    readsNote: 'Reads sign-in events (4624, 4625), account creation (4720), group changes (4732) and cleared logs (1102).',
    intro: 'Windows cannot send syslog by itself. Install NXLog Community Edition, a free tool that reads the Event Log and sends it to the box.',
    steps: () => [
      'Download NXLog Community Edition (the .msi file) from the NXLog site and install it on this Windows machine.',
      'Open nxlog.conf in Notepad run as Administrator.',
      'Keep the top of the file (define ROOT, Moduledir, CacheDir, Pidfile, LogFile…). Scroll to the end and paste the first block after it. It sends: successful (4624) and failed (4625) sign-ins, account creation (4720), group changes (4732), cleared security log (1102) and system errors.',
      'Restart the service with the PowerShell command in the second block.',
    ],
    snippets: (c) => [
      {
        label: 'C:\\Program Files\\nxlog\\conf\\nxlog.conf',
        code: [
          '<Extension syslog>', '    Module  xm_syslog', '</Extension>', '',
          '<Input eventlog>', '    Module  im_msvistalog',
          '    Query   <QueryList><Query Id="0"><Select Path="Security">*[System[(EventID=4624 or EventID=4625 or EventID=4720 or EventID=4732 or EventID=1102)]]</Select><Select Path="System">*[System[(Level=1 or Level=2)]]</Select></Query></QueryList>',
          '</Input>', '',
          '<Output vedette>', `    Module  ${c.proto === 'tcp' ? 'om_tcp' : 'om_udp'}`, `    Host    ${c.ip}`, `    Port    ${c.port}`,
          // Event Log có tab và xuống dòng trong $Message; syslog BSD không chứa được nên đổi thành dấu cách trước khi đóng gói.
          '    Exec    $Message =~ s/(\\t|\\R)/ /g; to_syslog_bsd();',
          '</Output>', '',
          '<Route vedette_route>', '    Path    eventlog => vedette', '</Route>',
        ].join('\n'),
      },
      { label: 'PowerShell (run as Administrator)', code: 'Restart-Service nxlog' },
    ],
    notes: [
      'NXLog is third-party software. You download and install it yourself; Vedette does not bundle it.',
      'If the file already has an Extension block using Module xm_syslog, drop that block from the pasted text to avoid a duplicate.',
      'Windows Event Forwarding (WEF) sends events between Windows machines, not syslog. To use it, install NXLog on the collector and read the Forwarded Events log: replace the Select Path lines in the Query with <Select Path="ForwardedEvents">*</Select>.',
    ],
  },
  {
    // Nguồn: rsyslog documentation, "omfwd: syslog forwarding output module" (rsyslog.com/doc).
    id: 'linux-rsyslog', group: 'server', name: 'Linux (rsyslog)', keywords: 'linux ubuntu debian centos rhel rocky alma rsyslog server', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Most Linux servers already run rsyslog. Add one forwarding rule and restart it.',
    steps: () => ['SSH to the server.', 'Create the file below.', 'Restart rsyslog, then send a test line.'],
    snippets: (c) => [{ label: '/etc/rsyslog.d/60-vedette.conf', code: rsyslogTarget(c) }, restartRsyslog, testLogger],
    notes: ['*.* forwards everything. To send only authentication logs use auth,authpriv.* instead.', 'TCP forwarding queues messages if the box is down; UDP drops them.'],
  },
  {
    // Nguồn: systemd journald.conf(5) ForwardToSyslog và rsyslog imuxsock/imjournal.
    id: 'linux-journald', group: 'server', name: 'Linux (systemd-journald via rsyslog)', keywords: 'journald journalctl systemd', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'journald keeps logs in its own store. Forward them to rsyslog, and rsyslog sends them to the box.',
    steps: () => ['Install rsyslog if it is missing (sudo apt install rsyslog, or sudo dnf install rsyslog).', 'Create the two files below.', 'Restart journald and rsyslog.'],
    snippets: (c) => [
      { label: '/etc/systemd/journald.conf.d/60-vedette.conf', code: ['[Journal]', 'ForwardToSyslog=yes'].join('\n') },
      { label: '/etc/rsyslog.d/60-vedette.conf', code: rsyslogTarget(c) },
      { label: 'Terminal', code: 'sudo systemctl restart systemd-journald rsyslog' },
    ],
    notes: ['On Red Hat family systems rsyslog already reads the journal; you only need the second file.'],
  },
  {
    // Nguồn: syslog-ng Open Source Edition Administration Guide, "network() destination" (syslog-ng.com).
    id: 'syslog-ng', group: 'server', name: 'syslog-ng', keywords: 'syslog-ng syslogng balabit', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Add a network destination and a log path to syslog-ng.',
    steps: () => ['Create the file below (on many systems files in /etc/syslog-ng/conf.d are included).', 'Restart syslog-ng.'],
    snippets: (c) => [
      { label: '/etc/syslog-ng/conf.d/vedette.conf', code: [`destination d_vedette { network("${c.ip}" port(${c.port}) transport("${c.proto === 'tcp' ? 'tcp' : 'udp'}")); };`, 'log { source(s_src); destination(d_vedette); };'].join('\n') },
      { label: 'Terminal', code: 'sudo systemctl restart syslog-ng' },
    ],
    notes: ['The source name (s_src) is the Debian and Ubuntu default. Use the source name from your own syslog-ng.conf.'],
  },

  // ───────── NAS and virtualisation ─────────
  {
    // Nguồn: Synology Knowledge Center, DSM Help, "Log Center > Log Sending" (kb.synology.com).
    id: 'synology', group: 'nas', name: 'Synology DSM (Log Center)', keywords: 'synology dsm diskstation nas log center', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Synology is set up in DSM; there is no command to paste. Log Center must be installed from Package Center.',
    steps: (c) => [
      'Open Log Center and go to Log Sending.',
      `Tick Send logs to a syslog server. Server ${c.ip}, port ${c.port}, protocol ${c.proto.toUpperCase()}, log format BSD (RFC 3164) or IETF (RFC 5424).`,
      'Press Send test log to check, then Apply.',
    ],
    snippets: (c) => [{ label: 'Log Sending', code: [`Server: ${c.ip}`, `Port: ${c.port}`, `Protocol: ${c.proto.toUpperCase()}`, 'Log format: BSD (RFC 3164)'].join('\n') }],
    notes: ['Synology NAS devices exposed to the Internet are common ransomware targets: keep these logs.'],
  },
  {
    // Nguồn: QNAP, "QuLog Center" và FAQ "What kind of syslog format can QNAP NAS receive and send?" (qnap.com).
    id: 'qnap', group: 'nas', name: 'QNAP (QuLog Center)', keywords: 'qnap qts quts qulog nas', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'QNAP is set up in QuLog Center; there is no command to paste.',
    steps: (c) => [
      'Open QuLog Center and go to Log Sender, then Send to Syslog Server (RFC 3164) or Send to QuLog Center (RFC 5424).',
      `Turn on sending, enter server ${c.ip}, port ${c.port}, protocol ${c.proto.toUpperCase()}.`,
      'Choose the log types to send (system events, access logs, connection logs) and apply.',
    ],
    snippets: (c) => [{ label: 'Syslog destination', code: [`Server: ${c.ip}`, `Port: ${c.port}`, `Protocol: ${c.proto.toUpperCase()}`].join('\n') }],
    notes: ['Menu names differ between QTS and QuTS hero versions: check the QNAP documentation for yours.'],
  },
  {
    // Nguồn: VMware ESXi documentation, "Configure Syslog on ESXi Hosts" (docs.vmware.com / techdocs.broadcom.com).
    id: 'esxi', group: 'nas', name: 'VMware ESXi', keywords: 'vmware esxi vsphere host hypervisor', protos: ['udp', 'tcp', 'tls'], reads: 'stored', readsNote: STORED,
    intro: 'Run on the ESXi host (SSH or the ESXi shell).',
    steps: () => ['Enable SSH on the host or open the shell from the console.', 'Paste the block.'],
    snippets: (c) => [{ label: 'ESXi shell', code: [`esxcli system syslog config set --loghost='${c.proto === 'tls' ? 'ssl' : c.proto}://${c.ip}:${c.port}'`, 'esxcli system syslog reload', 'esxcli network firewall ruleset set --ruleset-id=syslog --enabled=true', 'esxcli network firewall refresh'].join('\n') }],
    notes: ['vCenter can set this for many hosts at once: Host, Configure, System, Advanced System Settings, Syslog.global.logHost.', 'ssl:// needs the box to present a certificate the host trusts.'],
  },
  {
    // Nguồn: Proxmox VE Administration Guide, "System Software Updates / Logging": PVE ghi vào journald; chuyển tiếp bằng rsyslog.
    id: 'proxmox', group: 'nas', name: 'Proxmox VE', keywords: 'proxmox pve virtualization', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Proxmox VE logs to journald and has no remote syslog setting in its interface. Install rsyslog on the host and forward from there.',
    steps: () => ['SSH to the Proxmox host as root.', 'Install rsyslog, create the file below and restart.'],
    snippets: (c) => [
      { label: 'Terminal', code: 'apt install rsyslog' },
      { label: '/etc/rsyslog.d/60-vedette.conf', code: rsyslogTarget(c) },
      restartRsyslog,
    ],
    notes: ['The pveproxy access log and task logs are included because rsyslog reads the journal and /var/log/syslog.'],
  },

  // ───────── Security tools ─────────
  {
    // Nguồn: Suricata documentation, "Eve JSON Output" (docs.suricata.io 7.0): filetype syslog, identity, facility, level.
    id: 'suricata', group: 'security', name: 'Suricata', keywords: 'suricata ids ips eve', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Suricata writes eve events to the local syslog of the machine running it. rsyslog on that machine forwards them to the box.',
    steps: () => ['Edit the eve-log section in suricata.yaml as in the first block.', 'Create the rsyslog file as in the second block to forward facility local5 to the box.', 'Run the restart command in the third block.'],
    snippets: (c) => [
      { label: 'suricata.yaml', code: ['outputs:', '  - eve-log:', '      enabled: yes', '      filetype: syslog', '      identity: "suricata"', '      facility: local5', '      level: Info', '      types:', '        - alert', '        - dns', '        - http', '        - tls'].join('\n') },
      { label: '/etc/rsyslog.d/60-vedette.conf', code: rsyslogTarget(c, 'local5.*') },
      { label: 'Terminal', code: 'sudo systemctl restart rsyslog suricata' },
    ],
    notes: [],
  },
  {
    // Nguồn: Zeek documentation, "Log Files" và policy/tuning/json-logs; rsyslog imfile.
    id: 'zeek', group: 'security', name: 'Zeek', keywords: 'zeek bro network monitor', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Zeek writes log files, not syslog. Switch them to JSON and let rsyslog on the same machine forward the files.',
    steps: () => ['Add the JSON policy to local.zeek and redeploy (zeekctl deploy).', 'Create the rsyslog file below. Add one input line per log you want (conn.log, dns.log, notice.log).', 'Restart rsyslog.'],
    snippets: (c) => [
      { label: 'local.zeek', code: '@load policy/tuning/json-logs' },
      { label: '/etc/rsyslog.d/60-vedette.conf', code: ['module(load="imfile")', 'input(type="imfile" File="/opt/zeek/logs/current/notice.log" Tag="zeek-notice" Severity="info" Facility="local6")', 'input(type="imfile" File="/opt/zeek/logs/current/dns.log" Tag="zeek-dns" Severity="info" Facility="local6")', rsyslogTarget(c, 'local6.*')].join('\n') },
      restartRsyslog,
    ],
    notes: ['The path /opt/zeek is the default for a source install; packages may use /var/log/zeek or /usr/local/zeek.', 'conn.log is large. Start with notice.log and dns.log.'],
  },
  {
    // Nguồn: Wazuh documentation, "Alert management > Syslog output" (documentation.wazuh.com): khối <syslog_output> trong ossec.conf.
    id: 'wazuh', group: 'security', name: 'Wazuh manager (forward alerts)', keywords: 'wazuh ossec siem manager', protos: ['udp'], reads: 'stored', readsNote: STORED,
    intro: 'Run on the Wazuh manager. It forwards the alerts it generates to the box.',
    steps: () => ['Open /var/ossec/etc/ossec.conf on the manager.', 'Add the block inside <ossec_config>.', 'Restart the manager.'],
    snippets: (c) => [
      { label: '/var/ossec/etc/ossec.conf', code: ['<syslog_output>', `  <server>${c.ip}</server>`, `  <port>${c.port}</port>`, '  <level>7</level>', '  <format>json</format>', '</syslog_output>'].join('\n') },
      { label: 'Terminal', code: 'sudo systemctl restart wazuh-manager' },
    ],
    notes: ['level is the minimum alert level forwarded (7 and above here). Without it every alert is sent.', 'Wazuh forwards over UDP.'],
  },
  {
    // Nguồn: CrowdSec documentation: không có đầu ra syslog; ghi /var/log/crowdsec.log.
    id: 'crowdsec', group: 'security', name: 'CrowdSec', keywords: 'crowdsec bouncer ids', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'CrowdSec has no syslog output. Forward its log file with rsyslog on the same machine.',
    steps: () => ['Create the rsyslog file below.', 'Restart rsyslog.'],
    snippets: (c) => [
      { label: '/etc/rsyslog.d/60-vedette.conf', code: ['module(load="imfile")', 'input(type="imfile" File="/var/log/crowdsec.log" Tag="crowdsec" Severity="info" Facility="local6")', rsyslogTarget(c, 'local6.*')].join('\n') },
      restartRsyslog,
    ],
    notes: ['This forwards CrowdSec service logs. The decisions it makes (bans) stay in its own database: cscli decisions list.'],
  },

  // ───────── Web, proxy, DNS and mail ─────────
  {
    // Nguồn: nginx documentation, "Configuring Logging" (nginx.org): access_log syslog:server=...; chỉ UDP.
    id: 'nginx', group: 'web', name: 'nginx', keywords: 'nginx web server reverse proxy', protos: ['udp'], reads: 'stored', readsNote: STORED,
    intro: 'Add syslog targets to the nginx config. nginx sends syslog over UDP only.',
    steps: () => ['Edit nginx.conf (or the site file) and add the two lines in the http block.', 'Test with nginx -t and reload.'],
    snippets: (c) => [
      { label: 'nginx.conf (http block)', code: [`access_log syslog:server=${at(c)},facility=local7,tag=nginx,severity=info combined;`, `error_log syslog:server=${at(c)},facility=local7,tag=nginx_error;`].join('\n') },
      { label: 'Terminal', code: 'sudo nginx -t && sudo systemctl reload nginx' },
    ],
    notes: ['Replace existing access_log and error_log lines, or keep them to log to the local file as well.'],
  },
  {
    // Nguồn: Apache HTTP Server documentation, "Log Files" (httpd.apache.org): ErrorLog syslog, CustomLog piped to logger.
    id: 'apache', group: 'web', name: 'Apache httpd', keywords: 'apache httpd apache2 web server', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Apache logs to syslog locally; rsyslog on the same machine forwards to the box.',
    steps: () => ['Edit the Apache config (VirtualHost or apache2.conf) with the two lines.', 'Create the rsyslog file and restart both services.'],
    snippets: (c) => [
      { label: 'Apache config', code: ['ErrorLog syslog:local6', 'CustomLog "|/usr/bin/logger -t apache -p local6.info" combined'].join('\n') },
      { label: '/etc/rsyslog.d/60-vedette.conf', code: rsyslogTarget(c, 'local6.*') },
      { label: 'Terminal', code: 'sudo systemctl restart rsyslog && sudo systemctl reload apache2' },
    ],
    notes: ['The service is called httpd on Red Hat family systems.'],
  },
  {
    // Nguồn: Squid documentation, "access_log" (squid-cache.org): access_log syslog:facility.priority.
    id: 'squid', group: 'web', name: 'Squid proxy', keywords: 'squid proxy cache', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Squid writes access logs to syslog locally; rsyslog on the same machine forwards them.',
    steps: () => ['Edit squid.conf and add the access_log line.', 'Create the rsyslog file and restart both services.'],
    snippets: (c) => [
      { label: 'squid.conf', code: 'access_log syslog:local6.info squid' },
      { label: '/etc/rsyslog.d/60-vedette.conf', code: rsyslogTarget(c, 'local6.*') },
      { label: 'Terminal', code: 'sudo systemctl restart rsyslog && sudo squid -k reconfigure' },
    ],
    notes: [],
  },
  {
    // Nguồn: Pi-hole documentation, "Log files" (/var/log/pihole/pihole.log) và dnsmasq log-facility.
    id: 'pihole', group: 'web', name: 'Pi-hole / dnsmasq', keywords: 'pihole pi-hole dnsmasq dns sinkhole', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Pi-hole writes its DNS query log to a file. rsyslog on the same machine forwards the file.',
    steps: () => ['Create the rsyslog file below.', 'Restart rsyslog.'],
    snippets: (c) => [
      { label: '/etc/rsyslog.d/60-vedette.conf', code: ['module(load="imfile")', 'input(type="imfile" File="/var/log/pihole/pihole.log" Tag="pihole" Severity="info" Facility="local6")', rsyslogTarget(c, 'local6.*')].join('\n') },
      restartRsyslog,
    ],
    notes: ['Plain dnsmasq: add log-queries and log-facility=local6 to dnsmasq.conf and forward local6.* with rsyslog instead of the imfile input.', 'Query logs are large on busy networks.'],
  },
  {
    // Nguồn: BIND 9 Administrator Reference Manual, "logging statement" (bind9.readthedocs.io).
    id: 'bind', group: 'web', name: 'BIND (named)', keywords: 'bind named dns server', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'BIND logs to local syslog with a channel; rsyslog on the same machine forwards it.',
    steps: () => ['Add the logging block to named.conf (or named.conf.options).', 'Create the rsyslog file, reload BIND and restart rsyslog.'],
    snippets: (c) => [
      { label: 'named.conf', code: ['logging {', '    channel vedette { syslog local6; severity info; print-time yes; };', '    category default { vedette; };', '    category queries { vedette; };', '};'].join('\n') },
      { label: '/etc/rsyslog.d/60-vedette.conf', code: rsyslogTarget(c, 'local6.*') },
      { label: 'Terminal', code: 'sudo rndc reconfig && sudo systemctl restart rsyslog' },
    ],
    notes: ['The queries category is very chatty; remove it if you only need errors and security events.'],
  },
  {
    // Nguồn: Microsoft Learn, "DNS logging and diagnostics" (kênh Microsoft-Windows-DNSServer/Audit) và NXLog im_msvistalog.
    id: 'windows-dns', group: 'web', name: 'Windows DNS Server (via NXLog)', keywords: 'windows dns server microsoft dns nxlog', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Use NXLog Community Edition on the DNS server to send the DNS audit events.',
    steps: () => ['Install NXLog Community Edition on the DNS server.', 'Append the block to nxlog.conf (keep the top of the file).', 'Restart the NXLog service.'],
    snippets: (c) => [
      { label: 'C:\\Program Files\\nxlog\\conf\\nxlog.conf', code: ['<Extension syslog>', '    Module  xm_syslog', '</Extension>', '', '<Input dns>', '    Module  im_msvistalog', '    Query   <QueryList><Query Id="0"><Select Path="Microsoft-Windows-DNSServer/Audit">*</Select></Query></QueryList>', '</Input>', '', '<Output vedette_dns>', `    Module  ${c.proto === 'tcp' ? 'om_tcp' : 'om_udp'}`, `    Host    ${c.ip}`, `    Port    ${c.port}`, '    Exec    $Message =~ s/(\\t|\\R)/ /g; to_syslog_bsd();', '</Output>', '', '<Route dns_route>', '    Path    dns => vedette_dns', '</Route>'].join('\n') },
      { label: 'PowerShell (run as Administrator)', code: 'Restart-Service nxlog' },
    ],
    notes: ['The audit channel records zone and record changes. Query logging needs DNS debug logging turned on in the DNS Manager, and the file is read with im_file.'],
  },
  {
    // Nguồn: Postfix documentation, "Postfix logging": ghi qua syslog, facility mail.
    id: 'postfix', group: 'web', name: 'Postfix', keywords: 'postfix mail smtp mta', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Postfix logs to the mail facility of local syslog. rsyslog on the same machine forwards it.',
    steps: () => ['Create the rsyslog file below.', 'Restart rsyslog.'],
    snippets: (c) => [{ label: '/etc/rsyslog.d/60-vedette.conf', code: rsyslogTarget(c, 'mail.*') }, restartRsyslog],
    notes: ['Newer Postfix versions can log to a file or stdout instead of syslog (maillog_file). If so, use an imfile input on that file.'],
  },

  // ───────── Switches and Wi-Fi ─────────
  {
    id: 'cisco-switch', group: 'switch', name: 'Cisco Catalyst switch (IOS / IOS-XE)', keywords: 'cisco catalyst switch 2960 9200 9300', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Paste into the switch CLI in configuration mode.', steps: ciosSteps, snippets: ciosSnippets, notes: [],
  },
  {
    // Nguồn: Aruba AOS-CX Command-Line Interface Guide, "logging" (arubanetworks.com).
    id: 'aruba-cx', group: 'switch', name: 'Aruba switch (AOS-CX)', keywords: 'aruba aos-cx cx 6000 6100 6300', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Paste into the AOS-CX CLI in configuration mode.',
    steps: () => ['Open the CLI and enter configure.', 'Paste the line, then save with write memory.'],
    snippets: (c) => [{ label: 'AOS-CX CLI', code: `logging ${c.ip} ${c.proto === 'tcp' ? 'tcp' : 'udp'} ${c.port} severity info` }],
    notes: ['If the box is reached through a VRF other than default, add vrf <name> to the line. Check the CLI guide for your version.'],
  },
  {
    // Nguồn: HPE ArubaOS-Switch Management and Configuration Guide, "Event Log / Debug and Syslog".
    id: 'hpe-procurve', group: 'switch', name: 'HPE / Aruba switch (ArubaOS-Switch, ProCurve)', keywords: 'hpe procurve aruba 2530 2930 arubaos-switch', protos: ['udp'], reads: 'stored', readsNote: STORED,
    intro: 'Paste into the switch CLI in configuration mode.',
    steps: () => ['Open the CLI and enter configure.', 'Paste the block, then save with write memory.'],
    snippets: (c) => [{ label: 'ArubaOS-Switch CLI', code: [`logging ${c.ip}`, 'logging facility local5', 'logging severity info'].join('\n') }],
    notes: ['These switches send to port 514 only.'],
  },
  {
    // Nguồn: HPE FlexNetwork Comware 7 Network Management and Monitoring Configuration Guide, "Information center".
    id: 'hpe-comware', group: 'switch', name: 'HPE Comware / H3C switch', keywords: 'hpe comware h3c 1910 1950 5130 5140', protos: ['udp'], reads: 'stored', readsNote: STORED,
    intro: 'Paste into the switch CLI in system view.',
    steps: () => ['Open the CLI and enter system-view.', 'Paste the block, then save.'],
    snippets: (c) => [{ label: 'Comware CLI', code: ['info-center enable', `info-center loghost ${c.ip} port ${c.port} facility local5`].join('\n') }],
    notes: [],
  },
  {
    // Nguồn: Ubiquiti Help Center, "UniFi Network Settings: System, Remote Logging".
    id: 'unifi', group: 'switch', name: 'UniFi switches and access points (controller)', keywords: 'unifi controller switch access point uap usw', protos: ['udp'], reads: 'stored', readsNote: STORED,
    intro: 'UniFi devices send syslog under the control of the UniFi Network application.',
    steps: (c) => [
      'Open the UniFi Network application and go to Settings, System (some versions: Control Plane, Integrations).',
      `Find Remote Logging or Activity Logging (Syslog), enable it, and enter ${c.ip} and port ${c.port}.`,
      'Apply.',
    ],
    snippets: (c) => [{ label: 'Remote logging', code: [`Host: ${c.ip}`, `Port: ${c.port}`].join('\n') }],
    notes: ['The menu name changes between UniFi Network versions: check the Ubiquiti help center for yours. You can also set it per device (Device settings, Services, Remote Logging).'],
  },

  // ───────── Other and generic ─────────
  {
    id: 'syslog-generic', group: 'other', name: 'Other device (standard syslog, RFC 3164 / 5424)', keywords: 'syslog generic other rfc 3164 5424 unknown', protos: ['udp', 'tcp', 'tls'], reads: 'stored', readsNote: STORED,
    intro: 'Any device or program that can send standard syslog works. Point it at the address below.',
    steps: (c) => [`Find the remote syslog (or log server) setting in the device and enter ${c.ip}.`, `Set the port to ${c.port} and the protocol to ${c.proto.toUpperCase()}.`, 'Choose the log types to send and save.'],
    snippets: (c) => [{ label: 'Where to send', code: [`Server: ${c.ip}`, `Port: ${c.port}`, `Protocol: ${c.proto.toUpperCase()}`, 'Format: RFC 3164 or RFC 5424'].join('\n') }],
    notes: ['Vedette keeps the line text and time. It does not read device-specific fields from this source.'],
  },
  {
    id: 'cef-leef', group: 'other', name: 'Other device (CEF or LEEF over syslog)', keywords: 'cef leef arcsight qradar common event format', protos: ['udp', 'tcp'], reads: 'stored', readsNote: STORED,
    intro: 'Devices that can export CEF or LEEF over syslog. Choose that format in the device and point it at the address below.',
    steps: (c) => [`In the device, set the log format to CEF or LEEF and the destination to ${c.ip}.`, `Set the port to ${c.port} and the protocol to ${c.proto.toUpperCase()}.`],
    snippets: (c) => [{ label: 'Where to send', code: [`Server: ${c.ip}`, `Port: ${c.port}`, `Protocol: ${c.proto.toUpperCase()}`, 'Format: CEF or LEEF'].join('\n') }],
    notes: ['CEF and LEEF header lines are stored as text and searchable. Their fields are not parsed yet.'],
  },
]

export const CATALOG: Record<KindId, CatalogEntry> = Object.fromEntries(E.map((e) => [e.id, e])) as Record<KindId, CatalogEntry>
export const ENTRIES: CatalogEntry[] = E

/** Tìm theo tên, từ khoá, nhóm: mọi từ trong ô tìm phải khớp (không phân biệt hoa thường). */
export function searchCatalog(q: string): CatalogEntry[] {
  const words = q.toLowerCase().split(/\s+/).filter(Boolean)
  if (!words.length) return E
  return E.filter((e) => {
    const hay = `${e.name} ${e.keywords} ${GROUP_LABEL[e.group]}`.toLowerCase()
    return words.every((w) => hay.includes(w))
  })
}

export const protosOf = (k: KindId): Proto[] => CATALOG[k].protos
