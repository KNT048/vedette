// 30 devices like a Vietnamese SMB (display names in English). SAMPLE DATA, shown with the "Sample data" label.
// Fixed IDs for other modules to reference: a-fw01, a-nas02 (finding f-1), a-web01 (f-2), a-srvad (f-3)...
import type { Asset, AssetKind, ObsSource, Service, Software } from '@/lib/types'

const D = (days: number) => new Date(Date.now() - days * 864e5).toISOString()
const H = (hours: number) => new Date(Date.now() - hours * 36e5).toISOString()
const o = (value: string, source: ObsSource, confidence: number, days = 0) => ({ value, source, confidence, seen_at: D(days) })
const sw = (id: string, display: string, vendor: string, product: string, version: string | null, kev: string[], source: ObsSource, confidence: number): Software => ({ id, display, vendor, product, version, kev, source, confidence })
const svc = (port: number, name: string, source: ObsSource = 'nmap', confidence = 0.8, product?: string, version?: string): Service => ({ port, proto: 'tcp', name, product, version, source, confidence })

function a(p: Partial<Asset> & { id: string; ip: string; kind: AssetKind }): Asset {
  return {
    site: 'hq', mac: null, hostname: null, vendor: null, model: null, os: null, software: [], services: [],
    first_seen: D(40), last_seen: D(0), approved: true, fragile: false, origin: 'discovered', ...p,
  }
}

export function seedAssets(): Asset[] {
  const pcs: Asset[] = [
    ['accounts-01', 'Windows 11 Pro 23H2', 'Dell'], ['accounts-02', 'Windows 11 Pro 23H2', 'Dell'], ['accounts-03', 'Windows 10 Pro 22H2', 'HP'],
    ['sales-01', 'Windows 11 Pro 24H2', 'Lenovo'], ['sales-02', 'Windows 11 Pro 24H2', 'Lenovo'], ['sales-03', 'Windows 10 Pro 22H2', 'Asus'],
    ['hr-01', 'Windows 11 Pro 23H2', 'HP'], ['store-01', 'Windows 10 Pro 22H2', 'Dell'], ['director-laptop', 'Windows 11 Pro 24H2', 'Lenovo'],
    ['design-01', 'macOS 15', 'Apple'], ['design-02', 'macOS 14', 'Apple'], ['reception-01', 'Windows 10 Pro 22H2', 'Acer'],
  ].map(([h, os, v], i) => a({
    id: `a-pc${String(i + 1).padStart(2, '0')}`, ip: `192.168.10.${101 + i}`, kind: 'pc', hostname: `PC-${h!.toUpperCase()}`,
    mac: `3c:52:82:1a:${(16 + i).toString(16)}:0${i % 10}`, vendor: o(v!, 'passive', 0.9), os: o(os!, os!.startsWith('mac') ? 'passive' : 'nmap', 0.7),
    software: os!.startsWith('mac') ? [sw(`s-pc${i}`, 'macOS', 'Apple', 'macOS', os!.slice(6), ['apple|macos', 'apple|multiple products'], 'passive', 0.6)]
      : [sw(`s-pc${i}`, 'Windows', 'Microsoft', 'Windows', os!.replace('Windows ', ''), ['microsoft|windows'], 'nmap', 0.7)],
    services: os!.startsWith('mac') ? [] : [svc(445, 'microsoft-ds'), svc(3389, 'ms-wbt-server', 'nmap', 0.6)],
  }))

  return [
    a({ id: 'a-fw01', ip: '192.168.10.1', kind: 'firewall', hostname: 'FW-HQ', mac: '00:09:0f:aa:01:01', vendor: o('Fortinet', 'passive', 0.95), model: o('FortiGate 60F', 'snmp', 0.9), os: o('FortiOS 7.2', 'snmp', 0.6),
      software: [sw('s-fw01', 'FortiGate firewall', 'Fortinet', 'FortiOS', '7.2', ['fortinet|fortios', 'fortinet|multiple products'], 'snmp', 0.6),
        // three sources of one software: the agent's package, a person's entry on the scan banner, the banner itself (one line, no notice)
        { ...sw('s-fw01-ssh-agent', 'OpenSSH', 'OpenBSD', 'OpenSSH', '10.2p1', ['openbsd|openssh'], 'agent', 0.95), pkg_version: '10.2_p1-r1' },
        { ...sw('s-fw01-ssh-entry', 'OpenSSH', 'OpenBSD', 'OpenSSH', '10.2', ['openbsd|openssh'], 'manual', 1), pkg_version: '10.2_p1-r1', corrects: 's-fw01-ssh-nmap', set_at: D(1) },
        sw('s-fw01-ssh-nmap', 'OpenSSH', 'OpenBSD', 'OpenSSH', '10.2', ['openbsd|openssh'], 'nmap', 0.7),
        // an entry and a newer banner of another release: one line, the one notice
        { ...sw('s-fw01-web-entry', 'nginx', 'F5', 'nginx', '1.24.0', ['f5|nginx'], 'manual', 1), set_at: D(3) },
        sw('s-fw01-web-nmap', 'nginx', 'F5', 'nginx', '1.26.1', ['f5|nginx'], 'nmap', 0.7)],
      services: [svc(443, 'https', 'nmap', 0.9, 'FortiGate SSL VPN'), svc(22, 'ssh', 'nmap', 0.9), svc(541, 'fgfm', 'nmap', 0.7)] }),
    a({ id: 'a-rt02', ip: '192.168.10.2', kind: 'router', hostname: 'RT-BACKUP', mac: '48:a9:8a:10:22:02', vendor: o('MikroTik', 'passive', 0.95), model: o('hAP ax²', 'snmp', 0.85), os: o('RouterOS 7.14', 'snmp', 0.8),
      software: [sw('s-rt02', 'MikroTik router', 'MikroTik', 'RouterOS', '7.14', ['mikrotik|routeros'], 'snmp', 0.8)], services: [svc(8291, 'winbox'), svc(80, 'http', 'nmap', 0.8, 'MikroTik WebFig')] }),
    a({ id: 'a-sw01', ip: '192.168.10.3', kind: 'switch', hostname: 'SW-CORE', mac: 'f8:7b:20:30:33:03', vendor: o('Cisco', 'passive', 0.9), model: o('CBS350-24P', 'snmp', 0.9), os: o('CBS350 firmware 3.4', 'snmp', 0.8), services: [svc(443, 'https')] }),
    a({ id: 'a-ap01', ip: '192.168.10.4', kind: 'ap', hostname: 'AP-FLOOR1', mac: '74:ac:b9:40:44:04', vendor: o('Ubiquiti', 'passive', 0.9), model: o('U6 Lite', 'passive', 0.7), fragile: true }),
    a({ id: 'a-ap02', ip: '192.168.10.5', kind: 'ap', hostname: 'AP-FLOOR2', mac: '74:ac:b9:40:44:05', vendor: o('Ubiquiti', 'passive', 0.9), model: o('U6 Lite', 'passive', 0.7), fragile: true }),
    a({ id: 'a-srvad', ip: '192.168.10.10', kind: 'server', hostname: 'SRV-AD', mac: '00:15:5d:0a:10:10', vendor: o('Dell', 'passive', 0.8), model: o('PowerEdge T140', 'snmp', 0.8), os: o('Windows Server 2016', 'nmap', 0.75),
      software: [sw('s-srvad', 'Windows Server 2016', 'Microsoft', 'Windows', 'Server 2016 (1607)', ['microsoft|windows', 'microsoft|windows server'], 'nmap', 0.75)],
      services: [svc(53, 'domain'), svc(88, 'kerberos'), svc(389, 'ldap'), svc(445, 'microsoft-ds'), svc(3389, 'ms-wbt-server')] }),
    a({ id: 'a-srvfile', ip: '192.168.10.11', kind: 'server', hostname: 'SRV-FILE', mac: '00:15:5d:0a:10:11', vendor: o('Dell', 'passive', 0.8), os: o('Windows Server 2019', 'nmap', 0.75),
      // SQL Server added by hand without its version (Needs your input: type it there, or Not installed)
      software: [sw('s-srvfile', 'Windows Server 2019', 'Microsoft', 'Windows', 'Server 2019 (1809)', ['microsoft|windows', 'microsoft|windows server'], 'nmap', 0.75),
        sw('s-srvfile-sql', 'Microsoft SQL Server', 'Microsoft', 'SQL Server', null, ['microsoft|sql server'], 'manual', 1)], services: [svc(445, 'microsoft-ds'), svc(3389, 'ms-wbt-server')] }),
    a({ id: 'a-web01', ip: '192.168.10.12', kind: 'server', hostname: 'WEB01', mac: '00:15:5d:0a:10:12', vendor: o('VMware', 'passive', 0.7), os: o('Ubuntu 22.04', 'nmap', 0.8),
      software: [sw('s-web01-wp', 'WordPress website', 'WordPress', 'WordPress Core', '7.1.x', ['wordpress|wordpress core', 'wordpress|core'], 'nmap', 0.5), sw('s-web01-php', 'PHP', 'PHP Group', 'PHP', '8.1', ['php group|php'], 'nmap', 0.6)],
      services: [svc(22, 'ssh', 'nmap', 0.9, 'OpenSSH', '8.9p1'), svc(80, 'http', 'nmap', 0.9, 'nginx'), svc(443, 'https', 'nmap', 0.9, 'nginx')] }),
    a({ id: 'a-srvacc', ip: '192.168.10.13', kind: 'server', hostname: 'SRV-ACCOUNTS', mac: '00:15:5d:0a:10:13', vendor: o('HPE', 'passive', 0.8), os: o('Windows Server 2022', 'nmap', 0.75),
      software: [sw('s-srvacc', 'Windows Server 2022', 'Microsoft', 'Windows', 'Server 2022', ['microsoft|windows', 'microsoft|windows server'], 'nmap', 0.75), sw('s-srvacc-sql', 'Microsoft SQL Server', 'Microsoft', 'SQL Server', '2019', ['microsoft|sql server'], 'nmap', 0.7)],
      services: [svc(1433, 'ms-sql-s', 'nmap', 0.8, 'Microsoft SQL Server 2019'), svc(3389, 'ms-wbt-server')] }),
    a({ id: 'a-nas01', ip: '192.168.10.20', kind: 'nas', hostname: 'NAS-BACKUP', mac: '00:11:32:aa:20:20', vendor: o('Synology', 'passive', 0.95), model: o('DS920+', 'passive', 0.8), os: o('DSM 7.2', 'nmap', 0.5), fragile: true,
      software: [sw('s-nas01', 'Synology NAS (DSM)', 'Synology', 'DiskStation Manager', '7.2', ['synology|diskstation manager', 'synology|dsm'], 'nmap', 0.5)], services: [svc(5000, 'http', 'passive', 0.7, 'Synology DSM'), svc(5001, 'https', 'passive', 0.7)] }),
    a({ id: 'a-nas02', ip: '192.168.10.21', kind: 'nas', hostname: 'NAS-PHOTOS', mac: '24:5e:be:aa:21:21', vendor: o('QNAP', 'passive', 0.95), model: o('TS-453D', 'passive', 0.8), os: o('QTS 5.0.1', 'nmap', 0.6), fragile: true,
      software: [sw('s-nas02', 'QNAP NAS (QTS)', 'QNAP', 'QTS', '5.0.1', ['qnap|qts'], 'nmap', 0.6), sw('s-nas02-ps', 'QNAP Photo Station', 'QNAP', 'Photo Station', '6.0.20', ['qnap|photo station'], 'scan', 0.95)],
      services: [svc(8080, 'http', 'nmap', 0.9, 'QNAP QTS', '5.1.0'), svc(443, 'https', 'nmap', 0.9), svc(80, 'http', 'nmap', 0.8, 'Photo Station')] }),
    ...pcs,
    a({ id: 'a-prn01', ip: '192.168.10.201', kind: 'printer', hostname: 'HP-M404', vendor: o('HP', 'passive', 0.9), model: o('LaserJet Pro M404dn', 'snmp', 0.9), fragile: true, services: [svc(9100, 'jetdirect', 'passive', 0.7)] }),
    a({ id: 'a-prn02', ip: '192.168.10.202', kind: 'printer', hostname: 'CANON-LBP', vendor: o('Canon', 'passive', 0.9), model: o('LBP6030', 'passive', 0.6), fragile: true }),
    a({ id: 'a-prn03', ip: '192.168.10.203', kind: 'printer', hostname: 'BROTHER-STORE', vendor: o('Brother', 'passive', 0.9), model: o('HL-L2321D', 'passive', 0.5), fragile: true, approved: false, first_seen: D(1) }),
    a({ id: 'a-cam01', ip: '192.168.20.11', kind: 'camera', hostname: 'CAM-GATE', vendor: o('Hikvision', 'passive', 0.95), model: o('DS-2CD1023G0', 'passive', 0.7), fragile: true,
      software: [sw('s-cam01', 'Hikvision camera', 'Hikvision', 'IP Camera firmware', null, ['hikvision|multiple products', 'hikvision|security cameras web server'], 'passive', 0.5)], services: [svc(80, 'http', 'passive', 0.6), svc(554, 'rtsp', 'passive', 0.6)] }),
    a({ id: 'a-cam02', ip: '192.168.20.12', kind: 'camera', hostname: 'CAM-STORE', vendor: o('Hikvision', 'passive', 0.95), model: o('DS-2CD1023G0', 'passive', 0.7), fragile: true,
      software: [sw('s-cam02', 'Hikvision camera', 'Hikvision', 'IP Camera firmware', null, ['hikvision|multiple products', 'hikvision|security cameras web server'], 'passive', 0.5)] }),
    a({ id: 'a-cam03', ip: '192.168.20.13', kind: 'camera', hostname: 'CAM-LOBBY', vendor: o('Hikvision', 'passive', 0.95), model: o('DS-2CD1043G0', 'passive', 0.7), fragile: true,
      software: [sw('s-cam03', 'Hikvision camera', 'Hikvision', 'IP Camera firmware', null, ['hikvision|multiple products', 'hikvision|security cameras web server'], 'passive', 0.5)] }),
    a({ id: 'a-nvr01', ip: '192.168.20.10', kind: 'nvr', hostname: 'NVR-01', vendor: o('Hikvision', 'passive', 0.95), model: o('DS-7608NI-K2', 'passive', 0.8), fragile: true,
      software: [sw('s-nvr01', 'Hikvision NVR', 'Hikvision', 'NVR firmware', null, ['hikvision|multiple products'], 'passive', 0.5)], services: [svc(80, 'http', 'passive', 0.7), svc(8000, 'hikvision-sdk', 'passive', 0.6)] }),
    // BN340, an Alpine router the scan reads as OpenSSH 10.2 with an OS guess: CVE-2026-123158 is its question
    a({ id: 'a-bn340', ip: '192.168.10.9', kind: 'router', hostname: 'BN340', mac: '02:42:ac:11:03:40', vendor: o('Shenzhen BN', 'passive', 0.6), os: o('Linux 6.x', 'nmap', 0.5),
      software: [sw('s-bn340-ssh', 'OpenSSH', 'OpenBSD', 'OpenSSH', '10.2', ['openbsd|openssh'], 'nmap', 0.8)], services: [svc(22, 'ssh', 'nmap', 0.9, 'OpenSSH', '10.2')] }),
    // A device of unknown kind that the identification rules recognise from its card maker and its open port (modelled on a FortiGate).
    // A person added FortiGate to it with the version "latest", which Vedette cannot compare (Needs your input)
    a({ id: 'a-unk02', ip: '192.168.10.251', kind: 'unknown', mac: '70:4c:a5:fc:2f:50', vendor: o('Fortinet', 'nmap', 0.6), services: [svc(22, 'ssh', 'nmap', 0.5)],
      software: [sw('s-unk02-fgt', 'FortiGate', 'Fortinet', 'FortiOS', 'latest', ['fortinet|fortios'], 'manual', 1)], first_seen: D(1), last_seen: D(0),
      guess: { kind: 'firewall', confidence: 0.35, evidence: 'Fortinet network card and port 22 (ssh): most likely a FortiGate firewall (Fortinet also makes FortiAP access points and FortiSwitch switches; a scan of its web page or certificate tells which).', alternatives: ['ap', 'switch'] } }),
    a({ id: 'a-unk01', ip: '192.168.10.157', kind: 'unknown', hostname: null, mac: 'da:a1:19:5c:77:01', vendor: o('Device with a randomized MAC', 'passive', 0.3), approved: false, first_seen: D(0, ), last_seen: D(0), services: [svc(23, 'telnet')] }), // an open service is a reason to review a private address
    // Phones and a guest laptop on the guest Wi-Fi with private addresses, no open service, seen for a few hours: To review's
    // collapsed Seen briefly group (state seen), outside its count and the new-device notice
    a({ id: 'a-seen01', ip: '10.20.0.31', kind: 'smartphone', hostname: 'Galaxy-S24', mac: '9e:41:0c:2a:51:31', vendor: o('Device with a randomized MAC', 'passive', 0.3), approved: false, first_seen: H(5), last_seen: H(1) }),
    a({ id: 'a-seen02', ip: '10.20.0.32', kind: 'smartphone', hostname: 'Pixel-8', mac: '5a:12:7b:90:3e:32', vendor: o('Device with a randomized MAC', 'passive', 0.3), approved: false, first_seen: H(3), last_seen: H(0) }),
    a({ id: 'a-seen03', ip: '10.20.0.33', kind: 'unknown', hostname: 'guest-laptop', mac: 'b6:d3:4f:08:77:33', vendor: o('Device with a randomized MAC', 'passive', 0.3), approved: false, first_seen: H(8), last_seen: H(2) }),
  ]
}
