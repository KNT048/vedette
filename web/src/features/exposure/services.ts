import type { PortRow, Service, ServiceRow } from './types'

// Short names people know for the services the scan lists (nmap's names, or the usual port names of the surface scan).
const LABEL = new Map<string, string>(Object.entries({
  'microsoft-ds': 'SMB', 'netbios-ssn': 'NetBIOS', 'ms-sql': 'SQL Server', 'ms-sql-s': 'SQL Server', domain: 'DNS', postgresql: 'PostgreSQL', mysql: 'MySQL',
  mongodb: 'MongoDB', redis: 'Redis', 'winrm-https': 'WinRM', 'http-proxy': 'HTTP proxy', teamviewer: 'TeamViewer', radmin: 'Radmin',
  'mikrotik-api': 'MikroTik API', 'mikrotik-api-ssl': 'MikroTik API', winbox: 'Winbox', jetdirect: 'Printer', dvr: 'Camera recorder (DVR)',
  // nmap's own names, so no raw upper-case name reaches the page
  'cisco-sccp': 'Cisco SCCP (IP phones)', 'ms-wbt-server': 'Remote Desktop (RDP)', msrpc: 'Windows RPC', 'http-alt': 'HTTP', 'https-alt': 'HTTPS',
  'ssl/http': 'HTTPS', 'ssl/https': 'HTTPS', 'ssl/http-alt': 'HTTPS', 'ssl/imap': 'IMAPS', 'ssl/pop3': 'POP3S', 'ssl/smtp': 'SMTPS', 'ssl/sip': 'SIP over TLS',
  'ssl/ldap': 'LDAPS', 'vnc-http': 'VNC web viewer', 'upnp': 'UPnP', 'ipp': 'Printer (IPP)', 'rtsp': 'RTSP (cameras)', 'openvpn': 'OpenVPN',
  'pptp': 'PPTP VPN', 'isakmp': 'IPsec VPN', 'bgp': 'BGP',
}))

/** nmap's names that say no service was read: "unknown", a bare TLS layer, a port that closes at once. */
const unnamed = (service: string) => {
  const base = service === 'ssl' ? '' : service.replace(/^ssl\//, '')
  return base === '' || base === 'unknown' || base === 'tcpwrapped'
}
const isTls = (service: string) => service === 'ssl' || service.startsWith('ssl/') || service === 'https'

/** "SIP", "HTTPS", "Cisco SCCP (IP phones)": a person's name for a service name nmap or the port list gave. */
export function serviceName(service: string): string {
  const known = LABEL.get(service)
  if (known) return known
  const base = service.replace(/^ssl\//, '')
  const name = LABEL.get(base) ?? (/^[a-z0-9]{2,6}$/.test(base) ? base.toUpperCase() : base)
  return base !== service ? `${name} over TLS` : name
}

/** The Service cell of a row: the name, and whether only the port number says so. */
export function serviceText(s: Pick<Service, 'name' | 'ident'>): { name: string; byPort: boolean } {
  if (s.ident === 'none' || unnamed(s.name)) {
    if (s.name === 'tcpwrapped') return { name: 'Closed at once (tcpwrapped)', byPort: false }
    return { name: isTls(s.name) ? 'TLS, service not identified' : 'Service not identified', byPort: false }
  }
  if (s.ident === 'table') return { name: `Probably ${serviceName(s.name)}`, byPort: true }
  return { name: serviceName(s.name), byPort: false }
}

type Risk = 'voip' | 'remote' | 'files' | 'database' | 'control' | 'camera'

/**
 * Services attackers scan the Internet for all day (after CISA Cyber Hygiene's "potentially risky open services"
 * and Censys/Shodan exposure reports): the page names them and asks whether they are open on purpose. The value is the
 * key of the reason in exposure.json `risky.*`. A Map, not an object: a service named "constructor" must not find
 * Object.prototype.
 */
const RISKY = new Map<string, Risk>(Object.entries({
  sip: 'voip', sips: 'voip',
  rdp: 'remote', 'ms-wbt-server': 'remote', vnc: 'remote', ssh: 'remote', telnet: 'remote', teamviewer: 'remote', radmin: 'remote', winrm: 'remote', 'winrm-https': 'remote', pptp: 'remote',
  'microsoft-ds': 'files', 'netbios-ssn': 'files', ftp: 'files', nfs: 'files', rsync: 'files', msrpc: 'files',
  'ms-sql': 'database', 'ms-sql-s': 'database', mysql: 'database', postgresql: 'database', oracle: 'database', mongodb: 'database', redis: 'database', memcached: 'database', cassandra: 'database', etcd: 'database',
  docker: 'control', 'docker-tls': 'control', kubelet: 'control', kubernetes: 'control', winbox: 'control', 'mikrotik-api': 'control', 'mikrotik-api-ssl': 'control', cwmp: 'control', modbus: 'control', s7comm: 'control',
  dvr: 'camera',
} satisfies Record<string, Risk>))

/** The reason a service is commonly attacked; null when it is not, or when nothing identified it. */
export const riskOf = (s: Pick<Service, 'name' | 'ident'>) => (s.ident === 'none' || unnamed(s.name) ? null : RISKY.get(s.name) ?? RISKY.get(s.name.replace(/^ssl\//, '')) ?? null)

// The snapshot model of the older /exposure/targets API, which the sample data of the mock still serves.
type Ident = 'probed' | 'port' | 'none' | undefined
const identOf = (p: { service: string; ident?: Ident }): Ident => (p.ident ?? (unnamed(p.service) ? 'none' : undefined))
/** A port's service in a sentence, as the older "What changed" said it. */
export function serviceLabel(p: Pick<PortRow, 'service' | 'ident'>): string {
  if (identOf(p) === 'none') return isTls(p.service) ? 'TLS, service not identified' : 'service not identified'
  return identOf(p) === 'port' ? `probably ${serviceName(p.service)}` : serviceName(p.service)
}
/** A service row's ident, from nmap's method. */
export const serviceIdent = (r: Pick<ServiceRow, 'name' | 'method'>): Ident => (unnamed(r.name) ? 'none' : r.method === 'table' ? 'port' : r.method === 'probed' ? 'probed' : undefined)
