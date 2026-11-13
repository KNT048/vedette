import type { PortRow } from './types'

// Short names people know for the services the scan lists (its names are the usual port names, not detections).
const LABEL: Record<string, string> = {
  'microsoft-ds': 'SMB', 'netbios-ssn': 'NetBIOS', 'ms-sql': 'SQL Server', domain: 'DNS', postgresql: 'PostgreSQL', mysql: 'MySQL',
  mongodb: 'MongoDB', redis: 'Redis', 'winrm-https': 'WinRM', 'http-proxy': 'HTTP proxy', teamviewer: 'TeamViewer', radmin: 'Radmin',
  'mikrotik-api': 'MikroTik API', 'mikrotik-api-ssl': 'MikroTik API', winbox: 'Winbox', jetdirect: 'Printer', dvr: 'Camera recorder (DVR)',
}

/** "SIP 5060" for an open port. */
export const portLabel = (p: Pick<PortRow, 'service' | 'port'>) => `${LABEL[p.service] ?? p.service.toUpperCase()} ${p.port}`

/**
 * Services attackers scan the Internet for all day (D-485, after CISA Cyber Hygiene's "potentially risky open services"
 * and Censys/Shodan exposure reports): the page names them and asks whether they are open on purpose. The value is the
 * key of the reason in exposure.json `risky.*`.
 */
const RISKY: Record<string, 'voip' | 'remote' | 'files' | 'database' | 'control' | 'camera'> = {
  sip: 'voip', sips: 'voip',
  rdp: 'remote', vnc: 'remote', ssh: 'remote', telnet: 'remote', teamviewer: 'remote', radmin: 'remote', winrm: 'remote', 'winrm-https': 'remote', pptp: 'remote',
  'microsoft-ds': 'files', 'netbios-ssn': 'files', ftp: 'files', nfs: 'files', rsync: 'files', msrpc: 'files',
  'ms-sql': 'database', mysql: 'database', postgresql: 'database', oracle: 'database', mongodb: 'database', redis: 'database', memcached: 'database', cassandra: 'database', etcd: 'database',
  docker: 'control', 'docker-tls': 'control', kubelet: 'control', kubernetes: 'control', winbox: 'control', 'mikrotik-api': 'control', 'mikrotik-api-ssl': 'control', cwmp: 'control', modbus: 'control', s7comm: 'control',
  dvr: 'camera',
}

export const riskOf = (p: Pick<PortRow, 'service'>) => RISKY[p.service] ?? null
