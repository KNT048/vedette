// Sample data (the trial build): three example connections. Vendor names are allowed here and nowhere in the connection code (D-58).
import type { Connector, ConnectorTool } from '../connectors'

const T = (name: string, access: ConnectorTool['access'], description: string, enabled = true): ConnectorTool => ({ name, access, description, enabled })

export const seedConnectors = (): Connector[] => [
  {
    id: 'cn-fgt', name: 'Office FortiGate API', kind: 'http', target: 'https://192.168.10.1', asset_id: 'a-fw01',
    auth: { type: 'token', last4: 'k9Qe' }, username: null, pin: { kind: 'tls_sha256', value: '9f2c41d7a0b83e65c1d4f7a92b6e0835d1c7f4a8e3b29d60517c8ea4b3f2d10a', first_seen: '2026-11-08T02:10:00Z' }, allow: ['https://192.168.10.1/api/v2/'],
    tools: [
      T('get_virtual_ips', 'read', 'List virtual IPs (port forwarding / NAT) and the internal device each one points to'),
      T('get_firewall_policies', 'read', 'List firewall policies and which interfaces and addresses they allow'),
      T('get_system_status', 'read', 'Firmware version, model and uptime'),
      T('disable_virtual_ip', 'write', 'Turn off one virtual IP (stops port forwarding to an internal device)'),
      T('disable_firewall_policy', 'write', 'Turn off one firewall policy'),
      T('block_address', 'write', 'Add an IP address to a block address group'),
    ],
    enabled: true, status: 'ok', last_test: '2026-11-08T02:10:00Z',
  },
  {
    id: 'cn-ssh', name: 'File server (read-only SSH)', kind: 'ssh', target: '192.168.10.30:22', asset_id: null,
    auth: { type: 'ssh-key', last4: 'b2Lx' }, username: 'vedette-ro', pin: { kind: 'ssh_hostkey', value: 'ssh-ed25519 SHA256:q3Vn0cXk8e1Yw7mTz4pLr2aJb9HdUfS6oIgEyKtNxMc', first_seen: '2026-11-07T08:00:00Z' }, allow: ['uname -a', 'systemctl list-units --type=service --state=running', 'ss -tlnp', 'last -n 20'],
    tools: [T('run_allowed_command', 'read', 'Run one command from the allow list and return its output')],
    enabled: true, status: 'ok', last_test: '2026-11-07T08:00:00Z',
  },
  {
    id: 'cn-http', name: 'Vendor advisories (HTTP)', kind: 'http', target: 'https://www.cisa.gov', asset_id: null,
    auth: { type: 'none', last4: null }, username: null, pin: null, allow: ['https://www.fortiguard.com/', 'https://www.qnap.com/en/security-advisory/', 'https://www.cisa.gov/'],
    tools: [T('fetch_url', 'read', 'Fetch a page from an allowed address and return its text')],
    enabled: true, status: 'untested', last_test: null,
  },
]

