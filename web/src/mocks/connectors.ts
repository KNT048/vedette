// D-39: connections the in-box AI may use to reach other systems (MCP servers, SSH, HTTP, device APIs).
// The ai module owns the UI and endpoints (Settings → AI assistant → Connections); the response module (D-41)
// reads this store to find write tools. Every tool is 'read' or 'write'; write tools only ever run through an
// approved response action, never from a chat answer (hook "write tools need approval", always on).
import { collection } from './db'

export type ConnectorKind = 'device-api' | 'ssh' | 'http' | 'mcp-http' | 'mcp-stdio'
export interface ConnectorTool { name: string; access: 'read' | 'write'; description: string; enabled: boolean }
export interface Connector {
  id: string
  name: string
  kind: ConnectorKind
  /** device-api: which vendor API (FortiOS REST, RouterOS REST, pfSense API…) */
  vendor: 'fortinet' | 'mikrotik' | 'pfsense' | 'other' | null
  /** Base URL, host:port, or the MCP command */
  target: string
  /** Inventory device this connection controls, when known (for response plans) */
  asset_id: string | null
  auth: { type: 'none' | 'token' | 'basic' | 'ssh-key'; last4: string | null }
  /** Hosts, URL prefixes or command patterns the AI may use through this connection */
  allow: string[]
  tools: ConnectorTool[]
  enabled: boolean
  status: 'ok' | 'error' | 'untested'
  last_test: string | null
}

const T = (name: string, access: ConnectorTool['access'], description: string, enabled = true): ConnectorTool => ({ name, access, description, enabled })

export const connectorsStore = collection<Connector[]>('ai_connectors', () => [
  {
    id: 'cn-fgt', name: 'Office FortiGate API', kind: 'device-api', vendor: 'fortinet', target: 'https://192.168.10.1', asset_id: 'a-fw01',
    auth: { type: 'token', last4: 'k9Qe' }, allow: ['https://192.168.10.1/api/v2/'],
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
    id: 'cn-ssh', name: 'File server (read-only SSH)', kind: 'ssh', vendor: null, target: '192.168.10.30:22', asset_id: null,
    auth: { type: 'ssh-key', last4: 'b2Lx' }, allow: ['uname -a', 'systemctl list-units --type=service --state=running', 'ss -tlnp', 'last -n 20'],
    tools: [T('run_allowed_command', 'read', 'Run one command from the allow list and return its output')],
    enabled: true, status: 'ok', last_test: '2026-11-07T08:00:00Z',
  },
  {
    id: 'cn-http', name: 'Vendor advisories (HTTP)', kind: 'http', vendor: null, target: 'https://', asset_id: null,
    auth: { type: 'none', last4: null }, allow: ['https://www.fortiguard.com/', 'https://www.qnap.com/en/security-advisory/', 'https://www.cisa.gov/'],
    tools: [T('fetch_url', 'read', 'Fetch a page from an allowed address and return its text')],
    enabled: true, status: 'untested', last_test: null,
  },
], () => [])

/** Enabled write tools on enabled connections (what the response module may propose). */
export const writeTools = () => connectorsStore.get().filter((c) => c.enabled).flatMap((c) => c.tools.filter((t) => t.enabled && t.access === 'write').map((t) => ({ connector: c, tool: t })))
