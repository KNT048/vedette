// Static catalogs of the response module (D-51): the trigger catalog and the shape of catalog actions and templates. Used by the mock server;
// the UI reads all of it through the API. The action and rule template libraries are DATA (D-58): see ./templates/.
import type { Pack, Risk, RuleInput, Trigger, TriggerField } from './types'
import type { Tpl } from './logic'

export const T = (cli: string, method: Tpl['method'] = '', path = '', body = '', headers = ''): Tpl => ({ cli, method, path, body, headers })
export const NONE: Tpl = T('')

// ---- Triggers (WHEN) ----
const F = (key: string, label: string, type: TriggerField['type'], example: string, choices: string[] = []): TriggerField => ({ key, label, type, example, choices, min: null, max: null })
/** A number or port field with its range (D-390): a condition value outside it is refused when the rule is saved. */
const N = (key: string, label: string, type: 'number' | 'port', example: string, min: number, max: number): TriggerField => ({ ...F(key, label, type, example), min, max })
/** The kinds of evidence that prove a trigger to the AI (D-119). A trigger that is not here cannot be used by the AI: no evidence kind can show it happened. */
export const AI_PROOF: Partial<Record<Trigger, ('finding' | 'ioc_hit' | 'config_read')[]>> = { finding: ['finding'], ioc_connection: ['ioc_hit'] }
export const KINDS = ['firewall', 'router', 'switch', 'ap', 'nas', 'server', 'pc', 'printer', 'camera', 'nvr', 'iot', 'web', 'unknown']
export const TRIGGERS: { id: Trigger; name: string; description: string; fields: TriggerField[] }[] = [
  { id: 'honeypot', name: 'A device touches a honeypot trap', description: 'Something on your network connected to a decoy, used a planted credential or scanned the decoys. The source of a scan can be forged, so a scan never uses pre-approval.',
    fields: [F('source_ip', 'Source IP address', 'ip', '192.168.10.157'), F('source_device', 'Source device', 'text', 'PC-HR-01'), F('decoy', 'Decoy touched', 'text', 'FILESRV-OLD'), F('kind', 'Kind of touch', 'choice', 'scan', ['service', 'token', 'scan']), F('switch_port', 'Switch port of the source', 'interface', 'Gi1/0/12')] },
  { id: 'ioc_connection', name: 'A device connects to a known-bad address', description: 'A LAN device talked to an IP address or domain on a threat feed. Read from the known-bad connection list of the Logs module.',
    fields: [F('src_ip', 'Device IP address', 'ip', '192.168.10.105'), F('device', 'Device', 'text', 'PC-SALES-02'), F('dest', 'Destination', 'text', '185.220.101.47'), F('dest_kind', 'Destination kind', 'choice', 'ip', ['ip', 'domain']),
      F('dest_ip', 'Destination IP (empty for a domain)', 'ip', '185.220.101.47'), F('dest_domain', 'Destination domain (empty for an IP)', 'domain', 'cdn-update.badhost.example'), F('feeds', 'Feeds that list it', 'text', 'Tor exit list, IPsum'), N('confidence', 'Confidence (0 to 1)', 'number', '0.92', 0, 1), F('switch_port', 'Switch port of the device', 'interface', 'Gi1/0/5')] },
  { id: 'finding', name: 'A finding appears or is confirmed', description: 'A new vulnerability finding on one of your devices, or a suspected one that was confirmed.',
    fields: [F('device', 'Device', 'text', 'NAS-PHOTOS'), F('ip', 'Device IP address', 'ip', '192.168.10.21'), F('cve', 'CVE', 'text', 'CVE-2024-3400'), F('severity', 'Severity', 'choice', 'critical', ['critical', 'high', 'medium', 'low']), F('kev', 'Exploited in the wild (KEV)', 'flag', 'true', ['true', 'false']), F('exposed_via_nat', 'Reachable through port forwarding', 'flag', 'true', ['true', 'false']), F('vip', 'Firewall virtual IP name', 'name', 'NAS-PHOTO-443')] },
  { id: 'unknown_device', name: 'An unknown device appears', description: 'A device that is not in your approved inventory joined the network.',
    fields: [F('ip', 'IP address', 'ip', '192.168.10.157'), F('mac', 'MAC address', 'mac', '3c:22:fb:10:aa:01'), F('vendor', 'Vendor', 'text', 'Unknown vendor'), F('kind', 'Device type guess', 'choice', 'unknown', KINDS)] },
  { id: 'log_threshold', name: 'A log rule matched or a threshold was exceeded', description: 'Needs the Logs module. A declared log source received at least N lines of one signature (paste it from the Logs digest) within W minutes, for example 10 failed VPN logins in 5 minutes. Each address that alone sent N of those lines is an event of its own with its source IP address, so a rule can block it; when no single address did, the event names the log source only and actions that block an address are not available. Block on lines of a completed session (a failed login), not on dropped packets: the source of a dropped packet can be forged.',
    fields: [F('source_device', 'Log source', 'text', 'FW-HQ'), F('source_ip', 'Source IP address', 'ip', '203.0.113.99'), F('signature', 'Log signature', 'text', 'logid=0101039426 action=ssl-login-fail'), N('count', 'Number of matches', 'number', '12', 1, 1000000), N('window', 'Window (minutes)', 'number', '5', 5, 1440)] },
  { id: 'new_port', name: 'A new port opens on a public IP', description: 'The exposure check saw a port open on one of your public addresses that was closed before.',
    fields: [F('ip', 'Public IP address', 'ip', '203.0.113.10'), N('port', 'Port', 'port', '8080', 1, 65535), F('service', 'Service guess', 'text', 'http-alt'), F('device', 'Device behind it', 'text', 'WEB-01')] },
  { id: 'schedule', name: 'On a schedule', description: 'Runs every chosen number of minutes, for example a weekly digest or a nightly check.', fields: [F('run_at', 'Run time', 'text', '2026-11-09 03:00'), F('scope', 'Scope', 'text', 'whole network')] },
  { id: 'manual', name: 'Manual: run on a chosen device', description: 'Nothing starts it but you. Press Run on a device and pick the device.',
    fields: [F('device', 'Device', 'text', 'PC-HR-01'), F('ip', 'Device IP address', 'ip', '192.168.10.107'), F('mac', 'MAC address', 'mac', '3c:22:fb:10:aa:01'), F('switch_port', 'Switch port of the device', 'interface', 'Gi1/0/7')] },
]

// ---- Actions (THEN): the library is data in ./templates; this is its stored shape ----
export interface StoredCat {
  id: string; builtin: boolean; pack: Pack; kind: 'box' | 'device'; name: string; description: string
  connection_id: string | null; tool: string | null; rollback_tool: string | null
  run: Tpl; rollback: Tpl; verify: Tpl; precheck: Tpl; precheck_refuse: string[]; precheck_expect: string; risk: Risk; enabled: boolean; ai_may_propose: boolean
}
// ---- Rule templates (loaded from ./templates) ----
export interface TemplateDef { id: string; name: string; description: string; rule: RuleInput }
