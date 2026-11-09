// Static catalogs of the response module (D-51): trigger catalog, built-in action packs, rule templates. Used by the mock server;
// the UI reads all of it through the API.
import type { Pack, Risk, RuleInput, Trigger, TriggerField } from './types'
import type { Tpl } from './logic'

export const T = (cli: string, method: Tpl['method'] = '', path = '', body = '', headers = ''): Tpl => ({ cli, method, path, body, headers })
export const NONE: Tpl = T('')

// ---- Triggers (WHEN) ----
const F = (key: string, label: string, type: TriggerField['type'], example: string, choices: string[] = []): TriggerField => ({ key, label, type, example, choices })
export const KINDS = ['firewall', 'router', 'switch', 'ap', 'nas', 'server', 'pc', 'printer', 'camera', 'nvr', 'iot', 'web', 'unknown']
export const TRIGGERS: { id: Trigger; name: string; description: string; fields: TriggerField[] }[] = [
  { id: 'honeypot', name: 'A device touches a honeypot trap', description: 'Something on your network connected to a decoy, used a planted credential or scanned the decoys.',
    fields: [F('source_ip', 'Source IP address', 'ip', '192.168.10.157'), F('source_device', 'Source device', 'text', 'PC-HR-01'), F('decoy', 'Decoy touched', 'text', 'FILESRV-OLD'), F('kind', 'Kind of touch', 'choice', 'scan', ['service', 'token', 'scan']), F('switch_port', 'Switch port of the source', 'interface', 'Gi1/0/12')] },
  { id: 'ioc_connection', name: 'A device connects to a known-bad address', description: 'A LAN device talked to an IP address or domain on a threat feed. Read from the known-bad connection list of the Logs module.',
    fields: [F('src_ip', 'Device IP address', 'ip', '192.168.10.105'), F('device', 'Device', 'text', 'PC-SALES-02'), F('dest', 'Destination', 'text', '185.220.101.47'), F('dest_kind', 'Destination kind', 'choice', 'ip', ['ip', 'domain']),
      F('dest_ip', 'Destination IP (empty for a domain)', 'ip', '185.220.101.47'), F('dest_domain', 'Destination domain (empty for an IP)', 'domain', 'cdn-update.badhost.example'), F('feeds', 'Feeds that list it', 'text', 'Tor exit list, IPsum'), F('confidence', 'Confidence (0 to 100)', 'number', '92'), F('switch_port', 'Switch port of the device', 'interface', 'Gi1/0/5')] },
  { id: 'finding', name: 'A finding appears or is confirmed', description: 'A new vulnerability finding on one of your devices, or a suspected one that was confirmed.',
    fields: [F('device', 'Device', 'text', 'NAS-PHOTOS'), F('ip', 'Device IP address', 'ip', '192.168.10.21'), F('cve', 'CVE', 'text', 'CVE-2024-3400'), F('severity', 'Severity', 'choice', 'critical', ['critical', 'high', 'medium', 'low']), F('kev', 'Exploited in the wild (KEV)', 'flag', 'true', ['true', 'false']), F('exposed_via_nat', 'Reachable through port forwarding', 'flag', 'true', ['true', 'false']), F('vip', 'Firewall virtual IP name', 'text', 'NAS-PHOTO-443')] },
  { id: 'unknown_device', name: 'An unknown device appears', description: 'A device that is not in your approved inventory joined the network.',
    fields: [F('ip', 'IP address', 'ip', '192.168.10.157'), F('mac', 'MAC address', 'mac', '3c:22:fb:10:aa:01'), F('vendor', 'Vendor', 'text', 'Unknown vendor'), F('kind', 'Device type guess', 'choice', 'unknown', KINDS)] },
  { id: 'log_threshold', name: 'A log rule matched or a threshold was exceeded', description: 'For example 10 failed VPN logins from one address in 5 minutes.',
    fields: [F('source_device', 'Source device', 'text', 'vpn-client-203'), F('source_ip', 'Source IP address', 'ip', '203.0.113.99'), F('signature', 'Log signature', 'text', 'vpn_login_failed'), F('count', 'Number of matches', 'number', '12'), F('window', 'Window (minutes)', 'number', '5')] },
  { id: 'new_port', name: 'A new port opens on a public IP', description: 'The exposure check saw a port open on one of your public addresses that was closed before.',
    fields: [F('ip', 'Public IP address', 'ip', '203.0.113.10'), F('port', 'Port', 'port', '8080'), F('service', 'Service guess', 'text', 'http-alt'), F('device', 'Device behind it', 'text', 'WEB-01')] },
  { id: 'schedule', name: 'On a schedule', description: 'Runs every chosen number of minutes, for example a weekly digest or a nightly check.', fields: [F('run_at', 'Run time', 'text', '2026-11-09 03:00'), F('scope', 'Scope', 'text', 'whole network')] },
  { id: 'manual', name: 'Manual: run on a chosen device', description: 'Nothing starts it but you. Press Run on a device and pick the device.',
    fields: [F('device', 'Device', 'text', 'PC-HR-01'), F('ip', 'Device IP address', 'ip', '192.168.10.107'), F('mac', 'MAC address', 'mac', '3c:22:fb:10:aa:01'), F('switch_port', 'Switch port of the device', 'interface', 'Gi1/0/7')] },
]

// ---- Built-in actions (THEN): vendor packs and generic actions ----
export interface StoredCat {
  id: string; builtin: boolean; pack: Pack; kind: 'box' | 'device'; name: string; description: string
  connection_id: string | null; tool: string | null; rollback_tool: string | null
  run: Tpl; rollback: Tpl; verify: Tpl; risk: Risk; enabled: boolean; ai_may_propose: boolean
}
const FGT = 'cn-fgt'
const ADDRGRP = (g: string) => `config firewall addrgrp\n    edit "${g}"\n        append member "vedette-{ip}"\n    next\nend`
const ADDRGRP_RM = (g: string) => `config firewall addrgrp\n    edit "${g}"\n        unselect member "vedette-{ip}"\n    next\nend`
const ACL = (verb: 'deny' | 'no deny') => `ip access-list extended VEDETTE-BLOCK\n    ${verb} ip host {ip} any`
const dev = (o: Omit<StoredCat, 'builtin' | 'kind' | 'rollback_tool' | 'tool'> & { tool?: string | null }): StoredCat => ({ builtin: true, kind: 'device', rollback_tool: null, tool: null, ...o })
export const seedCatalog = (): StoredCat[] => [
  { id: 'blocklist_add', builtin: true, pack: 'box', kind: 'box', name: 'Add an address to the block list your firewall pulls', description: 'Publishes the IP address on the block list of this box. Your firewall fetches the list itself, so Vedette needs no write access to it. The entry is removed after the time to live.',
    connection_id: null, tool: null, rollback_tool: null, run: T('blocklist add {ip}'), rollback: T('blocklist remove {ip}'), verify: T('blocklist show {ip}'), risk: 'low', enabled: true, ai_may_propose: true },
  dev({ id: 'block_ip', pack: 'fortigate', name: 'FortiGate: add an IP to the Vedette-Blocked address group', description: 'Adds the address to the Vedette-Blocked address group on the firewall. A deny policy on that group (you create it once) then cuts the address off.', connection_id: FGT, tool: 'block_address',
    run: T(ADDRGRP('Vedette-Blocked'), 'POST', '/api/v2/cmdb/firewall/addrgrp/Vedette-Blocked/member', '{"name":"vedette-{ip}"}'), rollback: T(ADDRGRP_RM('Vedette-Blocked'), 'DELETE', '/api/v2/cmdb/firewall/addrgrp/Vedette-Blocked/member/vedette-{ip}'),
    verify: T('', 'GET', '/api/v2/cmdb/firewall/addrgrp/Vedette-Blocked'), risk: 'medium', enabled: true, ai_may_propose: true }),
  dev({ id: 'fgt_ban_ip', pack: 'fortigate', name: 'FortiGate: ban an IP address', description: 'Puts the address on the FortiGate banned list. All its sessions are dropped and new ones are refused until the ban is removed.', connection_id: FGT,
    run: T('diagnose user banned-ip add src4 {ip}', 'POST', '/api/v2/monitor/user/banned/add_users', '{"ip_addresses":["{ip}"]}'), rollback: T('diagnose user banned-ip delete src4 {ip}', 'POST', '/api/v2/monitor/user/banned/clear_users', '{"ip_addresses":["{ip}"]}'),
    verify: T('', 'GET', '/api/v2/monitor/user/banned/select'), risk: 'medium', enabled: true, ai_may_propose: true }),
  dev({ id: 'nat_off', pack: 'fortigate', name: 'FortiGate: disable a virtual IP (port forwarding)', description: 'Turns off the firewall virtual IP (NAT) that sends Internet traffic to a device. Traffic inside the office is not affected. Anyone using the published address loses access until it is turned back on.', connection_id: FGT, tool: 'disable_virtual_ip',
    run: T('config firewall vip\n    edit "{text}"\n        set status disable\n    next\nend', 'PUT', '/api/v2/cmdb/firewall/vip/{text}', '{"status":"disable"}'), rollback: T('config firewall vip\n    edit "{text}"\n        set status enable\n    next\nend', 'PUT', '/api/v2/cmdb/firewall/vip/{text}', '{"status":"enable"}'),
    verify: T('', 'GET', '/api/v2/cmdb/firewall/vip/{text}'), risk: 'medium', enabled: true, ai_may_propose: true }),
  dev({ id: 'mt_addrlist_add', pack: 'mikrotik', name: 'MikroTik: add an IP to an address list with a timeout', description: 'Adds the address to the vedette-block address list on RouterOS. The router also drops the entry by itself after one day.', connection_id: null,
    run: T('/ip firewall address-list add list=vedette-block address={ip} timeout=1d', 'PUT', '/rest/ip/firewall/address-list', '{"list":"vedette-block","address":"{ip}","timeout":"1d"}'), rollback: T('/ip firewall address-list remove [find list=vedette-block address={ip}]'),
    verify: T('/ip firewall address-list print where list=vedette-block'), risk: 'medium', enabled: false, ai_may_propose: false }),
  dev({ id: 'pf_alias_add', pack: 'pfsense', name: 'pfSense: add an IP to an alias', description: 'Adds the address to the Vedette_Blocklist alias through the pfSense API. A floating block rule on that alias (you create it once) does the blocking.', connection_id: null,
    run: T('', 'POST', '/api/v1/firewall/alias/entry', '{"name":"Vedette_Blocklist","address":["{ip}"]}'), rollback: T('', 'DELETE', '/api/v1/firewall/alias/entry', '{"name":"Vedette_Blocklist","address":["{ip}"]}'),
    verify: T('', 'GET', '/api/v1/firewall/alias'), risk: 'medium', enabled: false, ai_may_propose: false }),
  dev({ id: 'opn_alias_add', pack: 'opnsense', name: 'OPNsense: add an IP to an alias', description: 'Adds the address to the Vedette_Blocklist alias through the OPNsense API. A rule on that alias (you create it once) does the blocking.', connection_id: null,
    run: T('', 'POST', '/api/firewall/alias_util/add/Vedette_Blocklist', '{"address":"{ip}"}'), rollback: T('', 'POST', '/api/firewall/alias_util/delete/Vedette_Blocklist', '{"address":"{ip}"}'),
    verify: T('', 'GET', '/api/firewall/alias_util/list/Vedette_Blocklist'), risk: 'medium', enabled: false, ai_may_propose: false }),
  dev({ id: 'sw_acl_deny', pack: 'switch', name: 'Switch (SSH): deny an IP in the ACL', description: 'Adds a deny line for the address to the VEDETTE-BLOCK access list on a Cisco, Aruba or HPE switch over SSH. The list must be applied to your uplink once.', connection_id: null,
    run: T(ACL('deny')), rollback: T(ACL('no deny')), verify: T('show ip access-lists VEDETTE-BLOCK'), risk: 'medium', enabled: false, ai_may_propose: false }),
  dev({ id: 'sw_port_shut', pack: 'switch', name: 'Switch (SSH): shut a port', description: 'Shuts one switch port. Whatever is plugged in loses its network until the port is turned back on.', connection_id: null,
    run: T('interface {interface}\n    shutdown'), rollback: T('interface {interface}\n    no shutdown'), verify: T('show interface {interface} status'), risk: 'medium', enabled: false, ai_may_propose: false }),
  dev({ id: 'sw_vlan_quarantine', pack: 'switch', name: 'Switch (SSH): move a port to the quarantine VLAN', description: 'Moves one switch port into the quarantine VLAN, which has no route to your servers. Vedette reads the current VLAN of the port first and puts it back on undo. The device keeps a link but loses everything else, so a person must approve.', connection_id: null,
    run: T('interface {interface}\n    switchport access vlan {vlan}'), rollback: T('interface {interface}\n    no switchport access vlan'), verify: T('show interface {interface} switchport'), risk: 'high', enabled: false, ai_may_propose: true }),
  dev({ id: 'pihole_block', pack: 'dns', name: 'Pi-hole / AdGuard Home: block a domain', description: 'Adds the domain to the deny list of your DNS filter, so devices can no longer resolve it. AdGuard Home users copy this action and change the API call.', connection_id: null,
    run: T('', 'POST', '/api/domains/deny/exact', '{"domain":"{domain}","comment":"Vedette","enabled":true}'), rollback: T('', 'DELETE', '/api/domains/deny/exact/{domain}'), verify: T('', 'GET', '/api/domains/deny/exact/{domain}'), risk: 'low', enabled: false, ai_may_propose: true }),
  { id: 'msg_send', builtin: true, pack: 'generic', kind: 'box', name: 'Send a message to your alert channels', description: 'Sends a short message to the alert channels you set up. It changes nothing on any device and cannot be unsent.',
    connection_id: null, tool: null, rollback_tool: null, run: T('notify {text}'), rollback: NONE, verify: NONE, risk: 'low', enabled: true, ai_may_propose: true },
  { id: 'webhook_call', builtin: true, pack: 'generic', kind: 'box', name: 'Call your webhook', description: 'Sends a short text to the webhook channel you set up (a ticket system or automation tool). Nothing on your network changes.',
    connection_id: null, tool: null, rollback_tool: null, run: T('webhook post {text}'), rollback: NONE, verify: NONE, risk: 'low', enabled: true, ai_may_propose: false },
]

// ---- Rule templates ----
export interface TemplateDef { id: string; name: string; description: string; rule: RuleInput }
const R = (trigger: Trigger, name: string, rest: Partial<RuleInput> & Pick<RuleInput, 'actions'>): RuleInput =>
  ({ name, enabled: false, live: false, trigger, match: 'all', conditions: [], pre_approved: false, max_per_hour: 5, schedule_min: null, ...rest })
const C = (field: string, op: RuleInput['conditions'][number]['op'], value: string, n: number | null = null, window_min: number | null = null) => ({ field, op, value, n, window_min })
const A = (action_id: string, params: Record<string, string>, ttl_min: number | null) => ({ action_id, params, ttl_min })
export const TEMPLATES: TemplateDef[] = [
  { id: 'tpl-trap-fgt', name: 'Trap touched: block the source on FortiGate for 24 hours', description: 'When anything touches a honeypot trap, add its address to the FortiGate block group. Undone after 24 hours.',
    rule: R('honeypot', 'Trap touched: block source on FortiGate', { actions: [A('block_ip', { ip: '{{trigger.source_ip}}' }, 1440)] }) },
  { id: 'tpl-ioc-blocklist', name: 'Known-bad connection: add the destination to the block list', description: 'A device talked to a bad IP address with confidence 80 or more: publish the destination on the block list your firewall pulls.',
    rule: R('ioc_connection', 'Known-bad IP: add to the block list', { conditions: [C('dest_kind', 'eq', 'ip'), C('confidence', 'gte', '80')], actions: [A('blocklist_add', { ip: '{{trigger.dest_ip}}' }, 1440)], max_per_hour: 10 }) },
  { id: 'tpl-ioc-pihole', name: 'Known-bad domain: block it on Pi-hole', description: 'A device looked up a domain from a threat feed: add it to the DNS filter deny list for a week.',
    rule: R('ioc_connection', 'Known-bad domain: block on Pi-hole', { conditions: [C('dest_kind', 'eq', 'domain')], actions: [A('pihole_block', { domain: '{{trigger.dest_domain}}' }, 10080)], max_per_hour: 10 }) },
  { id: 'tpl-vpn-ban', name: '10 failed VPN logins in 5 minutes: ban the address', description: 'Brute force against the VPN: ban the source address on FortiGate for 24 hours.',
    rule: R('log_threshold', 'Failed VPN logins: ban the address', { conditions: [C('signature', 'eq', 'vpn_login_failed'), C('count', 'gte', '10'), C('window', 'lte', '5')], actions: [A('fgt_ban_ip', { ip: '{{trigger.source_ip}}' }, 1440)] }) },
  { id: 'tpl-nat-vip', name: 'Critical finding exposed through NAT: disable the virtual IP', description: 'A critical finding on a device that the Internet can reach: turn the FortiGate virtual IP off until it is patched.',
    rule: R('finding', 'Critical and exposed: disable the virtual IP', { conditions: [C('severity', 'eq', 'critical'), C('exposed_via_nat', 'eq', 'true')], actions: [A('nat_off', { text: '{{trigger.vip}}' }, 1440)], max_per_hour: 2 }) },
  { id: 'tpl-kev-msg', name: 'Exploited vulnerability found: message only', description: 'A finding that is exploited in the wild (KEV): send a message to your channels and change nothing.',
    rule: R('finding', 'KEV finding: message only', { conditions: [C('kev', 'eq', 'true')], actions: [A('msg_send', { text: 'KEV finding {{trigger.cve}} on {{trigger.device}}' }, null)], max_per_hour: 10 }) },
  { id: 'tpl-unknown-msg', name: 'Unknown device: message only', description: 'A device you have not approved joined the network: tell the team and change nothing.',
    rule: R('unknown_device', 'Unknown device: message only', { actions: [A('msg_send', { text: 'Unknown device {{trigger.mac}}, vendor {{trigger.vendor}}, at {{trigger.ip}}' }, null)], max_per_hour: 10 }) },
  { id: 'tpl-sweep-vlan', name: 'Port scan of the decoys: move the switch port to the quarantine VLAN', description: 'The same device touched the decoys 3 times in 10 minutes. HIGH RISK: it loses the network, so two different people must approve.',
    rule: R('honeypot', 'Decoy sweep: quarantine the switch port', { conditions: [C('source_ip', 'count_window', '', 3, 10)], actions: [A('sw_vlan_quarantine', { interface: '{{trigger.switch_port}}', vlan: '999' }, 240)], max_per_hour: 2 }) },
  { id: 'tpl-trap-mikrotik', name: 'Trap touched: add the source to a MikroTik address list', description: 'Same idea as the FortiGate rule, for a MikroTik router. Needs a MikroTik connection in the catalog.',
    rule: R('honeypot', 'Trap touched: MikroTik address list', { actions: [A('mt_addrlist_add', { ip: '{{trigger.source_ip}}' }, 1440)] }) },
  { id: 'tpl-ioc-pfsense', name: 'Very likely bad connection: add the destination to a pfSense alias', description: 'Confidence 90 or more: add the destination address to the pfSense Vedette_Blocklist alias.',
    rule: R('ioc_connection', 'Known-bad IP: pfSense alias', { conditions: [C('dest_kind', 'eq', 'ip'), C('confidence', 'gte', '90')], actions: [A('pf_alias_add', { ip: '{{trigger.dest_ip}}' }, 1440)] }) },
  { id: 'tpl-iot-shut', name: 'Camera or IoT device talks to a bad address: shut its switch port', description: 'Cameras and IoT devices have no reason to talk to bad addresses. Shuts the port until you turn it back on.',
    rule: R('ioc_connection', 'Bad connection from IoT: shut the port', { conditions: [C('', 'device_type', 'camera,nvr,iot'), C('confidence', 'gte', '70')], actions: [A('sw_port_shut', { interface: '{{trigger.switch_port}}' }, 240)], max_per_hour: 3 }) },
  { id: 'tpl-ssh-acl', name: 'SSH brute force: deny the address on the switch', description: '20 or more failed SSH logins in the window: add a deny line for the source on the switch ACL for 12 hours.',
    rule: R('log_threshold', 'SSH brute force: switch ACL', { conditions: [C('signature', 'eq', 'ssh_login_failed'), C('count', 'gte', '20')], actions: [A('sw_acl_deny', { ip: '{{trigger.source_ip}}' }, 720)] }) },
  { id: 'tpl-newport-msg', name: 'New open port on a public IP: message only', description: 'A new port opened on a public address: send a message so someone can check it is intended.',
    rule: R('new_port', 'New public port: message only', { actions: [A('msg_send', { text: 'New open port {{trigger.port}} on public IP {{trigger.ip}}, service {{trigger.service}}' }, null)], max_per_hour: 10 }) },
  { id: 'tpl-weekly-digest', name: 'Weekly: send a response digest message', description: 'Every 7 days send a short message that the weekly response digest is ready.',
    rule: R('schedule', 'Weekly response digest', { schedule_min: 10080, actions: [A('msg_send', { text: 'Weekly response digest is ready' }, null)], max_per_hour: 1 }) },
  { id: 'tpl-manual-ban', name: 'Manual: ban a device on FortiGate', description: 'Nothing runs by itself. Pick a device and press Run: its address is banned on FortiGate for 4 hours after approval.',
    rule: R('manual', 'Manual: ban a device on FortiGate', { actions: [A('fgt_ban_ip', { ip: '{{trigger.ip}}' }, 240)], max_per_hour: 5 }) },
]
