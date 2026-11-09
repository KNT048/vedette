// The action template library is data (D-58) and carries the fixes of action-templates.md §12. These tests read the JSON through the loader.
import { describe, expect, it } from 'vitest'
import { PARAM_TYPES, RUNTIME_VALUES, tplParams, validateTpl, type Tpl } from '../logic'
import { guides } from './guides'
import { seedCatalog, SEED_RULES, TEMPLATES, UNVERIFIED_NOTE } from './index'

const cat = seedCatalog()
const get = (id: string) => cat.find((a) => a.id === id)!
const shape = (t: Tpl) => [t.cli, t.path, t.body, t.headers].join('\n')

describe('action template library (data, D-58)', () => {
  it('ids are unique; every placeholder is a typed parameter or a value read at run time; message actions are the only ones using {text}', () => {
    expect(new Set(cat.map((a) => a.id)).size).toBe(cat.length)
    for (const a of cat) {
      const all = [a.run, a.rollback, a.verify].map(shape).join('\n')
      for (const m of all.matchAll(/\{([a-z_]+)\}/g)) expect([...PARAM_TYPES, ...RUNTIME_VALUES] as string[], `${a.id}: {${m[1]}}`).toContain(m[1])
      if (a.id !== 'msg_send' && a.id !== 'webhook_call') expect(tplParams(a.run, a.rollback, a.verify), a.id).not.toContain('text')
    }
  })

  it('what the docs still call unverified says so in the description the user reads (§0)', () => {
    expect(UNVERIFIED_NOTE).toBe('Not verified on a device yet — test in a lab first')
    for (const id of ['fgt_ban_ip', 'fgt_vip_disable', 'fgt_policy_disable', 'fgt_addrgrp_add', 'mt_addrlist_add', 'pf_alias_add', 'cisco_acl_deny', 'cisco_port_vlan_quarantine', 'aoscx_acl_deny', 'arubasw_acl_deny', 'adguard_block', 'pihole_block']) {
      expect(get(id).description, id).toContain(UNVERIFIED_NOTE)
    }
    expect(get('opn_alias_add').description).not.toContain(UNVERIFIED_NOTE) // the OPNsense calls were read in the official documentation
    expect(get('blocklist_add').description).not.toContain(UNVERIFIED_NOTE)
  })

  it('§12 (1) the virtual IP action takes {name}, not {text}; the policy alternative takes {id}', () => {
    expect(tplParams(get('fgt_vip_disable').run, get('fgt_vip_disable').rollback)).toEqual(['name'])
    expect(get('fgt_vip_disable').run.path).toBe('/api/v2/cmdb/firewall/vip/{name}')
    expect(tplParams(get('fgt_policy_disable').run, get('fgt_policy_disable').rollback)).toEqual(['id'])
    expect(get('fgt_policy_disable').risk).toBe('high')
    expect(get('fgt_policy_disable').ai_may_propose).toBe(false)
  })

  it('§12 (2) the ban carries the time to live of the action as its expiry', () => {
    expect(get('fgt_ban_ip').run.body).toContain('"expiry":{expiry_s}')
  })

  it('§12 (3) the address group action creates the address object and undo removes it, after leaving the group; the description names the anchor', () => {
    const a = get('fgt_addrgrp_add')
    expect(a.run.cli).toContain('config firewall address')
    expect(a.rollback.cli.indexOf('unselect member')).toBeLessThan(a.rollback.cli.indexOf('delete "vedette-{ip}"'))
    expect(a.description).toMatch(/anchor member/)
  })

  it('§12 (4) the address list undo exists over the API too, by the id read from the router, and the timeout is the time to live', () => {
    const a = get('mt_addrlist_add')
    expect(a.rollback.method).toBe('DELETE')
    expect(a.rollback.path).toBe('/rest/ip/firewall/address-list/{found_id}')
    expect(a.run.body).toContain('"timeout":"{timeout}"')
  })

  it('§12 (5)(6) pfSense is the unofficial package on v2 paths; OPNsense says External alias and lost after restart', () => {
    expect(get('pf_alias_add').name).toMatch(/unofficial/)
    expect(get('pf_alias_add').description).toMatch(/not made or supported by Netgate/)
    expect(shape(get('pf_alias_add').run)).not.toContain('/api/v1/')
    expect(get('pf_alias_add').run.path).toBe('/api/v2/firewall/alias')
    expect(get('opn_alias_add').description).toMatch(/External/)
    expect(get('opn_alias_add').description).toMatch(/not kept when OPNsense restarts/)
  })

  it('§12 (7)(8) one action per switch family; ACLs insert by sequence number and undo by it; the VLAN is restored from the port, not removed', () => {
    for (const id of ['sw_acl_deny', 'sw_port_shut', 'sw_vlan_quarantine']) expect(cat.some((a) => a.id === id), id).toBe(false)
    for (const id of ['cisco_acl_deny', 'aoscx_acl_deny', 'arubasw_acl_deny']) {
      expect(get(id).run.cli, id).toContain('{seq} deny')
      expect(get(id).rollback.cli, id).toContain('no {seq}')
    }
    expect(get('cisco_acl_deny').description).toMatch(/permit ip any any/)
    expect(get('aoscx_acl_deny').run.cli).toContain('deny any {ip}/32 any')
    expect(get('arubasw_acl_deny').run.cli).toContain('deny ip {ip} 0.0.0.0 any')
    for (const id of ['cisco_port_vlan_quarantine', 'aoscx_vlan_quarantine', 'arubasw_vlan_quarantine']) {
      expect(get(id).rollback.cli, id).toContain('{previous_vlan}')
      expect(get(id).rollback.cli, id).not.toMatch(/\bno\b/)
      expect(get(id).risk).toBe('high')
    }
    expect(get('cisco_port_vlan_quarantine').run.cli).toContain('switchport access vlan {vlan}')
    expect(get('aoscx_vlan_quarantine').run.cli).toContain('vlan access {vlan}')
    expect(get('arubasw_vlan_quarantine').run.cli).toContain('untagged {interface}')
  })

  it('§12 (9) AdGuard Home is its own action (read, change, write back); the Pi-hole text no longer sends people to copy it', () => {
    expect(get('adguard_block').description).toMatch(/reads all your user rules/)
    expect(get('adguard_block').rollback.body).toContain('{rules_before}')
    expect(get('pihole_block').description).not.toMatch(/AdGuard/)
  })

  it('§12 (10) parameter types id and name exist with the documented limits', async () => {
    const { PARAM_CHECK } = await import('../logic')
    expect(PARAM_CHECK.id('2147483647')).toBe(true)
    expect(PARAM_CHECK.id('2147483648')).toBe(false)
    expect(PARAM_CHECK.id('0')).toBe(false)
    expect(PARAM_CHECK.name('Vedette-Blocked_1.x')).toBe(true)
    expect(PARAM_CHECK.name('a'.repeat(65))).toBe(false)
  })

  it('§12 (11) the one-time pull setups are guides (FortiGate, OPNsense, AdGuard Home); saving the configuration is a separate action', () => {
    const ids = guides('https://box/list').map((g) => g.id)
    for (const id of ['fortigate', 'opnsense', 'adguard']) expect(ids).toContain(id)
    expect(get('cisco_save_config').run.cli).toBe('write memory')
    expect(get('cisco_save_config').enabled).toBe(false)
    for (const a of cat.filter((x) => x.id !== 'cisco_save_config')) expect(shape(a.run).toLowerCase(), a.id).not.toContain('write memory')
  })

  it('the library obeys the same rules a customer template does: shell characters are refused in the plain parts', () => {
    // The library is data validated by its loader; the display-only values (<seq>) and read-back commands with a pipe are the documented exceptions.
    for (const a of cat.filter((x) => x.kind === 'device' && x.id !== 'cisco_save_config' && !x.run.body.includes('{rules_before}') && !x.rollback.body.includes('{rules_before}') && x.id !== 'adguard_block')) {
      expect(validateTpl(a.run, a.id), `${a.id} run`).toBeNull()
    }
  })

  it('a rule template whose action is not verified says so in the gallery text; message-only and block-list templates do not', () => {
    const by = (id: string) => TEMPLATES.find((x) => x.id === id)!
    for (const id of ['tpl-trap-fgt', 'tpl-vpn-ban', 'tpl-nat-vip', 'tpl-sweep-vlan', 'tpl-trap-mikrotik', 'tpl-ioc-pfsense', 'tpl-iot-shut', 'tpl-ssh-acl', 'tpl-manual-ban', 'tpl-ioc-pihole']) expect(by(id).description, id).toContain(UNVERIFIED_NOTE)
    for (const id of ['tpl-ioc-blocklist', 'tpl-kev-msg', 'tpl-unknown-msg', 'tpl-newport-msg', 'tpl-weekly-digest']) expect(by(id).description, id).not.toContain(UNVERIFIED_NOTE)
  })

  it('rule templates and seed rules use only actions of the library', () => {
    const ids = new Set(cat.map((a) => a.id))
    for (const r of [...TEMPLATES.map((t) => t.rule), ...SEED_RULES]) for (const act of r.actions) expect(ids.has(act.action_id), act.action_id).toBe(true)
  })
})

describe('no brand in code (D-58): vendor names live only in the template data, the seeds and the examples', () => {
  const sources = import.meta.glob<string>(['../*.{ts,tsx}', '../../ai/*.{ts,tsx}', '../../ai/harness/*.{ts,tsx}', '../../core/ConnectionsSection.tsx', '../../core/connectionsMock.ts', '../../../mocks/connectors.ts', '../../../lib/connections.ts'], { query: '?raw', import: 'default', eager: true })
  const BRAND = /fortigate|fortios|fortinet|mikrotik|routeros|pfsense|opnsense|cisco|aruba|pi-hole|pihole|adguard|palo ?alto/i
  it('no code file under response or ai names a brand', () => {
    expect(Object.keys(sources).length).toBeGreaterThan(30) // the glob really found the code
    const offenders = Object.entries(sources).filter(([p]) => !/\.test\.tsx?$/.test(p)).filter(([, s]) => BRAND.test(s)).map(([p]) => p)
    expect(offenders).toEqual([])
  })
})
