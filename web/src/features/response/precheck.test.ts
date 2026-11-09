// The check before and the read-back as data (D-95), pure checks of logic.ts: what a template may not do. The mock API and the Go module
// apply the same rules (response.test.tsx, modules/response/precheck_test.go).
import { describe, expect, it } from 'vitest'
import { cliProblem, EMPTY_TPL, forbiddenHeader, needsPrecheck, readBackProblem, tplEmpty, validatePrecheck, validateTpl, type Tpl } from './logic'
import { CLI_BAN } from './templates'

const T = (o: Partial<Tpl>): Tpl => ({ ...EMPTY_TPL, ...o })
const steps = (o: { run?: Partial<Tpl>; rollback?: Partial<Tpl>; verify?: Partial<Tpl>; pre?: Partial<Tpl> }) => ({ run: T(o.run ?? {}), rollback: T(o.rollback ?? {}), verify: T(o.verify ?? {}), pre: T(o.pre ?? {}) })

describe('port guard (D-95 (3))', () => {
  it('a port named through {port}, {id} or {name} in a custom command or path still needs the check before', () => {
    for (const cli of ['interface GigabitEthernet1/0/{port}\nshutdown', 'interface Port-channel{id}\nshutdown', 'interface {name}\nshutdown']) {
      const run = T({ cli }), rollback = T({ cli: cli.replace('\nshutdown', '\nno shutdown') })
      expect(needsPrecheck(run, rollback, EMPTY_TPL, EMPTY_TPL, [], true), cli).toBe(true)
      expect(needsPrecheck(run, rollback, EMPTY_TPL, T({ cli: 'show running-config' }), [], true), `${cli} with a check and no refusal text`).toBe(true)
      expect(needsPrecheck(run, rollback, EMPTY_TPL, T({ cli: 'show running-config' }), ['Mode: trunk'], true), `${cli} with both`).toBe(false)
    }
    for (const path of ['/api/interface/{name}/disable', '/api/ports/{id}/disable', '/api/ports/{port}']) {
      expect(needsPrecheck(T({ method: 'POST', path }), T({ method: 'DELETE', path }), EMPTY_TPL, EMPTY_TPL, [], true), path).toBe(true)
    }
  })
  it('{interface} needs it everywhere, library actions included; a name or number in a body, or an address, does not', () => {
    const run = T({ cli: 'interface {interface}\nshutdown' })
    expect(needsPrecheck(run, EMPTY_TPL, EMPTY_TPL, EMPTY_TPL, [])).toBe(true)
    expect(needsPrecheck(T({ method: 'PUT', path: '/vip/{name}' }), EMPTY_TPL, EMPTY_TPL, EMPTY_TPL, [], false)).toBe(false) // a library action that names an object
    expect(needsPrecheck(T({ method: 'POST', path: '/d', body: '{"name":"{name}"}' }), EMPTY_TPL, EMPTY_TPL, EMPTY_TPL, [], true)).toBe(false)
    expect(needsPrecheck(T({ method: 'POST', path: '/block/{ip}' }), EMPTY_TPL, EMPTY_TPL, EMPTY_TPL, [], true)).toBe(false)
  })
})

describe('the check before and the read-back only read (D-95 (1), spec 1.6, 9.1 (3))', () => {
  it('an SSH check before cannot write: no change command, no line of the action or its undo', () => {
    const run = { cli: 'configure terminal\ninterface {interface}\nshutdown\nend' }, rollback = { cli: 'configure terminal\ninterface {interface}\nno shutdown\nend' }
    expect(cliProblem(CLI_BAN, steps({ run, rollback, pre: { cli: 'configure terminal\nshow interfaces {interface}' } }), true)).toMatch(/can change the device/)
    expect(cliProblem(CLI_BAN, steps({ run, rollback, pre: { cli: 'show interfaces {interface}\n  No  Shutdown ' } }), true)).not.toBeNull()
    expect(cliProblem(CLI_BAN, steps({ run: { cli: 'show a\nset x' }, rollback, pre: { cli: 'show interfaces\nSET   X' } }), true)).not.toBeNull()
    expect(cliProblem(CLI_BAN, steps({ run: { cli: 'poke port {interface}' }, rollback: { cli: 'poke port {interface} off' }, pre: { cli: 'show port\n  poke   port {interface} ' } }), true)).toMatch(/also a line of the action/)
    expect(cliProblem(CLI_BAN, steps({ run, rollback, pre: { cli: 'show interfaces {interface}\nreload' } }), true)).toMatch(/not allowed/)
    expect(cliProblem(CLI_BAN, steps({ run, rollback, verify: { cli: 'copy running-config startup-config' } }), true)).not.toBeNull()
    expect(cliProblem(CLI_BAN, steps({ run, rollback, verify: { cli: 'conf t\nshow x' } }), true)).not.toBeNull()
  })
  it('a pager line that opens the check and the action alike is fine; a plain read is fine', () => {
    const run = { cli: 'terminal length 0\nconfigure terminal\ninterface {interface}\nshutdown\nend' }, rollback = { cli: 'terminal length 0\nconfigure terminal\ninterface {interface}\nno shutdown\nend' }
    expect(cliProblem(CLI_BAN, steps({ run, rollback, pre: { cli: 'terminal length 0\nshow interfaces {interface} switchport' }, verify: { cli: 'terminal length 0\nshow interfaces {interface} status' } }), true)).toBeNull()
    expect(cliProblem(CLI_BAN, steps({ run, rollback, pre: { cli: 'show interfaces {interface}\nterminal length 0' } }), true)).not.toBeNull() // the pager line only counts as the first line
  })
  it('the refused commands (spec 9.3) are data and apply to a customer\'s run lines too; a library action is held to them only for its reads', () => {
    for (const cmd of ['reload', 'Reboot now', 'erase startup-config', 'write erase', 'format flash:', 'delete flash:x', 'factory-reset', 'no username admin', 'username evil secret x', 'enable secret 5 x', 'crypto key generate rsa', 'copy running-config tftp://10.0.0.9/x']) {
      expect(cliProblem(CLI_BAN, steps({ run: { cli: `interface {interface}\nshutdown\n${cmd}` } }), true), cmd).toMatch(/not allowed/)
    }
    expect(cliProblem(CLI_BAN, steps({ run: { cli: 'interface {interface}\nshutdown\nshow clock' } }), true)).toBeNull()
    expect(cliProblem(CLI_BAN, steps({ run: { cli: 'config firewall address\ndelete "vedette-{ip}"\nend' } }), false)).toBeNull() // reviewed data
    expect(cliProblem(CLI_BAN, steps({ run: { cli: 'x' }, verify: { cli: 'delete "vedette-{ip}"' } }), false)).not.toBeNull()
    expect(CLI_BAN.everywhere.length).toBeGreaterThan(10)
  })
  it('a read-back cannot write: an API read-back is a GET without a body', () => {
    for (const method of ['DELETE', 'POST', 'PUT', 'PATCH'] as const) expect(readBackProblem(T({ method, path: '/d/{domain}', expect: '"{domain}"' })), method).toMatch(/GET without a body/)
    expect(readBackProblem(T({ method: 'GET', path: '/d/{domain}', body: '{"delete":true}' }))).not.toBeNull()
    expect(readBackProblem(T({ method: 'GET', path: '/d/{domain}' }))).toBeNull()
    expect(readBackProblem(EMPTY_TPL)).toBeNull()
  })
  it('the check before: both texts are checked, the required text is plain ASCII up to 80', () => {
    const get = T({ method: 'GET', path: '/d/{domain}' })
    expect(validatePrecheck(get, [], 'http', 'ok')).toBeNull() // a required text alone is a check
    expect(validatePrecheck(get, [], 'http')).toMatch(/at least one text/)
    for (const bad of ['x'.repeat(81), 'a\nb', 'café', '   ']) expect(validatePrecheck(get, ['x'], 'http', bad), JSON.stringify(bad)).not.toBeNull()
    expect(validatePrecheck(EMPTY_TPL, [], 'http', 'x')).not.toBeNull()
    expect(validatePrecheck(get, Array.from({ length: 9 }, (_, i) => `r${i}`), 'http')).toMatch(/up to 8/)
  })
})

describe('headers a template may not set (D-94, review of 13b-2)', () => {
  it('method override, forwarding and credential headers are refused, in any case', () => {
    for (const h of ['X-HTTP-Method-Override', 'X-HTTP-Method', 'X-Method-Override', 'X-Real-IP', 'X-Original-URL', 'X-Rewrite-URL', 'Via', 'X-Forwarded', 'X-Forwarded-For', 'Authorization', 'Cookie', 'Host', 'Proxy-Foo', 'TE', 'Trailer', 'x-http-method-override']) {
      expect(forbiddenHeader(h), h).toBe(true)
      expect(validateTpl(T({ method: 'GET', path: '/d', headers: `${h}: x` }), 'Check before'), h).toMatch(/set by the connection/)
    }
    for (const h of ['Content-Type', 'Accept', 'X-Api-Key', 'X-Request-Id']) expect(forbiddenHeader(h), h).toBe(false)
  })
  it('a step that holds only headers is not empty, so it is validated', () => {
    expect(tplEmpty(T({ headers: 'Authorization: Bearer abc' }))).toBe(false)
    expect(validateTpl(T({ headers: 'Authorization: Bearer abc' }), 'Read-back')).not.toBeNull()
    expect(tplEmpty(EMPTY_TPL)).toBe(true)
  })
})
