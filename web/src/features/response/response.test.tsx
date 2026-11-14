import { beforeEach, describe, expect, it } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import { createMemoryRouter, MemoryRouter, RouterProvider } from 'react-router'
import { Toaster } from 'sonner'
import { makeQueryClient } from '@/app/App'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { eachOption } from '@/test/formMatrix'
import { collection } from '@/mocks/db'
import { connectorsStore, type Connector } from '@/mocks/connectors'
import { aiConfigStore, aiRunsStore, assetsStore, auditStore, modulesStore, orgStore, sessionStore, usersStore } from '@/mocks/stores'
import { checkValues, evalCondition, resolveParam, validateTpl, verifyChain, EMPTY_TPL, PARAM_CHECK, PARAM_TYPES, TOKEN_RE } from './logic'
import type { Role } from '@/lib/session'
import type { ActionRequest, AiState, Blocklist, Catalog, Condition, LogEntry, PlanList, ProposeResult, Rule, RuleInput, RunSummary, SettingsView, Simulation } from './types'
import ResponseSettings from './ResponseSettings'
import ResponsePage from './ResponsePage'
import FindingPanel from './FindingPanel'
import { ActionDialog } from './CatalogEditor'
import { RequestCard } from './RequestCard'
import { RuleDialog } from './RuleEditor'
import { actionsStore, buildChange, catalogStore, identityStore } from './state'
import { newLinkToken } from './identity'
import { telegramMessagesForTest } from '@/features/notify/mocks'

const USER: Record<Role, string> = { admin: 'u-admin', operator: 'u-op', viewer: 'u-view' }
const PROPOSAL = 'pr-f-1-nas-photo-443'
// The unverified FortiGate built-ins ship switched off for a new install (action-templates 12.1 item 6); these tests are about the gates, so the admin has switched them on.
beforeEach(() => { catalogStore.update((l) => l.map((c) => (['fgt_addrgrp_add', 'fgt_ban_ip', 'fgt_vip_disable'].includes(c.id) ? { ...c, enabled: true } : c))) })
const PHRASE = 'I ACCEPT THE RISK'

async function call<T = Record<string, unknown>>(role: Role, method: string, path: string, body?: unknown) {
  orgStore.update((o) => ({ ...o, setup_complete: true }))
  sessionStore.set({ userId: USER[role] })
  const res = await fetch(`${location.origin}/api/v1${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
  const json = (await res.json().catch(() => null)) as T & { error?: { code: string; message: string } }
  return { status: res.status, json, code: json?.error?.code }
}
const withTwofa = (on = true, ids = ['u-admin']) => usersStore.update((l) => l.map((u) => (ids.includes(u.id) ? { ...u, twofa: on } : u)))
async function turnOn() { withTwofa(); return call('admin', 'POST', '/response/execution', { enabled: true, phrase: PHRASE }) }
async function request() { return call<ActionRequest>('operator', 'POST', `/response/proposals/${PROPOSAL}/request`) }
const SETTINGS = { max_per_hour: 3, expiry_min: 15, approval_channels: [] as string[], breaker_max_per_hour: 20, multi_target_max: 5, maintenance: [] as unknown[], ai: { triggers: ['ioc_connection', 'finding'], budget_hour: 2, budget_day: 5 } }
const saveSettings = (over: Record<string, unknown> = {}) => call<SettingsView>('admin', 'PUT', '/response/settings', { ...SETTINGS, ...over })
const allow = (enabled: boolean) => call('admin', 'PUT', '/response/catalog/fgt_vip_disable', { enabled })
const actionsDb = collection<ActionRequest[]>('resp_actions', () => [])
const auditActions = () => auditStore.get().map((a) => a.action)
const list = <T,>(role: Role, path: string) => call<{ items: T[] }>(role, 'GET', path).then((r) => r.json.items)
const logList = () => list<LogEntry>('admin', '/response/log')
const getAction = async (id: string) => (await list<ActionRequest>('admin', '/response/actions')).find((a) => a.id === id)!
/** The notify channels of a test; every approver on them has linked their address (D-191), unless `linked` is false. */
function setChannels(list: { type: string; approvers?: { user_id: string; address: string }[]; [k: string]: unknown }[], linked = true) {
  collection<unknown>('notify_channels', () => []).set(list)
  identityStore.set(linked ? list.flatMap((c) => (c.approvers ?? []).map((a) => ({ user_id: a.user_id, channel: c.type, address: a.address, linked_at: new Date().toISOString() }))) : [])
}
function mapChat() {
  setChannels([
    { type: 'slack', configured: true, enabled: true, approvals: true, fields: { label: '#security' }, approvers: [{ user_id: 'u-op', address: 'U0OPS' }, { user_id: 'u-view', address: 'U0VIEW' }] },
    { type: 'telegram', configured: true, enabled: true, approvals: true, approvers: [{ user_id: 'u-admin', address: '777' }] },
  ])
}
const chat = (id: string, external_id: string, decision: 'approve' | 'reject' = 'approve') => call<ActionRequest>('admin', 'POST', `/response/actions/${id}/chat-decision`, { channel: 'slack', external_id, decision })

// ---- Rule helpers ----
const RULE: RuleInput = { name: 'Test rule', enabled: true, live: false, trigger: 'ioc_connection', match: 'all', conditions: [{ field: 'dest_kind', op: 'eq', value: 'ip', n: null, window_min: null }, { field: 'confidence', op: 'gte', value: '0.5', n: null, window_min: null }],
  actions: [{ action_id: 'blocklist_add', params: { ip: '{{trigger.dest_ip}}' }, ttl_min: 60 }], pre_approved: false, max_per_hour: 10, schedule_min: null }
const addRule = (over: Partial<RuleInput> = {}) => call<Rule>('admin', 'POST', '/response/rules', { ...RULE, ...over })
async function liveRule(over: Partial<RuleInput> = {}) {
  const r = await addRule(over)
  expect(r.status, JSON.stringify(r.json)).toBe(201)
  const live = await call<Rule>('admin', 'PUT', `/response/rules/${r.json.id}`, { ...RULE, ...over, live: true })
  expect(live.status).toBe(200)
  return live.json
}
/** Only the rule under test is on, so the run shows only its effect. */
async function onlyRule(id: string) {
  for (const r of await list<Rule>('admin', '/response/rules')) if (r.id !== id) await call('admin', 'PUT', `/response/rules/${r.id}`, { ...r, enabled: false })
  collection<string[]>('resp_done', () => []).set([])
}
const run = () => call<RunSummary>('operator', 'POST', '/response/rules/run').then((r) => r.json)
const pendingOf = async () => (await list<ActionRequest>('operator', '/response/actions')).filter((a) => a.status === 'pending')
const SSH_W: Connector = { id: 'cn-sw', name: 'Core switch (SSH)', kind: 'ssh', target: '192.168.10.2:22', asset_id: null, auth: { type: 'ssh-key', header: null, last4: 'c3Pq', key_fingerprint: null }, username: null, pin: null, allow: [], tools: [{ name: 'run_config', access: 'write', description: 'Run a configuration command', enabled: true }], enabled: true, status: 'ok', last_test: null }
const withSwitch = () => connectorsStore.update((l) => [...l, SSH_W])
async function enableSwitchActions() {
  withSwitch()
  // The built-in reads {previous_vlan} from the device while it runs, which a later version does; until then it is "not available yet". These tests are about approvals, so they use a copy whose undo puts the port back on VLAN 1.
  catalogStore.update((l) => l.map((c) => (c.id === 'cisco_port_vlan_quarantine' ? { ...c, rollback: { ...c.rollback, cli: c.rollback.cli.replace('{previous_vlan}', '1') } } : c)))
  expect((await call('admin', 'PUT', '/response/catalog/cisco_port_vlan_quarantine', { connection_id: 'cn-sw', enabled: true })).status).toBe(200)
}
const hpHits = (n: number, ip = '192.168.10.157') => collection<unknown>('hp_hits', () => []).set(Array.from({ length: n }, (_, i) => ({ id: `hit-t${i}`, ts: new Date(Date.now() - i * 60e3).toISOString(), kind: 'scan', src_ip: ip, trap_hostname: 'DECOY-1', is_test: false })))
const iocHits = (dests: string[]) => collection<unknown>('logs_ioc_hits', () => []).set(dests.map((d, i) => ({ id: `h${i + 1}`, ts: new Date().toISOString(), asset_id: null, src_ip: '192.168.10.105', dest: d, dest_kind: 'ip', seen_via: 'span_flow', feeds: ['IPsum'], confidence: 0.9 })))
const propose = (over: Record<string, unknown> = {}) => call<ProposeResult>('operator', 'POST', '/response/ai/proposals', {
  trigger: 'ioc_connection', action_id: 'blocklist_add', params: { ip: '185.220.101.77' }, confidence: 0.9, evidence: [{ kind: 'ioc_hit', id: 'h1' }], why: 'It keeps talking to a listed address.', ...over })

describe('response: AI plans (S-RESP-1, D-40)', () => {
  it('drafts the NAS plan from the inventory and the FortiGate read, with the exact change', async () => {
    mapChat()
    const { json } = await call<PlanList>('viewer', 'GET', '/response/plans?finding=f-1')
    expect(json.execution).toBe(false)
    const plan = json.items[0]!
    expect(plan.path).toContain('NAS-PHOTOS is reachable from the Internet through FortiGate virtual IP NAS-PHOTO-443')
    expect(plan.sent_to).toEqual(['Slack #security', 'Telegram'])
    expect(plan.steps.map((s) => s.kind)).toEqual(['contain', 'check', 'patch'])
    const p = plan.steps[0]!.proposal!
    expect(p.title).toBe('Turn off virtual IP NAS-PHOTO-443 on FW-HQ')
    expect(p.change.cli).toContain('edit "NAS-PHOTO-443"')
    expect(p.change.rest!.method).toBe('PUT')
    expect(p.change.rollback.cli).toContain('set status enable')
    expect(p.state).toBe('execution_off')
  })

  it('from 80 % of the month\'s AI budget the scheduled plan job drafts nothing (D-531a)', async () => {
    mapChat()
    collection<unknown[]>('resp_plans', () => []).set([]) // no plan drafted yet: only the job could add one
    aiConfigStore.update((c) => ({ ...c, monthly_budget: 10_000_000 }))
    aiRunsStore.set([{ id: 'run-spent', ts: new Date().toISOString(), skill: 'ask-my-data', model: 'claude-haiku-5-5', tokens_in: 8_500_000, tokens_out: 0, status: 'ok', profile: 'Claude Haiku' }])
    const { json } = await call<PlanList>('viewer', 'GET', '/response/plans?finding=f-1')
    expect(json.items).toEqual([])
  })

  it('clean install: no plans, no requests', async () => {
    const { setDataMode } = await import('@/mocks/db')
    setDataMode('clean')
    usersStore.set([{ id: 'u-admin', name: 'Admin', email: 'a@x.example', role: 'admin', password: 'x', twofa: false, created_at: new Date().toISOString(), last_login: null }])
    expect((await call<PlanList>('admin', 'GET', '/response/plans')).json.items).toEqual([])
    expect((await call<{ items: unknown[] }>('admin', 'GET', '/response/actions')).json.items).toEqual([])
  })
})

describe('response: security gates (S-RESP-2, D-41) G-1..G-8', () => {
  it('G-1 no request and no approval while the switch is off, and the refusal is audited', async () => {
    expect((await request()).code).toBe('execution_off')
    expect(auditActions()).toContain('response.refused')
  })

  it('G-2 enabling needs an admin, two-step sign-in and the exact phrase', async () => {
    expect((await call('operator', 'POST', '/response/execution', { enabled: true, phrase: PHRASE })).status).toBe(403)
    expect((await call('admin', 'POST', '/response/execution', { enabled: true, phrase: PHRASE })).code).toBe('twofa_required')
    withTwofa()
    for (const phrase of ['i accept the risk', 'I ACCEPT THE RISK ', 'I ACCEPT', undefined]) expect((await call('admin', 'POST', '/response/execution', { enabled: true, phrase })).code).toBe('phrase_mismatch')
    expect((await call<SettingsView>('admin', 'GET', '/response/settings')).json.execution).toBe(false)
    const ok = await call<SettingsView>('admin', 'POST', '/response/execution', { enabled: true, phrase: PHRASE })
    expect(ok.json.execution).toBe(true)
    expect(ok.json.accepted_by).toBe('admin@acme.example')
    expect(auditActions()).toContain('response.execution.enable')
  })

  it('G-3 a viewer can neither request nor approve', async () => {
    await turnOn()
    const r = await request()
    expect(r.status).toBe(201)
    expect((await call('viewer', 'POST', `/response/actions/${r.json.id}/approve`)).status).toBe(403)
    expect((await call('viewer', 'POST', `/response/proposals/${PROPOSAL}/request`)).status).toBe(403)
    expect((await getAction(r.json.id)).status).toBe('pending')
  })

  it('G-4 an expired request cannot be approved, nothing happens, and a notice is logged', async () => {
    await turnOn()
    const r = await request()
    actionsDb.update((l) => l.map((a) => (a.id === r.json.id ? { ...a, expires_at: new Date(Date.now() - 1000).toISOString() } : a)))
    expect((await call('operator', 'POST', `/response/actions/${r.json.id}/approve`)).code).toBe('expired')
    const a = await getAction(r.json.id)
    expect(a.status).toBe('expired')
    expect(a.items.every((i) => i.status === 'skipped')).toBe(true)
    expect(auditActions()).toContain('response.expire')
    expect((await logList()).some((e) => e.kind === 'expired' && /Notice sent/.test(e.detail))).toBe(true)
  })

  it('expiry is 15 minutes by default and only 15 to 30 can be configured', async () => {
    await turnOn()
    const r = await request()
    expect(Date.parse(r.json.expires_at) - Date.parse(r.json.requested_at)).toBe(15 * 60e3)
    for (const expiry_min of [5, 14, 31, 60]) expect((await saveSettings({ expiry_min })).code).toBe('invalid')
    expect((await saveSettings({ expiry_min: 30 })).status).toBe(200)
    await call('operator', 'POST', `/response/actions/${r.json.id}/reject`)
    expect(Date.parse((await request()).json.expires_at) - Date.now()).toBeGreaterThan(29 * 60e3)
  })

  it('G-5 a chat approval counts only from a mapped operator or admin on an approved channel, per channel', async () => {
    await turnOn(); mapChat()
    const r = await request()
    const id = r.json.id
    expect((await chat(id, 'U0NOPE')).code).toBe('approver_not_listed')
    expect((await chat(id, 'U0VIEW')).code).toBe('approver_not_listed') // on the list, but a viewer
    expect((await chat(id, 'U0OPS')).code).toBe('channel_not_allowed') // listed operator, channel not chosen for approvals
    expect((await saveSettings({ approval_channels: ['zalo'] })).status).toBe(400) // channel that does not exist
    await saveSettings({ approval_channels: ['slack', 'telegram'] })
    expect((await call('admin', 'POST', `/response/actions/${id}/chat-decision`, { channel: 'telegram', external_id: 'U0OPS', decision: 'approve' })).code).toBe('approver_not_listed')
    const ok = await chat(id, 'U0OPS')
    expect(ok.status).toBe(200)
    expect(ok.json.status).toBe('executed')
    expect(ok.json.approvals[0]!.via).toBe('slack')
    expect(ok.json.approvals[0]!.name).toBe('IT Operator')
    expect(ok.json.items[0]!.verified?.ok).toBe(true)
    expect(auditActions()).toEqual(expect.arrayContaining(['response.approve', 'response.execute']))
  })

  it('G-6 one request is approved once: a second approval is refused', async () => {
    await turnOn()
    const r = await request()
    expect((await call('operator', 'POST', `/response/actions/${r.json.id}/approve`)).status).toBe(200)
    expect((await call('operator', 'POST', `/response/actions/${r.json.id}/approve`)).code).toBe('not_pending')
    expect((await request()).code).toBe('already_requested')
    expect(auditStore.get().filter((a) => a.action === 'response.execute')).toHaveLength(1)
  })

  it('G-7 the client cannot send its own command: the request carries the stored change only', async () => {
    await turnOn()
    const res = await call<ActionRequest>('operator', 'POST', `/response/proposals/${PROPOSAL}/request`, { change: { cli: 'execute factoryreset' }, tool: 'x' })
    expect(res.json.items[0]!.change.cli).toContain('set status disable')
    expect(res.json.items[0]!.change.cli).not.toContain('factoryreset')
    expect((await call('operator', 'POST', '/response/proposals/not-a-proposal/request')).status).toBe(404)
  })

  it('G-8 hourly limit of approved device actions', async () => {
    await turnOn()
    await saveSettings({ max_per_hour: 1 })
    const a = await request()
    expect((await call('operator', 'POST', `/response/actions/${a.json.id}/approve`)).status).toBe(200)
    expect((await call('operator', 'POST', `/response/actions/${a.json.id}/rollback`)).status).toBe(200)
    const b = await request()
    expect(b.status).toBe(201)
    expect((await call('operator', 'POST', `/response/actions/${b.json.id}/approve`)).code).toBe('rate_limited')
  })

  it('only enabled catalog actions (allowed = enabled)', async () => {
    await turnOn()
    await allow(false)
    expect((await request()).code).toBe('tool_not_allowed')
    await allow(true)
    const r = await request()
    await allow(false)
    expect((await call('operator', 'POST', `/response/actions/${r.json.id}/approve`)).code).toBe('tool_not_allowed')
    expect((await call('operator', 'PUT', '/response/catalog/fgt_vip_disable', { enabled: true })).status).toBe(403)
  })

  it('only enabled write tools on enabled connections', async () => {
    await turnOn()
    const r = await request()
    connectorsStore.update((l) => l.map((c) => ({ ...c, tools: c.tools.map((t) => (t.name === 'disable_virtual_ip' ? { ...t, enabled: false } : t)) })))
    expect((await call('operator', 'POST', `/response/actions/${r.json.id}/approve`)).code).toBe('tool_unavailable')
    connectorsStore.update((l) => l.map((c) => ({ ...c, tools: c.tools.map((t) => (t.name === 'disable_virtual_ip' ? { ...t, enabled: true } : t)), enabled: false })))
    expect((await call('operator', 'POST', `/response/actions/${r.json.id}/approve`)).code).toBe('tool_unavailable')
    expect((await getAction(r.json.id)).status).toBe('pending')
  })

  it('emergency stop turns execution off and cancels every pending request', async () => {
    await turnOn()
    const r = await request()
    const before = (await pendingOf()).length
    const stop = await call<{ cancelled: number }>('operator', 'POST', '/response/emergency-stop')
    expect(stop.json.cancelled).toBe(before)
    const a = await getAction(r.json.id)
    expect(a.status).toBe('rejected')
    expect(a.note).toContain('emergency stop')
    expect((await call('operator', 'POST', `/response/actions/${r.json.id}/approve`)).code).toBe('not_pending')
    const s = (await call<SettingsView>('admin', 'GET', '/response/settings')).json
    expect(s.execution).toBe(false)
    expect(s.stopped_at).not.toBeNull() // INV-8: the stop also opens the breaker, until an administrator resumes
    expect(s.breaker_tripped_at).not.toBeNull()
    expect((await call<SettingsView>('operator', 'POST', '/response/breaker/reset')).status).toBe(403)
    const back = (await call<SettingsView>('admin', 'POST', '/response/breaker/reset')).json
    expect([back.stopped_at, back.breaker_tripped_at]).toEqual([null, null])
    expect((await call('viewer', 'POST', '/response/emergency-stop')).status).toBe(403)
    expect(auditActions()).toContain('response.emergency_stop')
  })

  it('rollback restores the device, needs execution on, and every step is in the audit log', async () => {
    await turnOn()
    const r = await request()
    await call('operator', 'POST', `/response/actions/${r.json.id}/approve`)
    await call('admin', 'POST', '/response/execution', { enabled: false })
    expect((await call('operator', 'POST', `/response/actions/${r.json.id}/rollback`)).code).toBe('execution_off')
    await call('admin', 'POST', '/response/execution', { enabled: true, phrase: PHRASE })
    const rb = await call<ActionRequest>('operator', 'POST', `/response/actions/${r.json.id}/rollback`)
    expect(rb.json.status).toBe('rolled_back')
    expect(auditActions()).toEqual(expect.arrayContaining(['response.execution.enable', 'response.request', 'response.approve', 'response.execute', 'response.execution.disable', 'response.refused', 'response.rollback']))
  })

  it('a rejected request stays rejected and records the reason', async () => {
    await turnOn()
    const r = await request()
    const rej = await call<ActionRequest>('operator', 'POST', `/response/actions/${r.json.id}/reject`, { reason: 'Planned change' })
    expect(rej.json.status).toBe('rejected')
    expect(rej.json.note).toContain('Planned change')
    expect((await call('operator', 'POST', `/response/actions/${r.json.id}/approve`)).code).toBe('not_pending')
  })
})

describe('response: approval model (D-51)', () => {
  it('every action needs approval by default: a live rule creates a pending bundled request and runs nothing', async () => {
    iocHits(['198.51.100.50'])
    const rule = await liveRule({ actions: [{ action_id: 'blocklist_add', params: { ip: '{{trigger.dest_ip}}' }, ttl_min: 60 }, { action_id: 'msg_send', params: { text: 'Bad connection from {{trigger.device}}' }, ttl_min: null }] })
    await onlyRule(rule.id)
    const sum = await run()
    expect(sum.requests).toBeGreaterThan(0)
    expect(sum.executed).toBe(0)
    const pending = (await pendingOf()).filter((a) => a.rule_id === rule.id && a.items.length === 2)
    expect(pending.length).toBe(1) // one bundled request per run; a duplicate target was merged out of the others
    expect(pending[0]!.items.every((i) => i.status === 'pending')).toBe(true)
    expect(pending[0]!.pre_approved).toBe(false)
    const bl = (await call<Blocklist>('admin', 'GET', '/response/blocklist')).json
    expect(bl.entries.map((e) => e.value)).not.toContain(pending[0]!.items[0]!.change.cli.split(' ').pop())
  })

  it('the approver can approve all or pick actions; unpicked actions are skipped', async () => {
    iocHits(['198.51.100.50'])
    const rule = await liveRule({ actions: [{ action_id: 'blocklist_add', params: { ip: '{{trigger.dest_ip}}' }, ttl_min: 60 }, { action_id: 'msg_send', params: { text: 'Bad connection from {{trigger.device}}' }, ttl_min: null }] })
    await onlyRule(rule.id); await run()
    const req = (await pendingOf()).find((a) => a.rule_id === rule.id && a.items.length === 2)!
    expect((await call('operator', 'POST', `/response/actions/${req.id}/approve`, { items: ['nope'] })).code).toBe('invalid_items')
    const ok = await call<ActionRequest>('operator', 'POST', `/response/actions/${req.id}/approve`, { items: [req.items[0]!.id] })
    expect(ok.json.status).toBe('executed')
    expect(ok.json.items.map((i) => i.status)).toEqual(['executed', 'skipped'])
    expect(ok.json.items[0]!.verified?.ok).toBe(true)
  })

  it('pre-approved is only for low-risk, reversible actions with an undo time of 24 hours or less, and only for an admin', async () => {
    const pre = (over: Partial<RuleInput>) => addRule({ pre_approved: true, ...over })
    expect((await pre({ actions: [{ action_id: 'fgt_addrgrp_add', params: { ip: '{{trigger.dest_ip}}' }, ttl_min: 60 }] })).status).toBe(400) // medium risk
    expect((await pre({ actions: [{ action_id: 'msg_send', params: { text: 'Hello' }, ttl_min: null }] })).status).toBe(400) // cannot be undone
    expect((await pre({ actions: [{ action_id: 'blocklist_add', params: { ip: '{{trigger.dest_ip}}' }, ttl_min: 1441 }] })).status).toBe(400) // more than 24 hours
    expect((await pre({ actions: [{ action_id: 'blocklist_add', params: { ip: '{{trigger.dest_ip}}' }, ttl_min: null }] })).status).toBe(400) // no undo time
    const ok = await pre({ actions: [{ action_id: 'blocklist_add', params: { ip: '{{trigger.dest_ip}}' }, ttl_min: 1440 }] })
    expect(ok.status).toBe(201)
    expect(ok.json.pre_approved).toBe(true)
    expect((await call('operator', 'POST', '/response/rules', { ...RULE, pre_approved: true, actions: [{ action_id: 'blocklist_add', params: { ip: '{{trigger.dest_ip}}' }, ttl_min: 60 }] })).status).toBe(403)
    // a rule that was pre-approved cannot be edited into a risky one
    expect((await call('admin', 'PUT', `/response/rules/${ok.json.id}`, { ...RULE, pre_approved: true, actions: [{ action_id: 'fgt_vip_disable', params: { name: '{{trigger.vip}}' }, ttl_min: 60 }], trigger: 'finding', conditions: [] })).status).toBe(400)
  })

  it('a pre-approved live rule runs without a person; the seeded one is marked in the request', async () => {
    const seeded = (await list<ActionRequest>('viewer', '/response/actions')).find((a) => a.id === 'act-seed-1')!
    expect(seeded.pre_approved).toBe(true)
    expect(seeded.approvals[0]!.via).toBe('auto')
    await call('admin', 'PUT', '/response/allowlist', { items: [] })
    const rule = await liveRule({ pre_approved: true, actions: [{ action_id: 'blocklist_add', params: { ip: '{{trigger.dest_ip}}' }, ttl_min: 600 }] })
    await onlyRule(rule.id)
    const sum = await run()
    expect(sum.executed).toBeGreaterThan(0)
    const done = (await list<ActionRequest>('viewer', '/response/actions')).filter((a) => a.rule_id === rule.id)
    expect(done.every((a) => a.pre_approved && a.status === 'executed')).toBe(true)
  })

  it('a high-risk action needs two different approvers, and the same person cannot approve twice', async () => {
    await turnOn(); await enableSwitchActions(); hpHits(3)
    const cloned = await call<Rule>('admin', 'POST', '/response/templates/tpl-sweep-vlan/clone')
    expect(cloned.status).toBe(201)
    expect(cloned.json.enabled).toBe(false)
    expect(cloned.json.live).toBe(false)
    await call('admin', 'PUT', `/response/rules/${cloned.json.id}`, { ...cloned.json, enabled: true, live: true })
    await onlyRule(cloned.json.id)
    await run()
    const req = (await pendingOf()).find((a) => a.rule_id === cloned.json.id)!
    expect(req.risk).toBe('high')
    expect(req.requires_approvals).toBe(2)
    expect(req.two_because).toMatch(/two different approvers/)
    expect(req.items[0]!.change.cli).toContain('switchport access vlan 999')
    mapChat(); await saveSettings({ approval_channels: ['slack', 'telegram'] })
    const first = await call<ActionRequest>('operator', 'POST', `/response/actions/${req.id}/approve`)
    expect(first.json.status).toBe('pending')
    expect(first.json.approvals).toHaveLength(1)
    expect(first.json.items[0]!.status).toBe('pending') // nothing ran yet
    expect((await call('operator', 'POST', `/response/actions/${req.id}/approve`)).code).toBe('same_approver')
    expect((await chat(req.id, 'U0OPS')).code).toBe('same_approver') // the same person from chat
    const second = await call<ActionRequest>('admin', 'POST', `/response/actions/${req.id}/approve`)
    expect(second.json.status).toBe('executed')
    expect(second.json.approvals.map((a) => a.user_id)).toEqual(['u-op', 'u-admin'])
  })

  it('an action that touches more targets than the limit also needs two approvers', async () => {
    await enableSwitchActions()
    const wide = await call<Rule>('admin', 'POST', '/response/rules', { ...RULE, trigger: 'manual', conditions: [], actions: [{ action_id: 'fgt_addrgrp_add', params: { ip: '{{trigger.ip}}' }, ttl_min: 60 }] })
    expect(wide.status).toBe(201)
    // 'cidr' fills {ip}? no: a range is its own type. The multi-target rule is exercised in the server through the targets count.
    const sim = await call<Simulation>('operator', 'POST', '/response/rules/simulate', { rule: { ...RULE, trigger: 'manual', conditions: [], actions: [{ action_id: 'fgt_addrgrp_add', params: { ip: '{{trigger.ip}}' }, ttl_min: 60 }] } })
    expect(sim.json.approvals).toBe(1)
  })

  it('email approval links stay single use; opening one approves nothing', async () => {
    await turnOn()
    setChannels([{ type: 'email', configured: true, enabled: true, approvals: true, approvers: [{ user_id: 'u-op', address: 'it@acme.example' }, { user_id: 'u-admin', address: 'admin@acme.example' }] }])
    await saveSettings({ approval_channels: ['email'] })
    const r = await request()
    const links = (await getAction(r.json.id)).email_links
    expect(links).toHaveLength(2)
    const token = links[0]!.url.split('/').pop()!
    const pub = async (m: string, p: string, b?: unknown) => { sessionStore.set({ userId: null }); const res = await fetch(`${location.origin}/api/v1${p}`, { method: m, headers: { 'Content-Type': 'application/json' }, body: b === undefined ? undefined : JSON.stringify(b) }); return { status: res.status, json: (await res.json()) as { state?: string; status?: string; error?: { code: string } } } }
    // the signed form of approval-tokens.md 4.1: v1.<id>.<tag>, both base64url of 16 bytes; the old 32 hex form is not a token any more
    expect(token).toMatch(TOKEN_RE)
    expect(new Set(links.map((l) => l.url.split('/').pop())).size).toBe(2)
    expect(TOKEN_RE.test('a'.repeat(32))).toBe(false)
    expect(TOKEN_RE.test(token.replace('v1.', 'v2.'))).toBe(false)
    expect(TOKEN_RE.test(`${token}x`)).toBe(false)
    expect((await pub('GET', `/response/approve/${'a'.repeat(32)}`)).json.state).toBe('unknown')
    expect((await pub('GET', `/response/approve/${token}`)).json.state).toBe('ready')
    expect(((await pub('GET', `/response/approve/${token}`)).json as { ai_generated?: boolean }).ai_generated, 'a rule request carries no AI label').toBe(false)
    expect((await getAction(r.json.id)).status).toBe('pending')
    expect((await pub('POST', `/response/approve/${token}`, { decision: 'approve' })).json.status).toBe('executed')
    expect((await pub('POST', `/response/approve/${token}`, { decision: 'approve' })).json.error?.code).toBe('used')
  })

  it('a link of a person who may no longer approve reads as no link (spec 8)', async () => {
    await turnOn()
    setChannels([{ type: 'email', configured: true, enabled: true, approvals: true, approvers: [{ user_id: 'u-op', address: 'it@acme.example' }, { user_id: 'u-admin', address: 'admin@acme.example' }] }])
    await saveSettings({ approval_channels: ['email'] })
    const r = await request()
    const token = (await getAction(r.json.id)).email_links[0]!.url.split('/').pop()!
    const pub = async (m: string, p: string, b?: unknown) => { sessionStore.set({ userId: null }); const res = await fetch(`${location.origin}/api/v1${p}`, { method: m, headers: { 'Content-Type': 'application/json' }, body: b === undefined ? undefined : JSON.stringify(b) }); return { status: res.status, json: (await res.json()) as { state?: string; title?: string | null; error?: { code: string } } } }
    expect((await pub('GET', `/response/approve/${token}`)).json.state).toBe('ready')
    usersStore.update((l) => l.map((u) => (u.id === 'u-op' ? { ...u, disabled: true } : u)))
    const gone = await pub('GET', `/response/approve/${token}`)
    expect(gone.json.state).toBe('unknown')
    expect(gone.json.title).toBeNull()
    expect((await pub('POST', `/response/approve/${token}`, { decision: 'approve' })).json.error?.code).toBe('approver_not_listed') // the page shows no link; the decision is refused 403, as in Go
  })

  it('two people, at most one by email link (D-124)', async () => {
    await turnOn()
    setChannels([{ type: 'email', configured: true, enabled: true, approvals: true, approvers: [{ user_id: 'u-op', address: 'it@acme.example' }, { user_id: 'u-admin', address: 'admin@acme.example' }] }])
    await saveSettings({ approval_channels: ['email'] })
    const r = await request()
    actionsStore.update((l) => l.map((a) => (a.id === r.json.id ? { ...a, items: a.items.map((i) => ({ ...i, targets: 99 })) } : a))) // more targets than the limit: two people
    const links = (await getAction(r.json.id)).email_links
    const [t1, t2] = links.map((l) => l.url.split('/').pop()!)
    const pub = async (m: string, p: string, b?: unknown) => { sessionStore.set({ userId: null }); const res = await fetch(`${location.origin}/api/v1${p}`, { method: m, headers: { 'Content-Type': 'application/json' }, body: b === undefined ? undefined : JSON.stringify(b) }); return { status: res.status, json: (await res.json()) as { status?: string; error?: { code: string } } } }
    expect((await pub('POST', `/response/approve/${t1}`, { decision: 'approve' })).json.status).toBe('pending')
    const second = await pub('POST', `/response/approve/${t2}`, { decision: 'approve' })
    expect(second.status).toBe(403)
    expect(second.json.error?.code).toBe('in_app_required')
    expect((await getAction(r.json.id)).approvals).toHaveLength(1)
    const done = await call<ActionRequest>('admin', 'POST', `/response/actions/${r.json.id}/approve`) // the other person, in the app
    expect(done.json.approvals.map((a) => a.via)).toEqual(['email', 'app'])
  })
})

describe('response: approvers prove their channel identity (S-RESP-2, D-191)', () => {
  const ids = (role: Role) => list<{ channel: string; address: string; linked: boolean; method: string; code_waiting: boolean }>(role, '/response/me/identities')
  const codeOf = (msg: string) => /code (\d{6})/.exec(msg)?.[1]
  const confirm = (role: Role, channel: string, code: string) => call(role, 'POST', `/response/me/identities/${channel}/confirm`, { code })
  const TG = (opId = '555') => [
    { type: 'slack', configured: true, enabled: true, approvals: true, fields: { label: '#security' }, approvers: [{ user_id: 'u-op', address: 'U0OPS' }] },
    { type: 'telegram', configured: true, enabled: true, approvals: true, approvers: [{ user_id: 'u-op', address: opId }, { user_id: 'u-admin', address: '777' }] },
  ]
  const tg = (id: string, external_id: string) => call<ActionRequest>('admin', 'POST', `/response/actions/${id}/chat-decision`, { channel: 'telegram', external_id, decision: 'approve' })
  async function unlinkedChat() {
    await turnOn(); setChannels(TG(), false)
    await saveSettings({ approval_channels: ['slack', 'telegram'] })
    return (await request()).json.id
  }

  it('Telegram: a press from a listed ID that is not linked decides nothing and holds no code; the person confirms the link signed in (D-414)', async () => {
    const id = await unlinkedChat()
    const r = await tg(id, '555')
    expect(r.status).toBe(403)
    expect(r.code).toBe('approver_not_linked')
    expect(codeOf(r.json.error!.message)).toBeUndefined()
    expect(r.json.error!.message).toMatch(/Open the link Vedette sent/)
    expect((await getAction(id)).approvals).toHaveLength(0)
    expect((await getAction(id)).status).toBe('pending')
    expect((await ids('operator')).find((r) => r.channel === 'telegram')).toEqual(expect.objectContaining({ address: '555', linked: false, method: 'send_code' }))
    const made = newLinkToken('u-op', 'telegram', '555')
    if (!('token' in made)) throw new Error(made.message)
    expect((await confirm('admin', 'telegram', made.token)).code).toBe('other_account') // another signed-in person: refused, the link stays good
    expect(auditActions()).toContain('response.identity_link_refused')
    expect((await confirm('operator', 'telegram', made.token)).status).toBe(200)
    expect(auditActions()).toContain('response.identity_link')
    expect((await ids('operator')).find((r) => r.channel === 'telegram')).toMatchObject({ linked: true, code_waiting: false })
    expect((await confirm('operator', 'telegram', made.token)).code).toBe('no_code') // single use
    const ok = await tg(id, '555')
    expect(ok.status).toBe(200)
    expect(ok.json.approvals[0]!.via).toBe('telegram')
  })

  it('Zalo personal: My account shows the status only; only the listed person, signed in, confirms the link the box sent (D-447)', async () => {
    await turnOn()
    setChannels([{ type: 'zalo-personal', configured: true, enabled: true, approvals: true, approvers: [{ user_id: 'u-op', address: '2938475610293847561' }] }], false)
    expect((await ids('operator')).find((r) => r.channel === 'zalo-personal')).toEqual(expect.objectContaining({ address: '2938475610293847561', linked: false, method: 'send_code' }))
    renderApp('/settings/account?tab=approvers', { role: 'operator' })
    const card = await screen.findByRole('region', { name: 'Approval channels' })
    const row = (await within(card).findByText('2938475610293847561')).closest('li')!
    expect(within(row).queryByLabelText('Code')).toBeNull() // status and Send again only: the link comes to the Zalo account (D-414)
    expect(within(row).getByRole('button', { name: 'Send again' })).toBeInTheDocument()
    const made = newLinkToken('u-op', 'zalo-personal', '2938475610293847561')
    if (!('token' in made)) throw new Error(made.message)
    expect((await confirm('admin', 'zalo-personal', made.token)).code).toBe('other_account') // another signed-in person: the link stays good
    expect((await confirm('operator', 'zalo-personal', '123456')).code).toBe('invalid_link')
    expect((await confirm('operator', 'zalo-personal', made.token)).json.linked).toBe(true)
    expect(auditActions()).toContain('response.identity_link')
    expect((await confirm('operator', 'zalo-personal', made.token)).code).toBe('no_code') // used
  })

  it('a channel whose answer others may see gets no code', async () => {
    const id = await unlinkedChat()
    const r = await chat(id, 'U0OPS')
    expect(r.code).toBe('approver_not_linked')
    expect(codeOf(r.json.error!.message)).toBeUndefined()
  })

  it('Telegram: My account shows Not linked and Send again; the bot sends a new link; the confirm page links it (D-414)', async () => {
    await unlinkedChat()
    renderApp('/settings/account?tab=approvers', { role: 'operator' })
    const card = await screen.findByRole('region', { name: 'Approval channels' })
    const row = (await within(card).findByText('555')).closest('li')!
    expect(within(row).getByText('Not linked')).toBeInTheDocument()
    expect(within(row).queryByLabelText('Code')).toBeNull()
    expect(within(row).queryByRole('alert')).toBeNull() // no red error before anything is done
    const before = telegramMessagesForTest().length
    await userEvent.click(within(row).getByRole('button', { name: 'Send again' }))
    expect(await within(row).findByText('Waiting')).toBeInTheDocument()
    const msg = telegramMessagesForTest()[before]!
    expect(msg.to).toBe('555')
    const path = /https:\/\/[^/]+(\/link\/telegram\?c=\S+)/.exec(msg.text)![1]!
    expect(auditActions()).toContain('notify.telegram_link_code')
    renderApp(path, { role: 'operator' })
    expect(await screen.findByText(/^Link Telegram account 555 to your Vedette user /)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Confirm' }))
    expect(await screen.findByText(/Linked\. Telegram user ID 555 now counts as you/)).toBeInTheDocument()
  })

  it('a changed ID or an unlink drops the proof', async () => {
    const id = await unlinkedChat()
    const made = newLinkToken('u-op', 'telegram', '555')
    if (!('token' in made)) throw new Error(made.message)
    expect((await confirm('operator', 'telegram', made.token)).status).toBe(200)
    collection<unknown>('notify_channels', () => []).set(TG('556')) // the administrator changed the ID; the stored proof is still for 555
    expect((await tg(id, '556')).code).toBe('approver_not_linked')
    collection<unknown>('notify_channels', () => []).set(TG())
    expect((await ids('operator')).find((r) => r.channel === 'telegram')!.linked).toBe(true)
    expect((await call('operator', 'DELETE', '/response/me/identities/telegram')).status).toBe(204)
    expect(auditActions()).toContain('response.identity_unlink')
    expect((await tg(id, '555')).code).toBe('approver_not_linked')
    expect((await call('operator', 'DELETE', '/response/me/identities/telegram')).code).toBe('not_linked')
  })

  it('email: a code to the sign-in email links it; a changed sign-in email unlinks it; no link is made for an unlinked address', async () => {
    await turnOn()
    setChannels([{ type: 'email', configured: true, enabled: true, approvals: true, approvers: [{ user_id: 'u-op', address: 'it@acme.example' }] }], false)
    await saveSettings({ approval_channels: ['email'] })
    expect((await getAction((await request()).json.id)).email_links).toHaveLength(0) // notify INV-13: no mail and no link for an unproved address
    expect((await call('operator', 'POST', '/response/me/identities/slack/code')).code).toBe('not_listed')
    const sent = await call<{ sent_to: string; preview_code: string }>('operator', 'POST', '/response/me/identities/email/code')
    expect(sent.status).toBe(200)
    expect(sent.json.sent_to).toBe('i•••@acme.example')
    expect((await call('operator', 'POST', '/response/me/identities/email/code')).code).toBe('resend_too_soon')
    expect((await confirm('operator', 'email', sent.json.preview_code)).status).toBe(200)
    expect((await call('operator', 'POST', '/response/me/identities/email/code')).code).toBe('already_linked')
    await call('operator', 'POST', '/response/emergency-stop')
    await call('admin', 'POST', '/response/breaker/reset')
    await turnOn()
    const r = await request()
    const token = (await getAction(r.json.id)).email_links.at(-1)!.url.split('/').pop()!
    sessionStore.set({ userId: null })
    expect((await (await fetch(`${location.origin}/api/v1/response/approve/${token}`)).json() as { state: string }).state).toBe('ready')
    usersStore.update((l) => l.map((u) => (u.id === 'u-op' ? { ...u, email: 'it2@acme.example' } : u)))
    expect((await (await fetch(`${location.origin}/api/v1/response/approve/${token}`)).json() as { state: string }).state).toBe('unknown')
    expect((await ids('operator'))[0]!.linked).toBe(false)
    expect((await call('operator', 'POST', '/response/me/identities/email/code')).code).toBe('address_mismatch')
  })

  it('a channel that is off lists nobody; Send again on a chat channel sends a new confirm link (D-414); viewers have no identities', async () => {
    setChannels([{ type: 'email', configured: true, enabled: false, approvals: true, approvers: [{ user_id: 'u-op', address: 'it@acme.example' }] }, { type: 'telegram', configured: true, enabled: true, approvals: true, approvers: [{ user_id: 'u-op', address: '42' }] }], false)
    expect((await call('operator', 'POST', '/response/me/identities/email/code')).code).toBe('not_listed')
    const again = await call<{ sent_to: string }>('operator', 'POST', '/response/me/identities/telegram/code')
    expect(again.json.sent_to).toBe('Telegram 42')
    expect((await call('operator', 'POST', '/response/me/identities/telegram/code')).code).toBe('resend_too_soon')
    expect((await call('viewer', 'GET', '/response/me/identities')).status).toBe(403)
  })

  it('settings show how many approvers linked and who has not', async () => {
    await turnOn(); mapChat(); identityStore.set([])
    const v = await call<SettingsView>('admin', 'GET', '/response/settings')
    expect(v.json.channels.find((c) => c.type === 'slack')).toMatchObject({ approvers: 2, linked: 0, unlinked: ['IT Operator', expect.any(String)] })
  })

  it('My account: no card for a viewer', async () => {
    renderApp('/settings/account?tab=approvers', { role: 'viewer' })
    await screen.findByRole('tab', { name: 'Sessions' }) // D-519: the tab is left out, so ?tab=approvers opens Profile
    expect(screen.getByRole('tab', { name: 'Profile' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.queryByText('Approval channels')).toBeNull()
  })
})

describe('response: typed placeholders and trigger data (D-51)', () => {
  it('every placeholder type accepts valid values and rejects injection', () => {
    const ok: Record<string, string> = { ip: '10.0.0.1', cidr: '10.0.0.0/24', domain: 'bad.example.com', port: '8080', mac: '3c:22:fb:10:aa:01', vlan: '999', interface: 'Gi1/0/12', id: '1042', name: 'NAS-PHOTO-443', text: 'NAS-PHOTO-443' }
    for (const p of PARAM_TYPES) expect(PARAM_CHECK[p](ok[p]!), p).toBe(true)
    const inject = ['10.0.0.1; reboot', '10.0.0.1\nreboot', '$(id)', '`id`', 'a | b', '10.0.0.1 && x', '"quoted"', '']
    for (const p of PARAM_TYPES) for (const v of inject) expect(PARAM_CHECK[p](v), `${p}: ${JSON.stringify(v)}`).toBe(false)
    const wrong: Record<string, string[]> = { ip: ['10.0.0.999', '1.2.3'], cidr: ['1.2.3.4/33', '1.2.3.4'], domain: ['x.y', 'bad_domain.com'], port: ['0', '70000'], mac: ['zz:zz:zz:zz:zz:zz'], vlan: ['0', '4095'], interface: ['bad name', '../x', 'a_b'], id: ['0', '2147483648', '12a', '-1', '1.5'], name: ['-lead', 'a b', 'a;b'], text: ['-leading', 'a'.repeat(81)] }
    for (const [p, vs] of Object.entries(wrong)) for (const v of vs) expect(PARAM_CHECK[p as keyof typeof PARAM_CHECK](v), `${p}: ${v}`).toBe(false)
    expect(checkValues(['ip'], { ip: '10.0.0.1\nreboot' })).not.toBeNull()
    expect(resolveParam('Alert {{trigger.device}} at {{ trigger.ip }}', { device: 'PC-1', ip: '10.0.0.5' })).toBe('Alert PC-1 at 10.0.0.5')
    expect(resolveParam('{{trigger.missing}}', {})).toBe('')
  })

  it('attacker-controlled trigger data is refused at run time and nothing is requested', async () => {
    for (const evil of ['Evil; reboot', 'Evil\nreboot', 'Evil `id`', 'Evil $(id)']) {
      assetsStore.update((l) => [...l, { ...l[0]!, id: 'a-evil', ip: '192.168.10.222', mac: '3c:22:fb:10:aa:99', hostname: 'evil', approved: false, vendor: { value: evil, source: 'dhcp', confidence: 1, seen_at: new Date().toISOString() } } as never])
      const rule = await liveRule({ trigger: 'unknown_device', conditions: [], actions: [{ action_id: 'msg_send', params: { text: 'Unknown device by {{trigger.vendor}}' }, ttl_min: null }] })
      await onlyRule(rule.id)
      const sum = await run()
      expect(sum.refused, evil).toBeGreaterThan(0)
      const all = JSON.stringify(await list<ActionRequest>('operator', '/response/actions'))
      expect(all, evil).not.toContain('Evil') // the crafted value never reached a request
      expect((await logList()).some((e) => e.kind === 'refused' && /not valid/.test(e.detail))).toBe(true)
      assetsStore.update((l) => l.filter((a) => a.id !== 'a-evil'))
      await call('admin', 'DELETE', `/response/rules/${rule.id}`)
    }
  })

  it('rules are checked when saved: unknown fields, wrong types and mixed values are refused', async () => {
    const bad = (params: Record<string, string>, action_id = 'blocklist_add') => addRule({ actions: [{ action_id, params, ttl_min: 60 }] })
    expect((await bad({ ip: '{{trigger.nope}}' })).status).toBe(400)
    expect((await bad({ ip: '{{trigger.device}}' })).status).toBe(400) // text field into an ip
    expect((await bad({ ip: '{{trigger.dest_ip}} extra' })).status).toBe(400)
    expect((await bad({ ip: '10.0.0.1; reboot' })).status).toBe(400)
    expect((await bad({})).status).toBe(400)
    expect((await bad({ ip: '{{trigger.dest_ip}}' })).status).toBe(201)
    expect((await addRule({ conditions: [{ field: 'nope', op: 'eq', value: 'x', n: null, window_min: null }] })).status).toBe(400)
    expect((await addRule({ conditions: [{ field: 'src_ip', op: 'in_cidr', value: 'x', n: null, window_min: null }] })).status).toBe(400)
  })

  it('conditions: equals, in list, CIDR, at least, device type, count in window, first time', () => {
    const now = Date.now(), ev = (id: string, m: number, f: Record<string, string>) => ({ id, ts: new Date(now - m * 60e3).toISOString(), fields: f, device_kind: 'camera' })
    const e = ev('e', 0, { ip: '10.1.2.3', n: '12', k: 'A' })
    const c = (op: string, field: string, value: string, n: number | null = null, window_min: number | null = null) => ({ op, field, value, n, window_min })
    expect(evalCondition(c('eq', 'k', 'a'), e, [])).toBe(true)
    expect(evalCondition(c('in', 'k', 'b, a'), e, [])).toBe(true)
    expect(evalCondition(c('in_cidr', 'ip', '10.1.0.0/16'), e, [])).toBe(true)
    expect(evalCondition(c('in_cidr', 'ip', '10.2.0.0/16'), e, [])).toBe(false)
    expect(evalCondition(c('gte', 'n', '12'), e, [])).toBe(true)
    expect(evalCondition(c('lte', 'n', '11'), e, [])).toBe(false)
    expect(evalCondition(c('device_type', '', 'camera,nvr'), e, [])).toBe(true)
    const others = [ev('o1', 3, { ip: '10.1.2.3' }), ev('o2', 6, { ip: '10.1.2.3' }), ev('o3', 30, { ip: '10.1.2.3' })]
    expect(evalCondition(c('count_window', 'ip', '', 3, 10), e, others)).toBe(true) // 2 earlier + this one within 10 minutes
    expect(evalCondition(c('count_window', 'ip', '', 4, 10), e, others)).toBe(false) // the third is 30 minutes old
    expect(evalCondition(c('first_time', 'ip', '', 24), e, others)).toBe(false)
    expect(evalCondition(c('first_time', 'ip', '', 24), e, [])).toBe(true)
  })
})

describe('response: safety envelope (D-51)', () => {
  it('dry run: a new rule starts in dry run, a match is logged and nothing is requested or run', async () => {
    iocHits(['198.51.100.50'])
    const r = await call<Rule>('admin', 'POST', '/response/rules', { ...RULE, live: true })
    expect(r.json.live).toBe(false) // the client cannot start a rule live
    await onlyRule(r.json.id)
    const before = (await list<ActionRequest>('operator', '/response/actions')).length
    const sum = await run()
    expect(sum.dry_run).toBeGreaterThan(0)
    expect(sum.requests).toBe(0)
    expect(sum.executed).toBe(0)
    expect((await list<ActionRequest>('operator', '/response/actions')).length).toBe(before)
    const dry = (await logList()).filter((e) => e.kind === 'dry_run')
    expect(dry.length).toBeGreaterThan(0)
    expect(dry[0]!.detail).toMatch(/Would do: Add .* to the block list/)
    expect(auditActions()).not.toContain('response.execute')
  })

  it('a log rule counts one pasted signature in 5 to 1440 minutes; it bans the address that sent N lines, and with none the ban is not available (D-287, D-288)', async () => {
    const sig = (value: string, window_min = 5, n = 10) => ({ field: 'signature', op: 'count_window' as const, value, n, window_min })
    const log = (conditions: RuleInput['conditions'], actions: RuleInput['actions'] = [{ action_id: 'msg_send', params: { text: '{{trigger.count}}' }, ttl_min: null }]) =>
      ({ ...RULE, trigger: 'log_threshold' as const, conditions, actions })
    expect((await addRule(log([sig('logid=0101039426 action=ssl-login-fail')]))).status).toBe(201)
    expect((await addRule(log([sig('Failed password for <name> from <ip> port <n> ssh<n>')]))).status).toBe(201)
    for (const bad of [[], [sig('4625: Failed logon', 4)], [sig('a'), sig('b')]]) expect((await addRule(log(bad))).status).toBe(400)
    expect((await addRule({ ...RULE, conditions: [{ field: 'dest_kind', op: 'eq', value: 'a=b', n: null, window_min: null }] })).status).toBe(400) // other values stay narrow
    expect((await addRule(log([sig('a\u2028b')]))).status).toBe(400) // one line, as the box counts it
    expect((await addRule({ ...log([sig('x')]), match: 'any' })).status).toBe(400)
    expect((await addRule(log([sig('x')], [{ action_id: 'msg_send', params: { text: '{{trigger.signature}}' }, ttl_min: null }]))).status).toBe(400)
    expect((await addRule(log([sig('  logid=0101039426 action=ssl-login-fail ')]))).json.conditions[0]!.value).toBe('logid=0101039426 action=ssl-login-fail')
    const ban = [{ action_id: 'blocklist_add', params: { ip: '{{trigger.source_ip}}' }, ttl_min: 60 }]
    const sim = await call<Simulation>('operator', 'POST', '/response/rules/simulate', { rule: log([sig('logid=0101039426 action=ssl-login-fail')], ban) })
    expect(sim.status).toBe(200)
    expect(sim.json.steps[0]!.change?.cli).toBe('blocklist add 203.0.113.99')
    const spread = await call<Simulation>('operator', 'POST', '/response/rules/simulate', { rule: log([sig('Failed password for <name> from <ip> port <n> ssh<n>', 10, 20)], ban), event_id: 'det-s-log-2' })
    expect(spread.status).toBe(200)
    expect(spread.json.steps[0]!.error).toMatch(/^Not available: no single address sent at least 20 lines of this signature/)
  })

  it('simulate shows the rendered commands and requests and executes nothing', async () => {
    iocHits(['198.51.100.50'])
    const before = [(await list<ActionRequest>('operator', '/response/actions')).length, (await logList()).length]
    const sim = await call<Simulation>('operator', 'POST', '/response/rules/simulate', { rule: { ...RULE, actions: [{ action_id: 'fgt_addrgrp_add', params: { ip: '{{trigger.dest_ip}}' }, ttl_min: 60 }] } })
    expect(sim.status).toBe(200)
    expect(sim.json.executed).toBe(0)
    expect(sim.json.event?.trigger).toBe('ioc_connection')
    expect(sim.json.steps[0]!.change?.rest?.url).toMatch(/^https:\/\/192\.168\.10\.1\/api\/v2\/cmdb\/firewall\/addrgrp\/Vedette-Blocked\/member$/)
    expect(sim.json.steps[0]!.change?.rest?.body).toMatch(/"name":"vedette-\d+\.\d+\.\d+\.\d+"/)
    expect(sim.json.notes.join(' ')).toMatch(/dry run/)
    expect((await list<ActionRequest>('operator', '/response/actions')).length).toBe(before[0])
    expect((await logList()).length).toBe(before[1]! + 1) // one simulated line
    expect((await logList()).at(-1)!.kind).toBe('simulated')
    expect(auditActions()).not.toContain('response.execute')
    const pre = await call<Simulation>('operator', 'POST', '/response/rules/simulate', { rule: { ...RULE, pre_approved: true } })
    expect(pre.json.notes.join(' ')).toMatch(/Pre-approved: a live run/)
    expect(pre.json.notes.join(' ')).not.toMatch(/needs approval|can be forged/) // review of D-286: one answer, not both
    expect((await call('viewer', 'POST', '/response/rules/simulate', { rule: RULE })).status).toBe(403)
    expect((await call('operator', 'POST', '/response/rules/simulate', { rule: { ...RULE, actions: [{ action_id: 'blocklist_add', params: { ip: 'x; y' }, ttl_min: 60 }] } })).status).toBe(400)
  })

  it('dedupe: the same target and action is merged, not asked again', async () => {
    iocHits(['198.51.100.50', '198.51.100.51'])
    const rule = await liveRule({ conditions: [{ field: 'dest_kind', op: 'eq', value: 'ip', n: null, window_min: null }] })
    await onlyRule(rule.id)
    const first = await run()
    expect(first.requests).toBeGreaterThan(0)
    const ips = (await list<ActionRequest>('operator', '/response/actions')).flatMap((a) => (a.status === 'pending' ? a.items.map((i) => i.change.cli) : []))
    expect(new Set(ips).size).toBe(ips.length) // no target twice
    // a second rule for the same events merges into what is already open
    const twin = await liveRule({ name: 'Twin rule' })
    await onlyRule(twin.id)
    const second = await run()
    expect(second.requests).toBe(0)
    expect(second.deduped).toBeGreaterThan(0)
    expect((await logList()).some((e) => e.kind === 'deduped')).toBe(true)
  })

  it('per-rule hourly limit', async () => {
    iocHits(['198.51.100.50', '198.51.100.51'])
    const rule = await liveRule({ max_per_hour: 1, conditions: [{ field: 'dest_kind', op: 'eq', value: 'ip', n: null, window_min: null }] })
    await onlyRule(rule.id)
    await call('admin', 'PUT', '/response/allowlist', { items: [] })
    const sum = await run()
    expect(sum.requests).toBe(1)
    expect((await logList()).some((e) => e.kind === 'refused' && /limit of 1 runs per hour/.test(e.detail))).toBe(true)
  })

  it('circuit breaker: more than N actions in an hour pauses everything, notifies, and an admin resumes', async () => {
    mapChat()
    expect((await saveSettings({ breaker_max_per_hour: 3 })).status).toBe(200)
    iocHits(['198.51.100.50', '198.51.100.51'])
    const rule = await liveRule({ conditions: [{ field: 'dest_kind', op: 'eq', value: 'ip', n: null, window_min: null }] })
    await onlyRule(rule.id)
    await run()
    const s = (await call<SettingsView>('admin', 'GET', '/response/settings')).json
    expect(s.breaker_tripped_at).not.toBeNull()
    expect(s.breaker_notified).toEqual(['Slack #security', 'Telegram'])
    const log = await logList()
    expect(log.some((e) => e.kind === 'breaker' && /Notified: Slack #security, Telegram/.test(e.detail))).toBe(true)
    // everything is paused: rules and the AI
    collection<string[]>('resp_done', () => []).set([])
    expect((await run()).requests).toBe(0)
    expect((await logList()).some((e) => e.kind === 'refused' && /circuit breaker is open/.test(e.detail))).toBe(true)
    iocHits(['198.51.100.9'])
    expect((await propose({ params: { ip: '198.51.100.9' } })).code).toBe('circuit_open')
    expect((await call('operator', 'POST', '/response/breaker/reset')).status).toBe(403)
    expect((await call<SettingsView>('admin', 'POST', '/response/breaker/reset')).json.breaker_tripped_at).toBeNull()
  })

  it('maintenance windows hold rules and AI requests', async () => {
    const now = Date.now()
    await saveSettings({ maintenance: [{ id: 'mw-1', name: 'Patch night', start: new Date(now - 60e3).toISOString(), end: new Date(now + 3600e3).toISOString() }] })
    const rule = await liveRule()
    await onlyRule(rule.id)
    expect((await run()).requests).toBe(0)
    expect((await logList()).some((e) => /maintenance window "Patch night"/.test(e.detail))).toBe(true)
    iocHits(['198.51.100.9'])
    expect((await propose({ params: { ip: '198.51.100.9' } })).code).toBe('maintenance')
    expect((await saveSettings({ maintenance: [{ id: 'x', name: 'Bad', start: new Date(now).toISOString(), end: new Date(now - 1000).toISOString() }] })).status).toBe(400)
  })

  it('never-touch list: never changed by a rule, even when a feed lists it; a range protects its members', async () => {
    const rule = await liveRule({ pre_approved: true, actions: [{ action_id: 'blocklist_add', params: { ip: '{{trigger.dest_ip}}' }, ttl_min: 600 }], conditions: [{ field: 'dest_kind', op: 'eq', value: 'ip', n: null, window_min: null }] })
    await onlyRule(rule.id)
    await run()
    const entries = (await call<Blocklist>('admin', 'GET', '/response/blocklist')).json.entries.map((e) => e.value)
    expect(entries).not.toContain('1.1.1.1') // a public DNS server on the never-touch list
    expect((await logList()).filter((e) => e.kind === 'refused').map((e) => e.detail).join('\n')).toMatch(/never-touch list \(Public DNS/)
    expect((await call('admin', 'PUT', '/response/allowlist', { items: [{ value: 'x; rm -rf /', label: 'bad' }] })).status).toBe(400)
    expect((await call('admin', 'PUT', '/response/allowlist', { items: [{ value: '185.220.101.0/24', label: 'Range' }] })).status).toBe(200)
    collection<string[]>('resp_done', () => []).set([])
    await run()
    expect((await logList()).filter((e) => e.kind === 'refused').map((e) => e.detail).join('\n')).toMatch(/185\.220\.101\.0\/24/)
  })

  it('a finding rule never switches off forwarding to a device on the never-touch list', async () => {
    await turnOn()
    const rule = await liveRule({ trigger: 'finding', conditions: [{ field: 'exposed_via_nat', op: 'eq', value: 'true', n: null, window_min: null }, { field: 'ip', op: 'eq', value: '192.168.10.21', n: null, window_min: null }], actions: [{ action_id: 'fgt_vip_disable', params: { name: '{{trigger.vip}}' }, ttl_min: 1440 }] })
    await onlyRule(rule.id)
    await call('admin', 'PUT', '/response/allowlist', { items: [{ value: '192.168.10.21', label: 'Declared service: photos' }] })
    await run()
    expect((await list<ActionRequest>('operator', '/response/actions')).some((a) => a.rule_id === rule.id)).toBe(false)
    await call('admin', 'PUT', '/response/allowlist', { items: [] })
    collection<string[]>('resp_done', () => []).set([])
    await run()
    const nat = (await list<ActionRequest>('operator', '/response/actions')).find((a) => a.rule_id === rule.id)!
    expect(nat.source).toBe('rule')
    expect(nat.status).toBe('pending')
    expect(nat.items[0]!.change.rest!.url).toContain('/vip/NAS-PHOTO-443')
  })

  it('TTL: an executed change is undone when its undo time ends', async () => {
    const rule = await liveRule({ pre_approved: true, actions: [{ action_id: 'blocklist_add', params: { ip: '{{trigger.dest_ip}}' }, ttl_min: 600 }], conditions: [{ field: 'dest_kind', op: 'eq', value: 'ip', n: null, window_min: null }] })
    await onlyRule(rule.id); await call('admin', 'PUT', '/response/allowlist', { items: [] })
    await run()
    const bl = (await call<Blocklist>('admin', 'GET', '/response/blocklist')).json
    expect(bl.entries.length).toBeGreaterThan(0)
    actionsDb.update((l) => l.map((a) => ({ ...a, items: a.items.map((i) => (i.status === 'executed' ? { ...i, remove_at: new Date(Date.now() - 1000).toISOString() } : i)) })))
    expect((await call<Blocklist>('admin', 'GET', '/response/blocklist')).json.entries).toEqual([])
    expect((await logList()).filter((x) => x.kind === 'ttl_removed').length).toBeGreaterThan(0)
  })

  it('rules: only an admin edits, a rule needs one action, templates clone disabled in dry run', async () => {
    expect((await call('operator', 'POST', '/response/rules', RULE)).status).toBe(403)
    expect((await addRule({ actions: [] })).status).toBe(400)
    const t = await list<{ id: string; rule: RuleInput }>('viewer', '/response/templates')
    expect(t.length).toBeGreaterThanOrEqual(12)
    expect(t.length).toBeLessThanOrEqual(15)
    expect(t.every((x) => !x.rule.enabled && !x.rule.live)).toBe(true)
    const clone = await call<Rule>('admin', 'POST', `/response/templates/${t[0]!.id}/clone`)
    expect(clone.json).toMatchObject({ enabled: false, live: false, pre_approved: false })
    expect((await call('operator', 'POST', `/response/templates/${t[0]!.id}/clone`)).status).toBe(403)
  })
})

describe('response: AI requests, server-side gates (D-51)', () => {
  // Two known-bad connections seen on port Gi1/0/7 of the switch, and a finding that tells the server which device the port belongs to (the never-touch subject).
  const OK_HIGH = { trigger: 'ioc_connection', action_id: 'cisco_port_vlan_quarantine', params: { interface: 'Gi1/0/7', vlan: '999' }, confidence: 0.95, evidence: [{ kind: 'ioc_hit', id: 'hp1' }, { kind: 'ioc_hit', id: 'hp2' }, { kind: 'finding', id: 'f-1' }] }
  const portHits = () => collection<unknown>('logs_ioc_hits', () => []).update((l) => [...(l as unknown[]), ...['hp1', 'hp2'].map((id, i) => ({ id, ts: new Date().toISOString(), asset_id: null, src_ip: '192.168.10.105', dest: `203.0.113.${i + 1}`, dest_kind: 'ip', switch_port: 'Gi1/0/7', seen_via: 'span_flow', feeds: ['IPsum'], confidence: 0.9 }))])
  const setup = async () => { await saveSettings({ ai: { triggers: ['ioc_connection', 'finding'], budget_hour: 20, budget_day: 100 } }); iocHits(['185.220.101.77', '198.51.100.1', '198.51.100.2', '198.51.100.3', '198.51.100.4', '198.51.100.5', '198.51.100.6']) }
  /** Another known-bad connection about the same address: real new evidence. */
  const moreHits = (id: string, dest: string) => collection<unknown>('logs_ioc_hits', () => []).update((l) => [...(l as unknown[]), { id, ts: new Date().toISOString(), asset_id: null, src_ip: '192.168.10.106', dest, dest_kind: 'ip', seen_via: 'span_flow', feeds: ['IPsum'], confidence: 0.9 }])

  it('a good request becomes a pending request with the evidence the server verified', async () => {
    await setup()
    const r = await propose()
    expect(r.status).toBe(201)
    expect(r.json.outcome).toBe('request')
    const a = r.json.request!
    expect(a.source).toBe('ai')
    expect(a.status).toBe('pending')
    expect(a.ai!.evidence[0]!.summary).toContain('185.220.101.77')
    expect(a.items[0]!.change.cli).toBe('blocklist add 185.220.101.77')
  })

  it('the AI never writes commands: any command, request or template field is refused', async () => {
    await setup()
    for (const field of ['cli', 'rest', 'change', 'command', 'url', 'body']) expect((await propose({ [field]: 'execute factoryreset' })).code, field).toBe('no_commands')
    expect((await propose({ params: { ip: '185.220.101.77; reboot' } })).code).toBe('invalid_target')
    expect((await propose({ action_id: 'does_not_exist' })).code).toBe('invalid')
  })

  it('only triggers the admin allows for the AI, and only actions flagged "AI may propose"', async () => {
    await setup()
    expect((await propose({ trigger: 'honeypot' })).code).toBe('trigger_not_allowed')
    expect((await propose({ action_id: 'webhook_call', params: { text: 'hello' } })).code).toBe('action_not_ai_allowed')
    await call('admin', 'PUT', '/response/catalog/blocklist_add', { ai_may_propose: false })
    expect((await propose()).code).toBe('action_not_ai_allowed')
    expect((await call('operator', 'PUT', '/response/catalog/blocklist_add', { ai_may_propose: true })).status).toBe(403)
  })

  it('evidence must be real, and about the target', async () => {
    await setup()
    expect((await propose({ evidence: [] })).code).toBe('evidence_missing')
    expect((await propose({ evidence: [{ kind: 'ioc_hit', id: 'h-invented' }] })).code).toBe('evidence_invalid')
    expect((await propose({ evidence: [{ kind: 'finding', id: 'f-invented' }] })).code).toBe('evidence_invalid')
    expect((await propose({ evidence: [{ kind: 'config_read', id: 'cn-fgt/disable_virtual_ip' }] })).code).toBe('evidence_invalid') // a write tool is not a read
    expect((await propose({ evidence: [{ kind: 'config_read', id: 'cn-fgt/get_virtual_ips/x' }] })).code).toBe('evidence_invalid') // exactly one slash
    expect((await propose({ evidence: [{ kind: 'ioc_hit', id: 'h2' }] })).code).toBe('evidence_mismatch') // a real hit about another address
    expect((await propose({ evidence: [{ kind: 'finding', id: 'f-1' }, { kind: 'ioc_hit', id: 'h1' }] })).status).toBe(201)
  })

  it('confidence below 0.8 is a suggestion note with no approval request', async () => {
    await setup()
    const before = (await list<ActionRequest>('operator', '/response/actions')).length
    const r = await propose({ confidence: 0.79 })
    expect(r.json.outcome).toBe('suggestion')
    expect(r.json.request).toBeNull()
    expect((await list<ActionRequest>('operator', '/response/actions')).length).toBe(before)
    expect((await call<AiState>('viewer', 'GET', '/response/ai')).json.notes.some((n) => n.target === '185.220.101.77' && n.kind === 'suggestion')).toBe(true)
    expect((await propose({ confidence: 0.8 })).json.outcome).toBe('request')
  })

  it('a connection read is evidence only for a device action through that same connection; a box action needs a finding or a known-bad connection about its target (D-119)', async () => {
    await setup()
    // the read happened, but it says nothing about a block-list address: the block list is not on a connection
    expect((await propose({ evidence: [{ kind: 'ioc_hit', id: 'h2' }, { kind: 'config_read', id: 'cn-fgt/get_virtual_ips' }] })).code).toBe('evidence_mismatch')
    // a read alone never proves a trigger
    expect((await propose({ evidence: [{ kind: 'config_read', id: 'cn-fgt/get_virtual_ips' }] })).code).toBe('evidence_mismatch')
    // a device action through another connection: the read of the firewall is not about a port of the switch
    await turnOn(); await enableSwitchActions(); portHits()
    const other = { ...OK_HIGH, evidence: [{ kind: 'ioc_hit', id: 'h1' }, { kind: 'config_read', id: 'cn-fgt/get_virtual_ips' }, { kind: 'finding', id: 'f-1' }] }
    expect((await propose(other)).code).toBe('evidence_mismatch')
    // through the action's own connection it counts
    connectorsStore.update((l) => l.map((c) => (c.id === 'cn-sw' ? { ...c, tools: [...c.tools, { name: 'show_config', access: 'read' as const, description: 'Read the configuration', enabled: true }] } : c)))
    const own = { ...OK_HIGH, evidence: [{ kind: 'ioc_hit', id: 'hp1' }, { kind: 'config_read', id: 'cn-sw/show_config' }, { kind: 'finding', id: 'f-1' }] }
    expect((await propose(own)).status).toBe(201)
  })

  it('the trigger must be proven by a kind of evidence, and some triggers cannot be proven at all (D-119)', async () => {
    await setup()
    expect((await propose({ trigger: 'finding' })).code).toBe('evidence_mismatch') // a finding trigger needs a finding among the evidence
    await saveSettings({ ai: { triggers: ['ioc_connection', 'finding', 'honeypot'], budget_hour: 20, budget_day: 100 } })
    const r = await propose({ trigger: 'honeypot' })
    expect(r.code).toBe('trigger_not_allowed')
    expect(r.json.error?.message).toContain('no kind of evidence can prove this trigger')
  })

  it('only open findings count as evidence', async () => {
    await setup()
    expect((await propose({ trigger: 'finding', action_id: 'fgt_addrgrp_add', params: { ip: '192.168.10.21' }, evidence: [{ kind: 'finding', id: 'f-1' }] })).status).toBe(201)
    await call('operator', 'POST', `/response/actions/${(await pendingOf())[0]!.id}/reject`, { reason: 'x' })
    const { findingsStore } = await import('@/mocks/stores')
    findingsStore.update((l) => l.map((f) => (f.id === 'f-1' ? { ...f, status: 'false_positive' as const } : f)))
    expect((await propose({ trigger: 'finding', action_id: 'fgt_addrgrp_add', params: { ip: '192.168.10.21' }, evidence: [{ kind: 'finding', id: 'f-1' }] })).code).toBe('evidence_invalid')
  })

  it('a never-touch address is refused for the device of every cited finding; a port action needs a finding for its subject (D-119)', async () => {
    await setup(); await turnOn(); await enableSwitchActions(); portHits()
    expect((await propose({ ...OK_HIGH, evidence: [{ kind: 'ioc_hit', id: 'hp1' }, { kind: 'ioc_hit', id: 'hp2' }] })).code).toBe('never_touch') // no finding: no subject
    expect((await propose({ ...OK_HIGH, evidence: [...OK_HIGH.evidence] })).status).toBe(201)
  })

  it('a cancellation (emergency stop) is not a rejection: it neither blocks a repeat nor counts for the quality breaker (D-119)', async () => {
    await setup()
    const before = (await call<AiState>('viewer', 'GET', '/response/ai')).json.quality
    expect((await propose()).status).toBe(201)
    expect((await call('operator', 'POST', '/response/emergency-stop')).status).toBe(200)
    expect((await call('admin', 'POST', '/response/breaker/reset')).status).toBe(200) // the stop opens the breaker (INV-8); the AI asks again once resumed
    expect((await call<AiState>('viewer', 'GET', '/response/ai')).json.quality).toMatchObject({ decided: before.decided, rejected: before.rejected })
    expect((await propose()).status).toBe(201)
  })

  it('more than 60 proposals in an hour are refused with 429; notes of each kind are capped at 50 (D-119)', async () => {
    await setup()
    for (let i = 0; i < 60; i++) expect((await propose({ confidence: 0.5 })).json.outcome ?? 'x').toBe('suggestion')
    const over = await propose({ confidence: 0.5 })
    expect(over.status).toBe(429)
    expect(over.code).toBe('rate_limited')
    const notes = (await call<AiState>('viewer', 'GET', '/response/ai')).json.notes
    expect(notes.filter((n) => n.kind === 'suggestion')).toHaveLength(50)
    expect((await logList()).filter((e) => e.kind === 'refused' && /rate_limited/.test(e.detail))).toHaveLength(1)
  })

  it('one open request per target and action', async () => {
    await setup()
    expect((await propose()).status).toBe(201)
    expect((await propose()).code).toBe('already_open')
    expect((await propose({ params: { ip: '198.51.100.1' }, evidence: [{ kind: 'ioc_hit', id: 'h2' }] })).status).toBe(201)
  })

  it('after a rejection, no repeat for 7 days unless there is new evidence; the reason can be saved as a hint', async () => {
    await setup()
    const a = (await propose()).json.request!
    const rej = await call<ActionRequest>('operator', 'POST', `/response/actions/${a.id}/reject`, { reason: 'This is our backup provider', remember: 'memory' })
    expect(rej.json.status).toBe('rejected')
    expect((await propose()).code).toBe('repeat_blocked')
    expect((await propose({ evidence: [{ kind: 'ioc_hit', id: 'h1' }, { kind: 'config_read', id: 'cn-fgt/get_virtual_ips' }] })).code).toBe('repeat_blocked') // a read that is not about the target is not new evidence
    expect((await propose({ evidence: [{ kind: 'ioc_hit', id: 'h1' }, { kind: 'ioc_hit', id: 'h3' }] })).code).toBe('repeat_blocked') // a hit about another address is not new evidence either
    moreHits('h-new', '185.220.101.77')
    expect((await propose({ evidence: [{ kind: 'ioc_hit', id: 'h1' }, { kind: 'ioc_hit', id: 'h-new' }] })).status).toBe(201) // new evidence about the same address
    const hints = (await call<AiState>('viewer', 'GET', '/response/ai')).json.hints
    expect(hints.some((h) => h.kind === 'memory' && h.text === 'This is our backup provider')).toBe(true)
    // after 7 days the rejection no longer counts
    actionsDb.update((l) => l.map((x) => (x.id === a.id ? { ...x, decided_at: new Date(Date.now() - 8 * 864e5).toISOString() } : x)))
    expect((await call<AiState>('viewer', 'GET', '/response/ai')).json.hints.length).toBeGreaterThan(0)
  })

  it('budget: over the hourly or daily budget the proposal goes into a digest', async () => {
    await saveSettings({ ai: { triggers: ['ioc_connection'], budget_hour: 2, budget_day: 5 } })
    iocHits(['198.51.100.1', '198.51.100.2', '198.51.100.3'])
    // one seeded AI request is already inside the hour
    expect((await propose({ params: { ip: '198.51.100.1' }, evidence: [{ kind: 'ioc_hit', id: 'h1' }] })).json.outcome).toBe('request')
    const over = await propose({ params: { ip: '198.51.100.2' }, evidence: [{ kind: 'ioc_hit', id: 'h2' }] })
    expect(over.json.outcome).toBe('digest')
    expect(over.json.request).toBeNull()
    const ai = (await call<AiState>('viewer', 'GET', '/response/ai')).json
    expect(ai.notes.some((n) => n.kind === 'digest' && n.target === '198.51.100.2')).toBe(true)
    expect(ai.usage.hour).toBe(2)
    expect((await saveSettings({ ai: { triggers: ['ioc_connection'], budget_hour: 5, budget_day: 3 } })).status).toBe(400) // day budget cannot be below the hourly one
  })

  it('quality breaker: more than half of the last 10 rejected pauses AI requests until an admin resumes', async () => {
    await setup()
    const targets = ['198.51.100.1', '198.51.100.2', '198.51.100.3', '198.51.100.4', '198.51.100.5']
    let paused = false
    for (const [i, ip] of targets.entries()) {
      const r = await propose({ params: { ip }, evidence: [{ kind: 'ioc_hit', id: `h${i + 2}` }] })
      if (r.code === 'ai_paused') { paused = true; break }
      expect(r.status).toBe(201)
      await call('operator', 'POST', `/response/actions/${r.json.request!.id}/reject`, { reason: 'Not a threat' })
    }
    const ai = (await call<AiState>('viewer', 'GET', '/response/ai')).json
    expect(ai.gates.paused_at).not.toBeNull()
    expect(ai.quality.rejected * 2).toBeGreaterThan(ai.quality.decided)
    expect(paused || (await propose({ params: { ip: '198.51.100.6' }, evidence: [{ kind: 'ioc_hit', id: 'h7' }] })).code === 'ai_paused').toBe(true)
    expect((await logList()).some((e) => e.kind === 'breaker' && /quality breaker/.test(e.detail))).toBe(true)
    expect((await call('operator', 'POST', '/response/ai/resume')).status).toBe(403)
    expect((await call<AiState>('admin', 'POST', '/response/ai/resume')).json.gates.paused_at).toBeNull()
  })

  it('high risk: a second check, and approval only in the app with the two-step code, from two different people', async () => {
    await turnOn(); await enableSwitchActions(); iocHits(['185.220.101.77']); portHits(); await saveSettings({ ai: { triggers: ['ioc_connection'], budget_hour: 20, budget_day: 100 } })
    mapChat(); await saveSettings({ approval_channels: ['slack', 'telegram'], ai: { triggers: ['ioc_connection'], budget_hour: 20, budget_day: 100 } })
    // second checker: needs 2 pieces of evidence and a confidence of 0.9 or more
    expect((await propose({ ...OK_HIGH, evidence: [OK_HIGH.evidence[0], OK_HIGH.evidence[2]] })).code).toBe('second_check_failed')
    expect((await propose({ ...OK_HIGH, evidence: [...OK_HIGH.evidence, { kind: 'ioc_hit', id: 'h1' }].filter((e) => e.id !== 'hp2') })).code).toBe('second_check_failed') // one about the port, one about something else
    expect((await propose({ ...OK_HIGH, confidence: 0.85 })).code).toBe('second_check_failed')
    const r = await propose(OK_HIGH)
    expect(r.status).toBe(201)
    const a = r.json.request!
    expect(a.risk).toBe('high')
    expect(a.requires_approvals).toBe(2)
    expect(a.ai!.in_app_only).toBe(true)
    expect(a.ai!.second_check?.ok).toBe(true)
    // not one tap from chat
    expect((await chat(a.id, 'U0OPS')).code).toBe('in_app_required')
    // in the app: two-step must be on, and the code must be given
    expect((await call('operator', 'POST', `/response/actions/${a.id}/approve`)).code).toBe('twofa_required')
    withTwofa(true, ['u-admin', 'u-op'])
    expect((await call('operator', 'POST', `/response/actions/${a.id}/approve`)).code).toBe('code_required')
    expect((await call('operator', 'POST', `/response/actions/${a.id}/approve`, { code: 'abc' })).code).toBe('invalid_code')
    const first = await call<ActionRequest>('operator', 'POST', `/response/actions/${a.id}/approve`, { code: '123456' })
    expect(first.json.status).toBe('pending')
    expect(first.json.approvals).toHaveLength(1)
    expect((await call('operator', 'POST', `/response/actions/${a.id}/approve`, { code: '123456' })).code).toBe('same_approver')
    const second = await call<ActionRequest>('admin', 'POST', `/response/actions/${a.id}/approve`, { code: '654321' })
    expect(second.json.status).toBe('executed')
  })
})

describe('response: action catalog (S-RESP-4)', () => {
  const CUSTOM = { name: 'Block a domain on the DNS filter', description: 'Adds a domain to the filter.', connection_id: 'cn-fgt', tool: null, rollback_tool: null, risk: 'low', enabled: true, ai_may_propose: false,
    run: { ...EMPTY_TPL, method: 'POST', path: '/api/v2/cmdb/webfilter/urlfilter/1/entries', body: '{"url":"{domain}"}' }, rollback: { ...EMPTY_TPL, method: 'DELETE', path: '/api/v2/cmdb/webfilter/urlfilter/1/entries/{domain}' }, verify: EMPTY_TPL }
  const MCP: Connector = { id: 'cn-mcp', name: 'Firewall MCP server', kind: 'mcp-http', target: 'https://mcp.lan/mcp', asset_id: null, auth: { type: 'token', header: null, last4: 'z9Zz', key_fingerprint: null }, username: null, pin: null, allow: [], enabled: true, status: 'ok', last_test: null,
    tools: [{ name: 'list_rules', access: 'read', description: '', enabled: true }, { name: 'block_address', access: 'write', description: '', enabled: true }, { name: 'unblock_address', access: 'write', description: '', enabled: true }] }

  it('template placeholders are typed and shell metacharacters are refused', () => {
    for (const bad of ['block {ip}; rm -rf /', 'block {ip} | nc evil 1', 'block $(id) {ip}', 'block `id` {ip}', 'block {ip} > /tmp/x', 'block {cmd}', 'block {unknown}', 'block {text}']) expect(validateTpl({ ...EMPTY_TPL, cli: bad }, 'Action'), bad).not.toBeNull()
    expect(validateTpl({ ...EMPTY_TPL, method: 'PUT', path: '/api/v2/x/../y' }, 'Action')).not.toBeNull()
    expect(validateTpl({ ...EMPTY_TPL, method: 'PUT', path: '/api/v2/vip/{name}', body: '{"status":"disable"}' }, 'Action')).toBeNull()
    expect(validateTpl({ ...EMPTY_TPL, method: 'PUT', path: '/api/v2/vip/{text}', body: '{"status":"disable"}' }, 'Action')).toMatch(/only for message actions/) // {text} is for messages, not for a device
    expect(validateTpl({ ...EMPTY_TPL, cli: 'ip access-list extended X\n    {seq} deny ip host {ip} any' }, 'Action')).toBeNull() // values read at run time are allowed
    expect(validateTpl({ ...EMPTY_TPL, method: 'POST', path: '/x', headers: 'X-Test: a\nInjected' }, 'Action')).not.toBeNull()
    expect(validateTpl({ ...EMPTY_TPL, method: 'POST', path: '/x', headers: 'X-Token: {name}' }, 'Action')).toBeNull()
  })

  it('check before and read-back are typed and checked on the server (INV-14c, D-95)', async () => {
    const post = (o: Record<string, unknown>) => call('admin', 'POST', '/response/catalog', { ...CUSTOM, ...o })
    const get = { ...EMPTY_TPL, method: 'GET', path: '/api/v2/cmdb/webfilter/urlfilter/1/entries/{domain}' }
    // read-back text: only on the read-back, 200 characters, typed placeholders only
    expect((await post({ verify: { ...get, expect: '"{domain}"' } })).status).toBe(201)
    expect((await post({ verify: { ...get, expect: 'x'.repeat(201) } })).status).toBe(400)
    expect((await post({ verify: { ...get, expect: 'a; b' } })).status).toBe(400)
    expect((await post({ verify: { ...get, expect: '{nope}' } })).status).toBe(400)
    expect((await post({ run: { ...CUSTOM.run, expect: 'x' } })).status).toBe(400)
    expect((await post({ rollback: { ...CUSTOM.rollback, expect: 'x' } })).status).toBe(400)
    // check before: a GET and 1 to 5 texts of up to 80 characters; both or neither
    const pre = { precheck: get, precheck_refuse: ['Administrative Mode: trunk'] }
    expect((await post(pre)).status).toBe(201)
    expect((await post({ precheck: get, precheck_refuse: [] })).status).toBe(400)
    expect((await post({ precheck: EMPTY_TPL, precheck_refuse: ['x'] })).status).toBe(400)
    expect((await post({ ...pre, precheck_refuse: ['1', '2', '3', '4', '5', '6', '7', '8', '9'] })).status).toBe(400)
    expect((await post({ ...pre, precheck_refuse: ['x'.repeat(81)] })).status).toBe(400)
    expect((await post({ ...pre, precheck_refuse: ['a\nb'] })).status).toBe(400)
    expect((await post({ ...pre, precheck_refuse: [' '] })).status).toBe(400)
    expect((await post({ precheck: { ...get, method: 'POST' }, precheck_refuse: ['x'] })).status).toBe(400) // it must not change anything
    expect((await post({ precheck: { ...get, body: '{"a":1}' }, precheck_refuse: ['x'] })).status).toBe(400)
    expect((await post({ precheck: { ...get, expect: 'x' }, precheck_refuse: ['x'] })).status).toBe(400)
    // a template that names a port needs a check before it, with a refusal (a trunk or uplink must never be touched)
    connectorsStore.update((l) => [...l, SSH_W])
    const port = { connection_id: 'cn-sw', run: { ...EMPTY_TPL, cli: 'interface {interface}\nshutdown' }, rollback: { ...EMPTY_TPL, cli: 'interface {interface}\nno shutdown' } }
    const noCheck = await post(port)
    expect(noCheck.status).toBe(400)
    expect(JSON.stringify(noCheck.json)).toMatch(/check before/)
    expect((await post({ ...port, precheck: { ...EMPTY_TPL, cli: 'show interfaces {interface} switchport' }, precheck_refuse: [] })).status).toBe(400)
    const ok = await post({ ...port, precheck: { ...EMPTY_TPL, cli: 'show interfaces {interface} switchport' }, precheck_refuse: ['Administrative Mode: trunk'] })
    expect(ok.status).toBe(201)
    expect(ok.json).toMatchObject({ precheck: { cli: 'show interfaces {interface} switchport' }, precheck_refuse: ['Administrative Mode: trunk'] })
    // the check cannot use a placeholder the action does not have
    expect((await post({ ...pre, precheck: { ...get, path: '/x/{ip}' } })).status).toBe(400)
    // an MCP server cannot run a check before
    connectorsStore.update((l) => [...l, MCP])
    const mcp = { connection_id: 'cn-mcp', tool: 'block_address', rollback_tool: 'unblock_address', run: { ...EMPTY_TPL, body: '{"address":"{ip}"}' }, rollback: { ...EMPTY_TPL, body: '{"address":"{ip}"}' } }
    expect((await post({ ...mcp, precheck: { ...EMPTY_TPL, body: '{}' }, precheck_refuse: ['x'] })).status).toBe(400)
    expect((await post(mcp)).status).toBe(201)
    // editing the check is a template edit
    const id = (ok.json as { id: string }).id
    const edited = await call('admin', 'PUT', `/response/catalog/${id}`, { precheck_refuse: ['Administrative Mode: trunk', 'Operational Mode: trunk'] })
    expect(edited.json).toMatchObject({ precheck_refuse: ['Administrative Mode: trunk', 'Operational Mode: trunk'] })
    expect((await call('admin', 'PUT', `/response/catalog/${id}`, { precheck_refuse: [] })).status).toBe(400)
    // a built-in takes no template edit
    expect((await call('admin', 'PUT', '/response/catalog/cisco_port_shut', { precheck_refuse: [] })).status).toBe(200)
    expect((await call<Catalog>('admin', 'GET', '/response/catalog')).json.items.find((a) => a.id === 'cisco_port_shut')!.precheck_refuse).toHaveLength(6)
  })

  it('no template can set a credential, address or hop-by-hop header, in a custom action or a built-in one (D-94)', async () => {
    const bad = ['Authorization: Bearer {name}', 'authorization: x', 'Cookie: a=b', 'Host: evil.lan', 'Proxy-Authorization: x', 'Proxy-Foo: x', 'Connection: close', 'Keep-Alive: 5', 'TE: trailers', 'Transfer-Encoding: chunked', 'Upgrade: x', 'Proxy-Connection: x', 'Forwarded: for=1.2.3.4', 'X-Forwarded-For: 1.2.3.4', 'X-Forwarded-Host: x', 'X-Test: a\nAUTHORIZATION: b']
    for (const h of bad) {
      expect(validateTpl({ ...EMPTY_TPL, method: 'POST', path: '/x', headers: h }, 'Action'), h).toMatch(/set by the connection/)
      expect((await call('admin', 'POST', '/response/catalog', { ...CUSTOM, run: { ...CUSTOM.run, headers: h } })).status, h).toBe(400)
      expect((await call('admin', 'POST', '/response/catalog', { ...CUSTOM, verify: { ...EMPTY_TPL, method: 'GET', path: '/x/{domain}', headers: h } })).status, `verify ${h}`).toBe(400)
      expect((await call('admin', 'POST', '/response/catalog', { ...CUSTOM, precheck: { ...EMPTY_TPL, method: 'GET', path: '/x/{domain}', headers: h }, precheck_refuse: ['x'] })).status, `precheck ${h}`).toBe(400)
    }
    expect(validateTpl({ ...EMPTY_TPL, method: 'POST', path: '/x', headers: 'Content-Type: application/json\nX-Request-Id: {name}' }, 'Action')).toBeNull()
    // the shipped library obeys the same rule
    for (const a of catalogStore.get()) for (const t of [a.run, a.rollback, a.verify, a.precheck]) expect(t.headers, a.id).not.toMatch(/authorization|cookie|^host|proxy-|forwarded/i)
  })

  it('built-in actions that need a value read from the device are not available yet; the others that name a port have a check before (action-templates 12.1)', async () => {
    withSwitch()
    for (const id of ['cisco_acl_deny', 'aoscx_acl_deny', 'cisco_port_vlan_quarantine', 'aoscx_vlan_quarantine', 'mt_addrlist_add', 'adguard_block']) {
      catalogStore.update((l) => l.map((c) => (c.id === id ? { ...c, connection_id: c.run.cli ? 'cn-sw' : 'cn-fgt' } : c)))
    }
    const items = (await call<Catalog>('admin', 'GET', '/response/catalog')).json.items
    for (const id of ['cisco_acl_deny', 'aoscx_acl_deny', 'cisco_port_vlan_quarantine', 'aoscx_vlan_quarantine', 'mt_addrlist_add', 'adguard_block']) {
      const a = items.find((x) => x.id === id)!
      expect(a.available, id).toBe(false)
      expect(a.unavailable_reason, id).toMatch(/Not available yet: .*\{(seq|previous_vlan|found_id|rules_before|timeout)\}/)
    }
    // the port actions are available once the switch is chosen: their check before and refusal texts are in the library
    for (const id of ['cisco_port_shut', 'aoscx_port_shut']) {
      catalogStore.update((l) => l.map((c) => (c.id === id ? { ...c, connection_id: 'cn-sw' } : c)))
    }
    const now = (await call<Catalog>('admin', 'GET', '/response/catalog')).json.items
    for (const id of ['cisco_port_shut', 'aoscx_port_shut']) expect(now.find((x) => x.id === id)!.available, id).toBe(true)
    // the time to live is worked out without the device
    expect(now.find((x) => x.id === 'fgt_ban_ip')!.unavailable_reason ?? '').not.toMatch(/Not available yet/)
  })

  it('the proposals route is documented as preview only (FORBID-5, D-97)', async () => {
    const { endpoints } = await import('./contract')
    const r = endpoints.find((x) => x.path === '/response/ai/proposals')!
    expect(r.summary).toMatch(/^Preview build only/)
  })

  it('the mock follows the module: ports named through another placeholder, writing read-backs and header-only steps are refused (review of 13b-2)', async () => {
    connectorsStore.update((l) => [...l, SSH_W])
    const post = (o: Record<string, unknown>) => call('admin', 'POST', '/response/catalog', { ...CUSTOM, ...o })
    const ssh = { connection_id: 'cn-sw', run: { ...EMPTY_TPL, cli: 'interface Port-channel{id}\nshutdown' }, rollback: { ...EMPTY_TPL, cli: 'interface Port-channel{id}\nno shutdown' } }
    const dodge = await post(ssh)
    expect(dodge.status).toBe(400)
    expect(JSON.stringify(dodge.json)).toMatch(/can name a port/)
    expect((await post({ ...ssh, precheck: { ...EMPTY_TPL, cli: 'show interfaces Port-channel{id}' }, precheck_refuse: ['Mode: trunk'] })).status).toBe(201)
    // an SSH check cannot write
    const port = { connection_id: 'cn-sw', run: { ...EMPTY_TPL, cli: 'interface {interface}\nshutdown' }, rollback: { ...EMPTY_TPL, cli: 'interface {interface}\nno shutdown' }, precheck_refuse: ['Mode: trunk'] }
    expect((await post({ ...port, precheck: { ...EMPTY_TPL, cli: 'show interfaces {interface}\nshutdown' } })).status).toBe(400)
    expect((await post({ ...port, precheck: { ...EMPTY_TPL, cli: 'configure terminal\nshow interfaces {interface}' } })).status).toBe(400)
    expect((await post({ ...port, run: { ...EMPTY_TPL, cli: 'interface {interface}\nshutdown\nreload' }, precheck: { ...EMPTY_TPL, cli: 'show interfaces {interface}' } })).status).toBe(400)
    expect((await post({ ...port, precheck: { ...EMPTY_TPL, cli: 'show interfaces {interface}' }, precheck_expect: 'Administrative Mode: static access' })).json).toMatchObject({ precheck_expect: 'Administrative Mode: static access' })
    // a read-back only reads; a step with only headers is not empty
    const get = { ...EMPTY_TPL, method: 'GET', path: '/d/{domain}' }
    for (const method of ['DELETE', 'POST', 'PUT', 'PATCH']) expect((await post({ verify: { ...get, method, expect: 'x' } })).status, method).toBe(400)
    expect((await post({ verify: { ...EMPTY_TPL, headers: 'Authorization: Bearer abc' } })).status).toBe(400)
    expect((await post({ precheck: { ...EMPTY_TPL, headers: 'X-Api-Key: abc' }, precheck_refuse: ['x'] })).status).toBe(400)
    expect((await post({ precheck: { ...get, headers: 'X-HTTP-Method-Override: DELETE' }, precheck_refuse: ['x'] })).status).toBe(400)
    expect((await post({ precheck: get, precheck_refuse: [], precheck_expect: 'x'.repeat(81) })).status).toBe(400)
    // the required text alone is a check
    expect((await post({ precheck: get, precheck_refuse: [], precheck_expect: 'ok' })).status).toBe(201)
  })

  it('GET /response/catalog hides the header values of every step from non-admins, the check before included (D-88 (26))', async () => {
    const secret = { ...EMPTY_TPL, method: 'GET', path: '/d/{domain}', headers: 'X-Api-Key: s3cretvalue' }
    const made = await call('admin', 'POST', '/response/catalog', { ...CUSTOM, run: { ...CUSTOM.run, headers: 'X-Api-Key: s3cretrun' }, verify: secret, precheck: secret, precheck_refuse: ['x'] })
    expect(made.status).toBe(201)
    const headersOf = (items: Catalog['items']) => items.flatMap((a) => [a.run, a.rollback, a.verify, a.precheck].map((t) => t.headers)).join('\n')
    for (const role of ['viewer', 'operator'] as const) {
      const seen = headersOf((await call<Catalog>(role, 'GET', '/response/catalog')).json.items)
      expect(seen, role).not.toContain('s3cret')
      expect(seen, role).toContain('X-Api-Key: (hidden)')
    }
    expect(headersOf((await call<Catalog>('admin', 'GET', '/response/catalog')).json.items)).toContain('s3cretvalue')
  })

  it('the approval screen shows the check before and the read-back, with the exact call and when it refuses', () => {
    const c = { ...catalogStore.get().find((x) => x.id === 'cisco_port_shut')!, connection_id: null }
    const ch = buildChange(c, { interface: 'Gi1/0/12' }, undefined, 'r')
    expect(ch.precheck).toBe('terminal length 0\nshow interfaces Gi1/0/12 switchport\nshow interfaces Gi1/0/12')
    expect(ch.precheck_rules).toMatch(/administratively down/)
    expect(ch.precheck_rules).toMatch(/unless its output contains "Administrative Mode: static access"/)
    expect(ch.precheck_rules).toMatch(/prints nothing/)
    expect(ch.verify).toBe('terminal length 0\nshow interfaces Gi1/0/12 status')
    expect(ch.verify_rule).toMatch(/"disabled".*after the undo it must not/)
    const api = { ...catalogStore.get().find((x) => x.id === 'fgt_policy_disable')! }
    const conn = { kind: 'http', target: 'https://fw.lan' } as never
    const ac = buildChange(api, { id: '7' }, conn, 'r')
    expect(ac.precheck).toBe('GET https://fw.lan/api/v2/cmdb/firewall/policy/7')
    expect(ac.precheck_rules).toMatch(/"action":"deny"/)
    expect(ac.verify).toBe('GET https://fw.lan/api/v2/cmdb/firewall/policy/7')
    expect(buildChange(catalogStore.get().find((x) => x.id === 'blocklist_add')!, { ip: '1.2.3.4' }, undefined, 'r').precheck).toBe('')
  })

  it('the approver sees the headers with their typed values, and {expiry_s} as the number that will be sent (13b-6 review M3)', () => {
    const conn = { kind: 'http', target: 'https://fw.lan' } as never
    const ban = catalogStore.get().find((x) => x.id === 'fgt_ban_ip')!
    const withHeaders = { ...ban, run: { ...ban.run, headers: 'X-Block-Scope: {ip}\nX-Commit: now' } }
    const ch = buildChange(withHeaders, { ip: '198.51.100.7' }, conn, 'r', 30)
    expect(ch.rest?.headers).toEqual({ 'X-Block-Scope': '198.51.100.7', 'X-Commit': 'now' })
    expect(ch.rest?.body).toContain('"expiry":1800')
    expect(ch.rest?.body).not.toContain('<expiry_s>')
    expect(buildChange(ban, { ip: '198.51.100.7' }, conn, 'r', 30).rest?.headers).toEqual({})
  })

  it('an item whose outcome is not known can be undone, and the card says why (13b-6 review M2)', async () => {
    await turnOn()
    const a = await request()
    expect((await call('operator', 'POST', `/response/actions/${a.json.id}/approve`)).status).toBe(200)
    actionsDb.update((l) => l.map((x) => (x.id === a.json.id ? { ...x, status: 'failed' as const, items: x.items.map((i) => ({ ...i, status: 'failed' as const, state_unknown: true, remove_at: null, result: 'State unknown: check the device.' })) } : x)))
    const card = (await call<{ items: ActionRequest[] }>('operator', 'GET', '/response/actions')).json.items.find((x) => x.id === a.json.id)!
    renderUi(<RequestCard a={card} />, 'operator')
    expect(screen.getByRole('note')).toHaveTextContent('The result of this change is unknown. Undo it to be sure it is not in force.')
    await waitFor(() => expect(screen.getByRole('button', { name: 'Roll back' })).toBeEnabled())
    const rb = await call<ActionRequest>('operator', 'POST', `/response/actions/${a.json.id}/rollback`)
    expect(rb.status).toBe(200)
    expect(rb.json.items[0]).toMatchObject({ status: 'rolled_back', state_unknown: false })
    expect(rb.json.items[0]!.result).toContain('earlier outcome was not known')
    // A plain failed item (nothing was changed) has nothing to undo.
    const b = await request()
    expect((await call('operator', 'POST', `/response/actions/${b.json.id}/approve`)).status).toBe(200)
    actionsDb.update((l) => l.map((x) => (x.id === b.json.id ? { ...x, status: 'failed' as const, items: x.items.map((i) => ({ ...i, status: 'failed' as const, remove_at: null })) } : x)))
    expect((await call('operator', 'POST', `/response/actions/${b.json.id}/rollback`)).code).toBe('not_executed')
  })

  it('an executed item shows the undo time the box set (remove_at), and "not undone automatically" when there is none (D-356)', async () => {
    await turnOn()
    const a = await request()
    actionsDb.update((l) => l.map((x) => (x.id === a.json.id ? { ...x, items: x.items.map((i) => ({ ...i, ttl_min: 60 })) } : x))) // an undo time of one hour
    const ok = await call<ActionRequest>('operator', 'POST', `/response/actions/${a.json.id}/approve`)
    expect(ok.status).toBe(200)
    expect(ok.json.items[0]).toMatchObject({ status: 'executed', reversible: true, ttl_min: 60 })
    expect(ok.json.items[0]!.remove_at).not.toBeNull() // the mock sets remove_at like the box: executed, can be undone, has a ttl
    const view = async () => (await call<{ items: ActionRequest[] }>('operator', 'GET', '/response/actions')).json.items.find((x) => x.id === a.json.id)!
    const first = renderUi(<RequestCard a={await view()} />, 'operator')
    expect(screen.getAllByText(/Undone automatically at/).length).toBeGreaterThan(0)
    expect(screen.queryByText(/Undone after/)).toBeNull()
    first.unmount()
    // A change that was already on the device before the step: executed, no undo time (the box does not set remove_at).
    actionsDb.update((l) => l.map((x) => (x.id === a.json.id ? { ...x, items: x.items.map((i) => ({ ...i, remove_at: null })) } : x)))
    renderUi(<RequestCard a={await view()} />, 'operator')
    expect(screen.getAllByText(/Not undone automatically \(undo it by hand\)/).length).toBeGreaterThan(0)
    expect(screen.queryByText(/Undone automatically at|Undone after/)).toBeNull()
  })

  it('custom actions: add, edit, delete; unsafe templates are refused; built-ins cannot be deleted; a rule in use blocks delete', async () => {
    expect((await call('admin', 'POST', '/response/catalog', { ...CUSTOM, run: { ...CUSTOM.run, body: '{"url":"{domain}; reboot"}' } })).status).toBe(400)
    expect((await call('admin', 'POST', '/response/catalog', { ...CUSTOM, run: { ...CUSTOM.run, body: '{"url":"{host}"}' } })).status).toBe(400)
    expect((await call('admin', 'POST', '/response/catalog', { ...CUSTOM, rollback: { ...CUSTOM.rollback, path: '/x/{ip}' } })).status).toBe(400) // rollback needs a value the action does not have
    expect((await call('operator', 'POST', '/response/catalog', CUSTOM)).status).toBe(403)
    const made = await call<{ id: string; params: string[]; builtin: boolean; pack: string }>('admin', 'POST', '/response/catalog', CUSTOM)
    expect(made.status).toBe(201)
    expect(made.json.params).toEqual(['domain'])
    expect((await call('admin', 'PUT', `/response/catalog/${made.json.id}`, { risk: 'high' })).status).toBe(200)
    expect((await call('admin', 'DELETE', '/response/catalog/fgt_vip_disable')).code).toBe('builtin')
    expect((await addRule({ actions: [{ action_id: made.json.id, params: { domain: '{{trigger.dest_domain}}' }, ttl_min: 60 }], conditions: [] })).status).toBe(201)
    expect((await call('admin', 'DELETE', `/response/catalog/${made.json.id}`)).code).toBe('in_use')
    expect((await addRule({ trigger: 'honeypot', conditions: [], actions: [{ action_id: made.json.id, params: { domain: '{{trigger.source_device}}' }, ttl_min: 60 }] })).status).toBe(400) // a device name is not a domain
  })

  it('the server follows the connection kind: fields of another kind are refused, read-only connections cannot be chosen', async () => {
    connectorsStore.update((l) => [...l, SSH_W, MCP])
    const post = (o: Record<string, unknown>) => call('admin', 'POST', '/response/catalog', { ...CUSTOM, ...o })
    // read-only connection (File server, only a read tool)
    const ro = await post({ connection_id: 'cn-ssh', run: { ...EMPTY_TPL, cli: 'block {ip}' }, rollback: { ...EMPTY_TPL, cli: 'unblock {ip}' } })
    expect(ro.status).toBe(409)
    expect(ro.code).toBe('read_only')
    expect((await call('admin', 'PUT', '/response/catalog/cisco_acl_deny', { connection_id: 'cn-ssh' })).code).toBe('read_only')
    // SSH: command only
    expect((await post({ connection_id: 'cn-sw' })).status).toBe(400) // API fields on an SSH connection
    expect((await post({ connection_id: 'cn-sw', run: { ...EMPTY_TPL, cli: 'block {ip}' }, rollback: { ...EMPTY_TPL, cli: 'unblock {ip}' } })).status).toBe(201)
    // API: no command
    expect((await post({ run: { ...CUSTOM.run, cli: 'block {domain}' } })).status).toBe(400)
    // MCP: a write tool of that server and arguments
    const mcp = { connection_id: 'cn-mcp', run: { ...EMPTY_TPL, body: '{"address":"{ip}"}' }, rollback: { ...EMPTY_TPL, body: '{"address":"{ip}"}' } }
    expect((await post({ ...mcp, tool: null, rollback_tool: 'unblock_address' })).status).toBe(400)
    expect((await post({ ...mcp, tool: 'list_rules', rollback_tool: 'unblock_address' })).status).toBe(400) // a read tool
    expect((await post({ ...mcp, tool: 'block_address', rollback_tool: 'unblock_address', run: { ...EMPTY_TPL, method: 'POST', path: '/x', body: '{"address":"{ip}"}' } })).status).toBe(400)
    const ok = await post({ ...mcp, tool: 'block_address', rollback_tool: 'unblock_address' })
    expect(ok.status).toBe(201)
    expect((ok.json as unknown as { connection_kind: string }).connection_kind).toBe('mcp-http')
    // a built-in action meant for an API cannot be pointed at an SSH connection
    expect((await call('admin', 'PUT', '/response/catalog/pihole_block', { connection_id: 'cn-sw' })).code).toBe('wrong_kind')
  })
})

describe('response: block list (pull)', () => {
  it('serves a plain-text list on a tokenised address, and a regenerated token kills the old one', async () => {
    const b = (await call<Blocklist>('admin', 'GET', '/response/blocklist')).json
    expect(b.url).toMatch(/^https:\/\/192\.168\.10\.250:8443\/api\/v1\/response\/blocklist\/[a-f0-9]{32}\.txt$/)
    expect(b.entries.map((e) => e.value)).toEqual(expect.arrayContaining(['185.220.101.47', '45.9.148.20', '198.51.100.23']))
    const path = new URL(b.url).pathname
    const txt = await fetch(`${location.origin}${path}`)
    expect(txt.headers.get('content-type')).toContain('text/plain')
    expect(await txt.text()).toMatch(/\n185\.220\.101\.47\n/)
    expect((await fetch(`${location.origin}/api/v1/response/blocklist/${'0'.repeat(32)}.txt`)).status).toBe(404)
    expect((await call('operator', 'POST', '/response/blocklist/token')).status).toBe(403)
    await call('admin', 'POST', '/response/blocklist/token')
    expect((await fetch(`${location.origin}${path}`)).status).toBe(404)
  })

  it('a block on an address the list never publishes is refused when it is planned, with not_publishable and a refused line (D-469)', async () => {
    iocHits(['192.168.1.5'])
    const priv = { action_id: 'blocklist_add', params: { ip: '{{trigger.dest_ip}}' }, ttl_min: 60 }
    const tell = { action_id: 'msg_send', params: { text: 'Bad connection from {{trigger.device}}' }, ttl_min: null }
    // a fixed private address is refused when the rule is saved (or simulated); a trigger field only when it runs
    const fixed = { ...RULE, actions: [{ ...priv, params: { ip: '192.168.1.5' } }] }
    expect([(await addRule(fixed)).code, (await call('operator', 'POST', '/response/rules/simulate', { rule: fixed })).code]).toEqual(['not_publishable', 'not_publishable'])
    const sim = await call<Simulation>('operator', 'POST', '/response/rules/simulate', { rule: { ...RULE, actions: [priv] } })
    expect(sim.status).toBe(200)
    expect(sim.json.steps[0]!.error).toMatch(/^192\.168\.1\.5 is not a public address .*Nothing was changed\.$/)
    // a live rule "block + tell": the block is dropped with its refused line, the message is still asked for
    const rule = await liveRule({ conditions: [{ field: 'dest_kind', op: 'eq', value: 'ip', n: null, window_min: null }], actions: [priv, tell] })
    await onlyRule(rule.id)
    const sum = await run()
    expect(sum.refused).toBeGreaterThan(0)
    const mine = (await list<ActionRequest>('operator', '/response/actions')).filter((a) => a.rule_id === rule.id)
    expect(mine.length).toBeGreaterThan(0)
    expect(mine.flatMap((a) => a.items.map((i) => i.action_id))).toEqual(mine.map(() => 'msg_send'))
    expect((await logList()).some((e) => e.kind === 'refused' && /^not_publishable: .*192\.168\.1\.5 is not a public address/.test(e.detail))).toBe(true)
    // an AI proposal, for the ranges the box's type check lets through to this gate; a public one still passes it
    await saveSettings({ ai: { triggers: ['ioc_connection', 'finding'], budget_hour: 20, budget_day: 100 } })
    for (const ip of ['10.0.0.5', '172.16.4.4', '100.64.0.1', '192.0.0.8', '198.18.0.1']) {
      const r = await propose({ params: { ip } })
      expect([r.status, r.code], ip).toEqual([409, 'not_publishable'])
    }
    expect((await propose({ params: { ip: '100.128.0.1' } })).code).not.toBe('not_publishable')
    expect((await call<Blocklist>('admin', 'GET', '/response/blocklist')).json.entries.map((e) => e.value)).not.toContain('192.168.1.5')
  })
})

describe('response: tamper-evident log (D-48)', () => {
  it('every step is chained, the chain verifies, and editing or deleting a line breaks it', async () => {
    await turnOn(); mapChat()
    const r = await request()
    await call('operator', 'POST', `/response/actions/${r.json.id}/reject`)
    await request()
    const log = await logList()
    expect(log.map((e) => e.kind)).toEqual(expect.arrayContaining(['request', 'rejected', 'settings']))
    expect(log[1]!.prev_hash).toBe(log[0]!.hash)
    expect(Object.keys(log[0]!).sort()).toEqual(['actor', 'detail', 'hash', 'id', 'kind', 'prev_hash', 'ts'])
    expect(await verifyChain(log)).toEqual({ ok: true, broken_at: null })
    expect(await verifyChain(log.map((e, i) => (i === 3 ? { ...e, detail: 'edited' } : e)))).toEqual({ ok: false, broken_at: 3 })
    expect((await verifyChain([...log.slice(0, 2), ...log.slice(3)])).ok).toBe(false)
    expect((await call('viewer', 'GET', '/response/log')).status).toBe(403)
  })
})

function renderUi(ui: React.ReactNode, role: Role = 'admin') {
  sessionStore.set({ userId: USER[role] })
  const qc = makeQueryClient()
  return render(<QueryClientProvider client={qc}><MemoryRouter>{ui}</MemoryRouter><Toaster /></QueryClientProvider>)
}

describe('response: screens', () => {
  it('the enable dialog shows the risk statement and needs two-step sign-in plus the exact phrase', async () => {
    renderUi(<ResponseSettings />)
    const sw = await screen.findByRole('switch', { name: /Let the AI carry out actions I approve/ })
    await waitFor(() => expect(sw).toBeEnabled())
    await userEvent.click(sw)
    const dialog = await screen.findByRole('dialog')
    expect(dialog).toHaveTextContent('This is a high-risk feature. Your AI can be wrong and can change your network devices. You carry the risk yourself. Vedette is provided as is under the Apache-2.0 license; its author, Kien Nguyen, is not responsible for actions your AI takes.')
    expect(screen.getByRole('link', { name: 'Turn it on in My account' })).toHaveAttribute('href', '/settings/account?tab=sign-in')
    await userEvent.type(screen.getByLabelText(`Type ${PHRASE} to confirm`), PHRASE)
    expect(screen.getByRole('button', { name: 'Turn on AI execution' })).toBeDisabled() // two-step sign-in is off
  })

  it('with two-step sign-in on, only the exact phrase enables it, then Emergency stop shows', async () => {
    withTwofa()
    renderUi(<ResponseSettings />)
    const sw = await screen.findByRole('switch', { name: /Let the AI carry out actions I approve/ })
    await waitFor(() => expect(sw).toBeEnabled())
    await userEvent.click(sw)
    const input = await screen.findByLabelText(`Type ${PHRASE} to confirm`)
    const confirm = screen.getByRole('button', { name: 'Turn on AI execution' })
    await waitFor(() => expect(screen.getByText('On')).toBeInTheDocument())
    await userEvent.type(input, 'i accept the risk')
    expect(confirm).toBeDisabled()
    await userEvent.clear(input)
    await userEvent.type(input, PHRASE)
    expect(confirm).toBeEnabled()
    await userEvent.click(confirm)
    expect(await screen.findByRole('button', { name: 'Emergency stop' })).toBeInTheDocument()
    expect((await call<SettingsView>('admin', 'GET', '/response/settings')).json.execution).toBe(true)
  })

  it('settings show the safety envelope, AI gates, the never-touch list and the catalog by pack', async () => {
    renderUi(<ResponseSettings />)
    expect(await screen.findByLabelText('Circuit breaker: actions per hour')).toHaveValue(20)
    expect(screen.getByLabelText('Approval expiry (minutes)')).toHaveValue(15)
    expect(screen.getByText('AI requests: gates')).toBeInTheDocument()
    expect(await screen.findByText('Never-touch list')).toBeInTheDocument()
    expect(await screen.findByRole('region', { name: 'FortiGate' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'MikroTik' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Cisco IOS / IOS-XE' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Aruba AOS-CX' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: /DNS filters/ })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'This box' })).toBeInTheDocument() // built-in groups are translated, library packs show the name the library gives them
  })

  it('Response opens on the inbox; the tabs are Requests, Rules, Actions, Log, Settings; Rules shows rules and the template gallery (D-513)', async () => {
    renderApp('/response')
    expect(await screen.findByRole('heading', { level: 1, name: 'Response' })).toBeInTheDocument()
    expect(screen.getAllByRole('tab').map((x) => x.textContent?.replace(/\d+.*$/, '').trim())).toEqual(['Requests', 'Rules', 'Actions', 'Log', 'Settings'])
    expect(screen.getByRole('tab', { name: /^Requests/ })).toHaveAttribute('aria-selected', 'true')
    expect(await screen.findByRole('heading', { name: 'Inbox' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'Rules' }))
    expect(await screen.findByText('Block destinations of known-bad connections')).toBeInTheDocument()
    expect(await screen.findByText('Template gallery')).toBeInTheDocument()
    expect(await screen.findByText('Trap touched: block the source on FortiGate for 24 hours')).toBeInTheDocument()
    expect(screen.getAllByText('Dry run').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Pre-approved, no person').length).toBeGreaterThan(0)
  })

  it('the high-risk banner counts the waiting requests in words, never a raw {{count}} (walk-1 W1-17)', async () => {
    await turnOn()
    const pending = (await list<ActionRequest>('admin', '/response/actions')).filter((a) => a.status === 'pending').length
    renderApp('/response')
    const banner = (await screen.findByText('High-risk mode is on')).parentElement!
    expect(banner.textContent).not.toContain('{{')
    expect(banner).toHaveTextContent(pending === 1 ? '1 request is waiting.' : `${pending} requests are waiting.`)
  })

  it('Requests tab: pending bundled request with pick boxes, AI request with evidence, and the AI plan with its off-state message', async () => {
    renderApp('/response#requests')
    expect(await screen.findByText('Block 91.92.240.12 and tell the team')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: /Include: Add 91.92.240.12 to the block list/ })).toBeChecked()
    expect(screen.getByRole('button', { name: 'Approve all' })).toBeInTheDocument()
    expect((await screen.findAllByText(/PC-FIN-02 connected to 45.148.10.95/)).length).toBeGreaterThan(0)
    expect(document.querySelector('[data-ai="true"]')).toBeTruthy()
    expect(await screen.findByText(/NAS-PHOTOS is reachable from the Internet through FortiGate virtual IP NAS-PHOTO-443/)).toBeInTheDocument()
    expect(screen.getAllByText('Execution is off. Turn it on in Settings, AI response (high risk).').length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: 'Request approval' })).toBeDisabled()
    await userEvent.click(screen.getByRole('button', { name: /History/ }))
    expect((await screen.findAllByText('Add 203.0.113.77 to the block list')).length).toBeGreaterThan(0)
  })

  it('page frame (D-464): old #hash links open the tab through ?tab=, Requests carries the pending count, a tab the role may not see opens the inbox', async () => {
    // ResponsePage on its own router, so the test can read the address after the redirect.
    const at = (url: string) => {
      sessionStore.set({ userId: 'u-admin' })
      const router = createMemoryRouter([{ path: '/response', element: <ResponsePage /> }], { initialEntries: [url] })
      const view = render(<QueryClientProvider client={makeQueryClient()}><RouterProvider router={router} /></QueryClientProvider>)
      const where = () => router.state.location.pathname + router.state.location.search + router.state.location.hash
      return { view, where }
    }
    const log = at('/response?incident=al-4#log')
    expect(await screen.findByRole('tab', { name: 'Log' })).toHaveAttribute('aria-selected', 'true')
    expect(log.where()).toBe('/response?incident=al-4&tab=log')
    expect(screen.getByRole('tab', { name: /^Requests \d+ waiting for a decision$/ })).toBeInTheDocument()
    log.view.unmount()
    const ai = at('/response#ai')
    expect(await screen.findByRole('tab', { name: /^Requests/ })).toHaveAttribute('aria-selected', 'true')
    expect(ai.where()).toBe('/response?tab=requests')
    ai.view.unmount()
    // any other hash (the skip link's #main) is not an old tab name: no redirect; a tab that moved (D-513) opens where it went
    const skip = at('/response?tab=metrics#main')
    expect(await screen.findByRole('tab', { name: 'Log' })).toHaveAttribute('aria-selected', 'true')
    expect(skip.where()).toBe('/response?tab=log#main')
    skip.view.unmount()
    const bl = at('/response#blocklist')
    expect(await screen.findByRole('tab', { name: 'Actions' })).toHaveAttribute('aria-selected', 'true')
    expect(bl.where()).toBe('/response?tab=actions')
    bl.view.unmount()
    renderApp('/response?tab=actions', { role: 'viewer' })
    expect(await screen.findByRole('tab', { name: /^Requests/ })).toHaveAttribute('aria-selected', 'true')
    expect(screen.queryByRole('tab', { name: 'Actions' })).toBeNull()
    expect(screen.queryByRole('tab', { name: 'Settings' })).toBeNull()
  })

  it('Metrics tab: acceptance, AI budget and the rejected requests with their reasons', async () => {
    renderApp('/response#metrics')
    expect((await screen.findAllByText('Acceptance')).length).toBeGreaterThan(0)
    expect(await screen.findByText('This hour')).toBeInTheDocument()
    expect((await screen.findAllByText(/Our own vulnerability scanner/)).length).toBeGreaterThan(0)
    expect(screen.getByText('Try an AI request (preview build)')).toBeInTheDocument()
  })

  it('Block list tab with setup steps, and the Log tab with "Chain verified"', async () => {
    renderApp('/response#blocklist')
    expect((await screen.findAllByText(/:8443\/api\/v1\/response\/blocklist\//)).length).toBeGreaterThan(0)
    expect(screen.getByText('FortiGate: External Block List (threat feed)')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Regenerate token' })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'Log' }))
    expect(await screen.findByText('Chain verified')).toBeInTheDocument()
  })

  it('an empty Block list says what fills it, that it holds public addresses only, and links to the template that is off (D-469)', async () => {
    actionsDb.set([])
    renderApp('/response#blocklist')
    expect(await screen.findByText('Nothing is blocked right now.')).toBeInTheDocument()
    expect(screen.getByText(/^Only approved "block" actions add addresses here/)).toBeInTheDocument()
    expect(screen.getByText(/^Only public addresses are published\. A block on a private or reserved address/)).toBeInTheDocument()
    expect(screen.getByText(/"Known-bad connection: add the destination to the block list" ships switched off/)).toBeInTheDocument()
    expect((await screen.findAllByText(/:8443\/api\/v1\/response\/blocklist\//)).length).toBeGreaterThan(0) // the address row stays, so the firewall can be set up first
    await userEvent.click(screen.getByRole('link', { name: 'Turn it on: Rules, Template gallery' }))
    expect(await screen.findByRole('heading', { name: 'Template gallery' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Rules', selected: true })).toBeInTheDocument()
  })

  it('finding page shows the response plan through the slot', async () => {
    renderApp('/findings/f-1')
    expect(await screen.findByRole('heading', { name: 'Response plan' })).toBeInTheDocument()
    expect(await screen.findByText(/Turn off virtual IP NAS-PHOTO-443 on FW-HQ/, { selector: 'p' })).toBeInTheDocument()
  })

  it('response off: the finding page does not call the module, also while the module list loads (W10-1, no 404 in the console)', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'response' ? { ...m, enabled: false } : m)))
    const asked: string[] = []
    let modules = false
    server.events.on('request:start', ({ request }) => {
      const path = new URL(request.url).pathname
      if (path.endsWith('/modules')) modules = true
      if (path.includes('/response/')) asked.push(path)
    })
    const { container } = render(<QueryClientProvider client={makeQueryClient()}><MemoryRouter><FindingPanel findingId="f-1" /></MemoryRouter></QueryClientProvider>)
    await waitFor(() => expect(modules).toBe(true)) // the first render, before the module list arrives, is the one that used to ask
    await waitFor(() => expect(container).toBeEmptyDOMElement())
    expect(asked).toEqual([])
    server.events.removeAllListeners()
  })

  it('a requested proposal on the finding page links to the Requests tab (D-464: ?tab=, not #requests)', async () => {
    await turnOn()
    expect((await request()).status).toBe(201)
    renderApp('/findings/f-1')
    expect(await screen.findByRole('link', { name: 'Requested, see Action requests' })).toHaveAttribute('href', '/response?tab=requests')
  })

  it('the public approval page shows the change on load and decides only on the button', async () => {
    await turnOn()
    setChannels([{ type: 'email', configured: true, enabled: true, approvals: true, approvers: [{ user_id: 'u-op', address: 'it@acme.example' }, { user_id: 'u-admin', address: 'admin@acme.example' }] }])
    await saveSettings({ approval_channels: ['email'] })
    const r = await request()
    const token = (await getAction(r.json.id)).email_links[0]!.url.split('/').pop()!
    sessionStore.set({ userId: null })
    renderApp(`/approve/${token}`, { role: null })
    expect(await screen.findByText(/Turn off virtual IP NAS-PHOTO-443/, { selector: 'p' })).toBeInTheDocument()
    expect((await getAction(r.json.id)).status).toBe('pending')
    await userEvent.click(screen.getByRole('button', { name: 'Approve' }))
    expect(await screen.findByText(/Approved\. The action is being carried out/)).toBeInTheDocument()
  })

  it('the rule editor has WHEN, IF and THEN, simulates, and warns about pre-approved', async () => {
    renderUi(<RuleDialog rule={null} onClose={() => undefined} />)
    expect(await screen.findByRole('heading', { name: 'WHEN' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'IF' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'THEN' })).toBeInTheDocument()
    expect(screen.getByText(/Trigger data is attacker-controlled/)).toBeInTheDocument()
    const pre = await screen.findByRole('switch', { name: /Pre-approved \(no person asks\)/ })
    await waitFor(() => expect(pre).toBeEnabled()) // the default action is low risk and reversible
    await userEvent.click(pre)
    expect(await screen.findByText(/will carry out these actions without asking anyone/)).toBeInTheDocument()
    await userEvent.type(screen.getByLabelText('Name'), 'Editor test')
    await userEvent.click(screen.getByRole('button', { name: 'Simulate with the latest event' }))
    const sim = await screen.findByRole('region', { name: 'Simulation' })
    expect(within(sim).getByText('Nothing was executed')).toBeInTheDocument()
  })
})

// ---- Form matrix (docs/QA.md §2): the custom action form per connection kind ----
describe('response: custom action form follows the connection kind', () => {
  const extra: Connector[] = [
    SSH_W,
    { id: 'cn-web', name: 'Ticket API (HTTP)', kind: 'http', target: 'https://tickets.lan', asset_id: null, auth: { type: 'token', header: null, last4: 'a1Bc', key_fingerprint: null }, username: null, pin: null, allow: [], tools: [{ name: 'post_ticket', access: 'write', description: '', enabled: true }], enabled: true, status: 'ok', last_test: null },
    { id: 'cn-mt', name: 'MikroTik API', kind: 'http', target: 'https://192.168.10.2', asset_id: null, auth: { type: 'token', header: null, last4: 'm1Kr', key_fingerprint: null }, username: null, pin: null, allow: [], tools: [{ name: 'add_address', access: 'write', description: '', enabled: true }], enabled: true, status: 'ok', last_test: null },
    { id: 'cn-nc', name: 'Switch RESTCONF', kind: 'netconf-restconf', target: 'https://192.168.10.3', asset_id: null, auth: { type: 'basic', header: null, last4: 'n3Tc', key_fingerprint: null }, username: null, pin: null, allow: [], tools: [{ name: 'apply_config', access: 'write', description: '', enabled: true }], enabled: true, status: 'ok', last_test: null },
    { id: 'cn-awx', name: 'Automation platform', kind: 'automation', target: 'https://automation.lan', asset_id: null, auth: { type: 'token', header: null, last4: 'a7Wx', key_fingerprint: null }, username: null, pin: null, allow: [], tools: [{ name: 'launch_job', access: 'write', description: '', enabled: true }], enabled: true, status: 'ok', last_test: null },
    { id: 'cn-mcp', name: 'Firewall MCP server', kind: 'mcp-http', target: 'https://mcp.lan/mcp', asset_id: null, auth: { type: 'token', header: null, last4: 'z9Zz', key_fingerprint: null }, username: null, pin: null, allow: [], enabled: true, status: 'ok', last_test: null,
      tools: [{ name: 'list_rules', access: 'read', description: '', enabled: true }, { name: 'block_address', access: 'write', description: '', enabled: true }, { name: 'unblock_address', access: 'write', description: '', enabled: true }] },
    { id: 'cn-mcps', name: 'Local MCP (stdio)', kind: 'mcp-stdio', target: 'fw-mcp', asset_id: null, auth: { type: 'none', header: null, last4: null, key_fingerprint: null }, username: null, pin: null, allow: [], enabled: true, status: 'ok', last_test: null, tools: [{ name: 'quarantine', access: 'write', description: '', enabled: true }] },
  ]
  const FORTI = /cmdb\/firewall\/vip/
  const L = { method: /^API method$/, path: /^API path$/, body: /^API body/, command: /^Command$/, headers: /^Headers$/, tool: /^Write tool$/, args: /^Tool arguments$/ }
  const ALL = [L.method, L.path, L.body, L.command, L.headers, L.tool, L.args]
  const only = (shown: RegExp[]) => ALL.filter((p) => !shown.includes(p))

  it('renders only the fields of each kind, leaks no default from another kind, and locks read-only connections', async () => {
    connectorsStore.update((l) => [...l, ...extra])
    orgStore.update((o) => ({ ...o, setup_complete: true }))
    const cat = (await call<Catalog>('admin', 'GET', '/response/catalog')).json
    renderUi(<ActionDialog action={null} cat={cat} onClose={() => undefined} />)
    const conn = await screen.findByLabelText('Connection')
    // the dialog opens on the first connection that can write; no brand prefill (D-58): the fields start empty
    expect(screen.getAllByLabelText(L.path)[0]).toHaveValue('')
    const pick = async (name: string) => { await userEvent.selectOptions(conn, within(conn).getByRole('option', { name: new RegExp(name) })) }
    await eachOption([
      { option: 'Office FortiGate API', shown: [L.method, L.path, L.headers, L.body], hidden: only([L.method, L.path, L.headers, L.body]) },
      { option: 'File server', hidden: [] }, // read-only: see below, the option cannot be picked
      { option: 'MikroTik API', shown: [L.method, L.path, L.headers, L.body], hidden: only([L.method, L.path, L.headers, L.body]) },
      { option: 'Switch RESTCONF', shown: [L.method, L.path, L.headers, L.body], hidden: only([L.method, L.path, L.headers, L.body]) }, // NETCONF / RESTCONF: carried as an HTTP request
      { option: 'Automation platform', shown: [L.method, L.path, L.headers, L.body], hidden: only([L.method, L.path, L.headers, L.body]) },
      { option: 'Ticket API', shown: [L.method, L.path, L.headers, L.body], hidden: only([L.method, L.path, L.headers, L.body]) },
      { option: 'Core switch', shown: [L.command], hidden: only([L.command]) },
      { option: 'Firewall MCP server', shown: [L.tool, L.args], hidden: only([L.tool, L.args]) },
      { option: 'Local MCP', shown: [L.tool, L.args], hidden: only([L.tool, L.args]) },
      { option: 'Office FortiGate API', shown: [L.method, L.path, L.headers, L.body], hidden: only([L.method, L.path, L.headers, L.body]) }, // going back restores the same fields
    ], async (o) => { if (o !== 'File server') await pick(o) })

    // no default of one kind leaks into another
    await pick('Core switch')
    expect(screen.queryByDisplayValue(FORTI)).toBeNull()
    expect(within(screen.getByRole('group', { name: 'Action' })).getByLabelText(L.command)).toHaveValue('')
    await pick('Ticket API')
    expect(screen.queryByDisplayValue(FORTI)).toBeNull()
    expect(within(screen.getByRole('group', { name: 'Action' })).getByLabelText(L.path)).toHaveValue('')
    await pick('MikroTik API')
    expect(screen.queryByDisplayValue(FORTI)).toBeNull()
    expect(within(screen.getByRole('group', { name: 'Action' })).getByLabelText(L.path)).toHaveValue('')

    // switching clears what the user typed
    await pick('Office FortiGate API')
    const path = within(screen.getByRole('group', { name: 'Action' })).getByLabelText(L.path)
    await userEvent.clear(path); await userEvent.type(path, '/typed/by/hand')
    await pick('Core switch'); await pick('Office FortiGate API')
    expect(within(screen.getByRole('group', { name: 'Action' })).getByLabelText(L.path)).toHaveValue('')

    // MCP: only the write tools of that server can be chosen
    await pick('Firewall MCP server')
    const tool = within(screen.getByRole('group', { name: 'Action' })).getByLabelText(L.tool)
    expect(within(tool).getAllByRole('option').map((x) => x.textContent)).toEqual(['Pick a write tool', 'block_address', 'unblock_address'])

    // read-only connections are in the list but cannot be chosen
    const ro = within(conn).getByRole('option', { name: /File server \(read-only SSH\) \(Read-only: this connection has no write tools\)/ })
    expect(ro).toBeDisabled()
    expect(within(conn).getByRole('option', { name: /Vendor advisories \(HTTP\) \(Read-only/ })).toBeDisabled()
    expect(within(conn).getByRole('option', { name: 'Core switch (SSH)' })).toBeEnabled()
  })

  it('form matrix: the check before and the read-back text, on and off, for each kind (D-95)', async () => {
    connectorsStore.update((l) => [...l, ...extra])
    orgStore.update((o) => ({ ...o, setup_complete: true }))
    const cat = (await call<Catalog>('admin', 'GET', '/response/catalog')).json
    renderUi(<ActionDialog action={null} cat={cat} onClose={() => undefined} />)
    const conn = await screen.findByLabelText('Connection')
    const pick = async (name: string) => { await userEvent.selectOptions(conn, within(conn).getByRole('option', { name: new RegExp(name) })) }
    const EXPECT = /^Text the read-back must contain$/, REFUSE = /^Refuse when the output contains$/, CHECK = /^Check before/, MUST = /^Output must contain \(optional\)$/
    const pre = () => screen.getByRole('group', { name: CHECK })
    const withCheck = [EXPECT, REFUSE, MUST]
    await eachOption([
      { option: 'Office FortiGate API', shown: withCheck }, { option: 'MikroTik API', shown: withCheck }, { option: 'Switch RESTCONF', shown: withCheck }, { option: 'Automation platform', shown: withCheck },
      { option: 'Ticket API', shown: withCheck }, { option: 'Core switch', shown: withCheck },
      { option: 'Firewall MCP server', hidden: withCheck, shown: [/An MCP server cannot run a check before yet/] }, // no read-back and no check before on an MCP server
      { option: 'Local MCP', hidden: withCheck },
      { option: 'Office FortiGate API', shown: withCheck }, // going back restores them
    ], pick)
    // the read-back text belongs to the read-back group only; the check before has the refusal texts and no body
    await pick('Office FortiGate API')
    expect(within(screen.getByRole('group', { name: /^Read-back/ })).getByLabelText(EXPECT)).toHaveValue('')
    expect(within(screen.getByRole('group', { name: 'Action' })).queryByLabelText(EXPECT)).toBeNull()
    expect(within(screen.getByRole('group', { name: 'Rollback (undo)' })).queryByLabelText(EXPECT)).toBeNull()
    expect(within(pre()).queryByLabelText(EXPECT)).toBeNull()
    expect(within(pre()).queryByLabelText(L.body)).toBeNull()
    expect(within(pre()).getByLabelText(REFUSE)).toHaveValue('')
    expect(within(pre()).getByLabelText(MUST)).toHaveValue('')
    expect(within(screen.getByRole('group', { name: 'Action' })).queryByLabelText(MUST)).toBeNull()
    const methods = within(within(pre()).getByLabelText(L.method)).getAllByRole('option').map((o) => o.textContent)
    expect(methods).toEqual(['Choose a method', 'GET']) // a check before can only read
    // on: type them, and they are kept per connection kind; switching the connection clears them
    await userEvent.type(within(screen.getByRole('group', { name: /^Read-back/ })).getByLabelText(EXPECT), 'ok')
    await userEvent.type(within(pre()).getByLabelText(REFUSE), 'a{enter}b')
    expect(within(pre()).getByLabelText(REFUSE)).toHaveValue('a\nb')
    await pick('Core switch')
    expect(within(screen.getByRole('group', { name: /^Read-back/ })).getByLabelText(EXPECT)).toHaveValue('')
    expect(within(pre()).getByLabelText(REFUSE)).toHaveValue('')
    expect(within(pre()).getByLabelText(L.command)).toBeInTheDocument() // SSH: the check is a command
    // the form refuses what the server refuses: a port without a check, a check without a refusal text
    await userEvent.type(screen.getByLabelText('Name'), 'Shut a port')
    await userEvent.type(within(screen.getByRole('group', { name: 'Action' })).getByLabelText(L.command), 'interface {{interface}{enter}shutdown')
    await userEvent.type(within(screen.getByRole('group', { name: 'Rollback (undo)' })).getByLabelText(L.command), 'interface {{interface}{enter}no shutdown')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await within(pre()).findByText(/needs a check before it/)).toBeInTheDocument() // under the group it is about (D-390)
    await userEvent.type(within(pre()).getByLabelText(L.command), 'show interfaces {{interface} switchport')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await within(pre()).findByText(/at least one text that makes it refuse/)).toBeInTheDocument()
    await userEvent.type(within(pre()).getByLabelText(REFUSE), 'Administrative Mode: trunk')
    await userEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull())
    const saved = (await call<Catalog>('admin', 'GET', '/response/catalog')).json.items.find((a) => a.name === 'Shut a port')!
    expect(saved).toMatchObject({ precheck: { cli: 'show interfaces {interface} switchport' }, precheck_refuse: ['Administrative Mode: trunk'] })
  })

  it('a new SSH connection starts read-only (write tool off); the action form unlocks when an admin turns the write tool on, and the server refuses while it is off', async () => {
    orgStore.update((o) => ({ ...o, setup_complete: true }))
    const made = await call<{ id: string; tools: { name: string; access: string; enabled: boolean }[] }>('admin', 'POST', '/core/connections', { name: 'New switch', kind: 'ssh', target: '192.168.10.40:22', auth_type: 'ssh-key', username: 'vedette', secret: 'a-long-enough-key', allow: ['show version'], enabled: true })
    expect(made.status).toBe(201)
    expect(made.json.tools.find((t) => t.access === 'write')).toMatchObject({ name: 'run_approved_command', enabled: false })
    const ACTION = { name: 'Shut a port', description: 'x', connection_id: made.json.id, tool: null, rollback_tool: null, precheck: { ...EMPTY_TPL, cli: 'show interfaces {interface} switchport' }, precheck_refuse: ['Administrative Mode: trunk'], risk: 'medium', enabled: false, ai_may_propose: false, run: { ...EMPTY_TPL, cli: 'interface {interface}\n    shutdown' }, rollback: { ...EMPTY_TPL, cli: 'interface {interface}\n    no shutdown' }, verify: EMPTY_TPL }
    expect((await call('admin', 'POST', '/response/catalog', ACTION)).json).toMatchObject({ error: { code: 'read_only' } })
    const open = async () => { const cat = (await call<Catalog>('admin', 'GET', '/response/catalog')).json; const v = renderUi(<ActionDialog action={null} cat={cat} onClose={() => undefined} />); const conn = await screen.findByLabelText('Connection'); const o = within(conn).getByRole('option', { name: /New switch/ }); const r = { text: o.textContent ?? '', disabled: (o as HTMLOptionElement).disabled }; v.unmount(); return r }
    const locked = await open()
    expect(locked.disabled).toBe(true)
    expect(locked.text).toMatch(/Read-only: this connection has no write tools/)
    const tools = made.json.tools.map((t) => ({ name: t.name, enabled: t.access === 'write' ? true : t.enabled }))
    expect((await call('admin', 'PUT', `/core/connections/${made.json.id}`, { name: 'New switch', kind: 'ssh', target: '192.168.10.40:22', auth_type: 'ssh-key', username: 'vedette', allow: ['show version'], enabled: true, tools })).status).toBe(200)
    expect((await open()).disabled).toBe(false)
    expect((await call('admin', 'POST', '/response/catalog', ACTION)).status).toBe(201)
  })

  it('the rule builder THEN step does not offer an action whose connection is read-only', async () => {
    catalogStore.update((l) => l.map((c) => (c.id === 'cisco_acl_deny' ? { ...c, connection_id: 'cn-ssh' } : c)))
    renderUi(<RuleDialog rule={null} onClose={() => undefined} />)
    const select = await screen.findByLabelText('Action 1')
    const opt = within(select).getByRole('option', { name: /Cisco switch \(SSH\): deny an IP in the ACL \(Read-only: this connection has no write tools\)/ })
    expect(opt).toBeDisabled()
  })
})

describe('response: rule editor form matrix (docs/QA.md §2)', () => {
  const pickIn = async (label: string, name: string | RegExp, root: HTMLElement) => { const s = within(root).getByLabelText(label); await userEvent.selectOptions(s, within(s).getByRole('option', { name })) }

  it('the trigger decides the fields: only "On a schedule" has a run interval, and a change of trigger drops conditions and trigger data', async () => {
    renderUi(<RuleDialog rule={null} onClose={() => undefined} />)
    const dlg = await screen.findByRole('dialog')
    await screen.findByRole('heading', { name: 'WHEN' })
    await userEvent.click(within(dlg).getByRole('button', { name: 'Add a condition' }))
    expect(within(dlg).getAllByLabelText('Field')).toHaveLength(1)
    await eachOption([
      { option: 'A device connects to a known-bad address', hidden: ['Run every (minutes)'] },
      { option: 'On a schedule', shown: ['Run every (minutes)'] },
      { option: 'An unknown device appears', hidden: ['Run every (minutes)'] },
      { option: 'On a schedule', shown: ['Run every (minutes)'] },
    ], async (o) => { await pickIn('When this happens', o, dlg) }, dlg)
    expect(within(dlg).queryAllByLabelText('Field')).toHaveLength(0) // conditions of the other trigger are gone
    expect(within(dlg).getByLabelText('Run every (minutes)')).toHaveValue(10080)
    await pickIn('When this happens', 'An unknown device appears', dlg)
    expect(within(dlg).queryByLabelText('Run every (minutes)')).toBeNull()
  })

  it('each condition test shows its own inputs and clears the value typed for the previous test', async () => {
    renderUi(<RuleDialog rule={null} onClose={() => undefined} />)
    const dlg = await screen.findByRole('dialog')
    await screen.findByRole('heading', { name: 'IF' })
    await userEvent.click(within(dlg).getByRole('button', { name: 'Add a condition' }))
    await userEvent.type(within(dlg).getByLabelText('Value'), '192.168.10.0/24')
    const VALUE = 'Value'
    await eachOption([
      { option: 'count within a window', shown: ['At least', 'Minutes', /times within/], hidden: [VALUE, 'Hours', 'Device type is one of'] },
      { option: 'first time seen', shown: ['Hours'], hidden: [VALUE, 'At least', 'Minutes'] },
      { option: 'device type', shown: [VALUE, 'Device type is one of'], hidden: ['Field', 'At least', 'Hours'] },
      { option: 'is inside range', shown: [VALUE, 'Field'], hidden: ['At least', 'Hours', 'Device type is one of'] },
      { option: 'equals', shown: [VALUE, 'Field'], hidden: ['At least', 'Hours'] },
    ], async (o) => { await pickIn('Test', o, dlg) }, dlg)
    expect(within(dlg).getByLabelText('Value')).toHaveValue('') // the CIDR typed first did not follow the test around
    await pickIn('Test', 'device type', dlg)
    await pickIn('Test', 'equals', dlg)
    expect((within(dlg).getByLabelText('Field') as HTMLSelectElement).value).not.toBe('') // the field is picked again, not left empty
  })

  it('a log-threshold rule can be built in the editor: signature + count + window save, "any" is locked, the {ip} refills', async () => {
    renderUi(<RuleDialog rule={null} onClose={() => undefined} />)
    const dlg = await screen.findByRole('dialog')
    await screen.findByRole('heading', { name: 'IF' })
    await pickIn('When this happens', /log rule matched/, dlg)
    expect(within(dlg).getByLabelText('Conditions must match')).toBeDisabled()
    await userEvent.type(within(dlg).getByLabelText('Name'), 'Ban log attackers')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Add a condition' }))
    await pickIn('Test', 'count within a window', dlg)
    await pickIn('Field', 'Log signature', dlg)
    await userEvent.type(within(dlg).getByLabelText(/^Signature/), 'Failed password for <name>')
    await userEvent.clear(within(dlg).getByLabelText('Minutes'))
    await userEvent.type(within(dlg).getByLabelText('Minutes'), '10')
    expect(within(dlg).getByLabelText(/^Signature/)).toHaveValue('Failed password for <name>')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(async () => { const j = (await call<Rule[] | { items: Rule[] }>('admin', 'GET', '/response/rules')).json; const rules = Array.isArray(j) ? j : j.items; expect(rules.find((r) => r.name === 'Ban log attackers')?.conditions[0]).toMatchObject({ op: 'count_window', field: 'signature', value: 'Failed password for <name>', window_min: 10 }) })
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('the server refuses what the form locks: pre-approved with a risky action, an action on a read-only connection', async () => {
    const cat = (await call<Catalog>('admin', 'GET', '/response/catalog')).json
    const risky = cat.items.find((c) => c.risk !== 'low')!
    const input = { name: 'Risky', enabled: false, live: false, trigger: 'ioc_connection', match: 'all', conditions: [], actions: [{ action_id: risky.id, params: {}, ttl_min: null }], pre_approved: true, max_per_hour: 5, schedule_min: null }
    expect((await call('admin', 'POST', '/response/rules', input)).status).toBe(400)
  })

  it('a condition value must fit its field: the range or the choices of the trigger catalog (D-390)', async () => {
    const trig = (await list<{ id: string; fields: { key: string; min: number | null; max: number | null }[] }>('viewer', '/response/triggers')).find((x) => x.id === 'ioc_connection')!
    expect(trig.fields.find((f) => f.key === 'confidence')).toMatchObject({ min: 0, max: 1 })
    expect(trig.fields.find((f) => f.key === 'device')).toMatchObject({ min: null, max: null })
    const cond = (field: string, op: Condition['op'], value: string) => addRule({ conditions: [{ field, op, value, n: null, window_min: null }] })
    // the same rows and words as the box's TestRuleIsCheckedWhenSaved
    const conf = 'Confidence (0 to 1): give a number from 0 to 1.', num = 'At least / at most: give a number.'
    for (const [field, op, value, msg] of [['confidence', 'gte', '7', conf], ['confidence', 'lte', '-3', conf], ['confidence', 'gte', 'NaN', num], ['confidence', 'gte', '0.5 ', num], ['confidence', 'gte', '0x1', num], ['confidence', 'gte', '1e0', num],
      ['confidence', 'in', '0.5, 2', 'Confidence (0 to 1): give numbers from 0 to 1, separated by commas.'], ['confidence', 'eq', '', conf], ['device', 'gte', '3', 'At least / at most: only for a number field.'], ['dest_kind', 'eq', 'ipv4', 'Destination kind: use one of ip, domain.']] as const) {
      const r = await cond(field, op, value)
      expect([r.status, r.json.error?.message], `${field} ${op} ${value}`).toEqual([400, msg])
    }
    expect((await cond('confidence', 'gte', '0')).status).toBe(201)
    expect((await cond('dest_kind', 'in', 'IP, domain')).status).toBe(201)
  })

  it('form errors show under their input: the name, a confidence of 7, an empty action value; fixing one clears it (D-390)', async () => {
    renderUi(<RuleDialog rule={null} onClose={() => undefined} />)
    const dlg = await screen.findByRole('dialog')
    await screen.findByRole('heading', { name: 'IF' })
    await userEvent.click(within(dlg).getByRole('button', { name: 'Add a condition' }))
    await pickIn('Field', 'Confidence (0 to 1)', dlg)
    await pickIn('Test', 'is at least', dlg)
    await userEvent.type(within(dlg).getByLabelText('Value'), '7')
    const param = within(dlg).getByLabelText(/^Value for /)
    await userEvent.clear(param)
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save' }))
    expect(await within(dlg).findByText(/^Give a name of 1 to 80 letters/)).toBeInTheDocument()
    expect(within(dlg).getByLabelText('Name')).toHaveAttribute('aria-invalid', 'true')
    expect(within(dlg).getByText('Confidence (0 to 1): give a number from 0 to 1.')).toBeInTheDocument()
    expect(within(dlg).getByLabelText('Value')).toHaveAttribute('aria-describedby', 'rc-0-error')
    expect(within(dlg).getByText('Fill in this value.')).toBeInTheDocument()
    expect(screen.queryByRole('alert')).toBeNull() // nothing is left for the box at the bottom
    await userEvent.clear(within(dlg).getByLabelText('Value'))
    await userEvent.type(within(dlg).getByLabelText('Value'), '0.9')
    expect(within(dlg).queryByText(/give a number from 0 to 1/)).toBeNull()
    expect(within(dlg).getByText('Fill in this value.')).toBeInTheDocument()
    expect((await list<Rule>('admin', '/response/rules')).some((r) => r.conditions.some((c) => c.value === '7'))).toBe(false)
  })

  it('a rule card asks before Delete and says when a rule is switched or a template cloned (D-390)', async () => {
    renderApp('/response?tab=rules')
    const name = (await list<Rule>('admin', '/response/rules')).find((r) => r.enabled)!.name
    await userEvent.click(await screen.findByRole('switch', { name: `Rule ${name} is on` }))
    expect(await screen.findByText(`Rule ${name} is off`)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: `Delete rule ${name}` }))
    const confirm = await screen.findByRole('dialog', { name: `Delete rule ${name}?` })
    await userEvent.click(within(confirm).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect((await list<Rule>('admin', '/response/rules')).some((r) => r.name === name)).toBe(true) // Cancel deletes nothing
    await userEvent.click(screen.getByRole('button', { name: `Delete rule ${name}` }))
    await userEvent.click(within(await screen.findByRole('dialog', { name: `Delete rule ${name}?` })).getByRole('button', { name: 'Delete' }))
    expect(await screen.findByText('Rule deleted')).toBeInTheDocument()
    expect((await list<Rule>('admin', '/response/rules')).some((r) => r.name === name)).toBe(false)
    await userEvent.click(screen.getAllByRole('button', { name: /^Clone / }).find((b) => !(b as HTMLButtonElement).disabled)!)
    expect(await screen.findByText('Cloned: switched off, in dry run')).toBeInTheDocument()
  })
})

// ---- Item 20 (S-RESP-2, D-513): the inbox, the guided "Let the AI propose actions" setup, and why an empty inbox is empty ----
describe('response: inbox and guided setup (item 20, D-513)', () => {
  const triggersOf = () => list<{ id: string; ai_allowed: boolean; ai_evidence: string[] }>('admin', '/response/triggers')

  it('the plans carry what the plan job did and why nothing was sent; the triggers say what proves them to the AI (D-119)', async () => {
    const { json } = await call<PlanList>('operator', 'GET', '/response/plans')
    expect(json.planner.ran_at).not.toBeNull()
    expect(json.planner.sending).toBe(false)
    expect(json.planner.considered).toBeGreaterThan(0)
    const f = json.planner.findings.find((x) => x.finding_id === 'f-1')!
    expect(['not_sent', 'has_plan']).toContain(f.outcome)
    expect(f.reason).not.toBe('')
    const tr = await triggersOf()
    expect(tr.find((x) => x.id === 'finding')!.ai_evidence).toEqual(['finding'])
    expect(tr.find((x) => x.id === 'honeypot')!.ai_evidence).toEqual([])
  })

  it('an empty inbox shows the five steps with their status and what leaves the box, and explains why nothing is waiting', async () => {
    actionsDb.set([])
    renderApp('/response')
    const setup = await screen.findByRole('region', { name: 'Let the AI propose actions' })
    for (const step of ['1. Connect a firewall or switch', '2. Choose what the AI may propose', '3. Approvers and the channel', '4. Turn on execution (high risk)', '5. Pick the AI profile for response plans (this starts the AI)'])
      expect(within(setup).getByRole('heading', { name: step })).toBeInTheDocument()
    expect(within(setup).getAllByText('What leaves the box:')).toHaveLength(5)
    expect(within(setup).getByText(/of 4 required steps done/)).toBeInTheDocument()
    const why = await screen.findByRole('region', { name: 'Why is nothing waiting?' })
    expect(await within(why).findByText(/open critical findings?, asked the AI about/)).toBeInTheDocument()
    expect(within(why).getAllByText(/the execution switch is off|written for it on an earlier run|No action the AI may propose/).length).toBeGreaterThan(0)
    expect(within(why).getAllByText(/the AI may not use it/).length).toBeGreaterThan(3) // honeypot, unknown device, log, new port, schedule, manual
  })

  it('the steps write the same settings their own screens write: the finding trigger, "AI may propose", and execution behind the risk phrase', async () => {
    actionsDb.set([])
    renderApp('/response')
    const box = await screen.findByRole('checkbox', { name: 'Critical findings: the AI may send requests from its plans' })
    await waitFor(() => expect(box).toBeEnabled())
    const before = (await call<SettingsView>('admin', 'GET', '/response/settings')).json.ai.triggers.includes('finding')
    await userEvent.click(box)
    await waitFor(async () => expect((await call<SettingsView>('admin', 'GET', '/response/settings')).json.ai.triggers.includes('finding')).toBe(!before))
    const bl = (await call<Catalog>('admin', 'GET', '/response/catalog')).json.items.find((a) => a.id === 'blocklist_add')!
    const sw = await screen.findByRole('switch', { name: `AI may propose ${bl.name}` })
    const was = bl.ai_may_propose
    await userEvent.click(sw)
    await waitFor(async () => expect((await call<Catalog>('admin', 'GET', '/response/catalog')).json.items.find((a) => a.id === 'blocklist_add')!.ai_may_propose).toBe(!was))
    await userEvent.click(screen.getByRole('button', { name: 'Turn on execution…' }))
    const dialog = await screen.findByRole('dialog', { name: 'Turn on AI execution' })
    expect(within(dialog).getByRole('button', { name: 'Turn on AI execution' })).toBeDisabled() // the phrase and two-step sign-in, as in Settings
  })

  it('a viewer sees the status of each step but no control', async () => {
    actionsDb.set([])
    renderApp('/response', { role: 'viewer' })
    const setup = await screen.findByRole('region', { name: 'Let the AI propose actions' })
    expect(within(setup).getAllByText('An administrator does this step.').length).toBeGreaterThan(0)
    expect(within(setup).queryByRole('button', { name: 'Turn on execution…' })).toBeNull()
    expect(within(setup).getByRole('checkbox', { name: /Critical findings/ })).toBeDisabled()
  })

  it('only a device action counts: the block list never covers a device on your network, so steps 1 and 2 stay to do with it alone (review M1)', async () => {
    actionsDb.set([])
    // nothing reaches a device: every device action switched off in the catalog and without a connection; the block list is on and the AI may propose it
    catalogStore.update((l) => l.map((c) => (c.kind === 'device' ? { ...c, enabled: false, connection_id: null, ai_may_propose: false } : c.id === 'blocklist_add' ? { ...c, enabled: true, ai_may_propose: true } : c)))
    renderApp('/response')
    const setup = await screen.findByRole('region', { name: 'Let the AI propose actions' })
    const step = (name: string) => within(setup).getByRole('heading', { name }).parentElement!
    expect(await within(step('1. Connect a firewall or switch')).findByText('To do')).toBeInTheDocument()
    expect(within(step('2. Choose what the AI may propose')).getByText('To do')).toBeInTheDocument()
    expect(within(setup).getAllByText(/it does not cover devices on your network/).length).toBeGreaterThan(0)
  })

  it('the AI profile waits for steps 1, 2 and 4, with the reason; a plan written before them is never sent (review M2)', async () => {
    actionsDb.set([])
    renderApp('/response')
    const select = await screen.findByRole('combobox', { name: 'AI profile for Response plans' })
    expect(select).toBeDisabled() // execution is off in the sample
    expect(screen.getByText(/^Finish steps 1, 2 and 4 first/)).toBeInTheDocument()
    expect(select).toHaveAccessibleDescription(/Finish steps 1, 2 and 4 first/)
  })

  it('a non-admin sees "Ask an administrator" for step 1 when no device action is ready (review L2)', async () => {
    actionsDb.set([])
    catalogStore.update((l) => l.map((c) => (c.kind === 'device' ? { ...c, connection_id: null } : c)))
    renderApp('/response', { role: 'operator' })
    const setup = await screen.findByRole('region', { name: 'Let the AI propose actions' })
    expect(within(within(setup).getByRole('heading', { name: '1. Connect a firewall or switch' }).parentElement!).getByText('Ask an administrator')).toBeInTheDocument()
  })

  it('a viewer gets the planner counts and outcome codes, not the sentences of the operator log (review L1)', async () => {
    const viewer = (await call<PlanList>('viewer', 'GET', '/response/plans')).json.planner
    const op = (await call<PlanList>('operator', 'GET', '/response/plans')).json.planner
    expect(viewer.findings.length).toBeGreaterThan(0)
    expect(viewer.findings.every((f) => f.reason === '' && f.outcome)).toBe(true)
    expect(op.findings.every((f) => f.reason !== '')).toBe(true)
  })

  it('links that meant rules or requests name their tab now that the inbox opens first (review L4)', async () => {
    const { recordActivity } = await import('@/features/ai/activity')
    recordActivity({ job: 'response-plan', profile: '', model: '', hooks: [], tools: [], links: [{ kind: 'proposal', id: 'pr-x' }, { kind: 'action', id: 'act-x' }], input: 'i', output: 'o', summary: 'Sent 1 AI-generated proposal', tokens_in: 0, tokens_out: 0, result: 'ok' })
    const { default: ActivityPanel } = await import('@/features/ai/ActivityPanel')
    renderUi(<ActivityPanel />)
    await userEvent.click((await screen.findAllByRole('button', { name: /^Details of Response plan/ }))[0]!)
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByRole('link', { name: 'Proposal pr-x' })).toHaveAttribute('href', '/response?tab=requests')
    expect(within(dialog).getByRole('link', { name: 'Action act-x' })).toHaveAttribute('href', '/response?tab=requests')
  })

  it('filters by source and risk; with requests waiting the setup folds into one line', async () => {
    const pending = (await list<ActionRequest>('admin', '/response/actions')).filter((a) => a.status === 'pending')
    expect(pending.length).toBeGreaterThan(0)
    renderApp('/response')
    expect(await screen.findByText(/^Let the AI propose actions/, { selector: 'summary' })).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: 'Why is nothing waiting?' })).toBeNull()
    const one = pending[0]!
    expect((await screen.findAllByText(one.title)).length).toBeGreaterThan(0)
    const other = (['high', 'medium', 'low'] as const).find((r) => r !== one.risk)!
    await userEvent.click(within(screen.getByRole('group', { name: 'Risk' })).getByRole('button', { name: `${other[0]!.toUpperCase()}${other.slice(1)} risk` }))
    const shown = pending.filter((a) => a.risk === other)
    if (!shown.some((a) => a.title === one.title)) await waitFor(() => expect(screen.queryByRole('heading', { name: one.title, level: 3 })).toBeNull())
    if (!shown.length) expect(screen.getByText(/No request matches these filters/)).toBeInTheDocument()
    await userEvent.click(within(screen.getByRole('group', { name: 'Where from' })).getByRole('button', { name: 'People' }))
    expect(within(screen.getByRole('group', { name: 'Where from' })).getByRole('button', { name: 'People' })).toHaveAttribute('aria-pressed', 'true')
  })
})

describe('response: Respond from an incident (S-RESP-3, D-509)', () => {
  type Panel = import('./types').IncidentPanel
  const hitRow = (id: string, src: string, asset: string | null, kind = 'service') => ({ id, ts: new Date().toISOString(), kind, service: 'ssh', port: 22, src_ip: src, src_asset_id: asset, is_test: false, excerpt: '', events: [], trap_ip: '192.168.10.240', trap_hostname: 'FILESRV-OLD' })
  const incident = (id: string, hit: string, title: string, status = 'new', kind = 'trap') => ({ id, kind, attempt: false, link: `/honeypot/hits/${hit}`, title, asset_ids: [], severity: 'critical', status, first_seen: new Date().toISOString(), last_seen: new Date().toISOString(), count: 1,
    what: title, action: 'Take the machine off the network (unplug the cable, turn off Wi-Fi), then ask its user what they were doing.', sends: [], handled_by: null, handled_at: null, note: null })
  beforeEach(() => {
    collection<unknown[]>('hp_hits', () => []).set([hitRow('hit-lan', '192.168.10.107', 'a-pc07'), hitRow('hit-pub', '203.0.113.9', null), hitRow('hit-scan', '192.168.10.170', null, 'scan'), hitRow('hit-v6', 'fd00::5', null)])
    collection<unknown[]>('notify_incidents', () => []).set([incident('al-4', 'hit-lan', 'PC-HR-01 touched the SSH trap'), incident('in-pub', 'hit-pub', '203.0.113.9 touched the SSH trap'),
      incident('in-scan', 'hit-scan', '192.168.10.170 scanned the Trap IPs'), incident('in-v6', 'hit-v6', 'fd00::5 touched the SSH trap'), incident('in-done', 'hit-lan', 'PC-HR-01 touched the SSH trap', 'resolved'),
      { ...incident('in-log', 'hit-lan', 'WEB01 logged far more failed sign-ins than usual', 'new', 'log_anomaly'), link: '/logs' }])
  })

  it('a LAN source: never the block list; a firewall block is a pending request after execution is on, asked once', async () => {
    const p = (await call<Panel>('viewer', 'GET', '/response/incidents/al-4')).json
    expect(p.source).toMatchObject({ ip: '192.168.10.107', scope: 'lan' })
    expect(p.options.map((o) => o.action_id)).not.toContain('blocklist_add')
    const fgt = p.options.find((o) => o.action_id === 'fgt_addrgrp_add')!
    expect(fgt).toMatchObject({ ready: false, why: 'Execution is off. Turn it on in Settings, AI response (high risk).', ttl_min: 1440 })
    expect((await call('operator', 'POST', '/response/incidents/al-4/request', { action_id: 'fgt_addrgrp_add' })).code).toBe('execution_off')
    expect((await call('operator', 'POST', '/response/incidents/al-4/request', { action_id: 'blocklist_add' })).code).toBe('tool_not_allowed')
    await turnOn()
    const r = await call<ActionRequest>('operator', 'POST', '/response/incidents/al-4/request', { action_id: 'fgt_addrgrp_add' })
    expect(r.status).toBe(201)
    expect(r.json).toMatchObject({ source: 'person', status: 'pending', proposal_id: 'incident:al-4', pre_approved: false })
    expect(r.json.items[0]!.ttl_min).toBe(1440)
    expect((await call('operator', 'POST', '/response/incidents/al-4/request', { action_id: 'fgt_addrgrp_add' })).code).toBe('already_requested')
    expect((await call<Panel>('viewer', 'GET', '/response/incidents/al-4')).json.options.find((o) => o.action_id === 'fgt_addrgrp_add')).toMatchObject({ requested: true, ready: false })
    expect((await call('viewer', 'POST', '/response/incidents/al-4/request', { action_id: 'fgt_addrgrp_add' })).status).toBe(403)
  })

  it('a public source: the block list, even with execution off, through approval', async () => {
    const p = (await call<Panel>('viewer', 'GET', '/response/incidents/in-pub')).json
    expect(p.source).toMatchObject({ ip: '203.0.113.9', scope: 'public' })
    expect(p.options.find((o) => o.action_id === 'blocklist_add')).toMatchObject({ ready: true, title: 'Add 203.0.113.9 to the block list' })
    const r = await call<ActionRequest>('operator', 'POST', '/response/incidents/in-pub/request', { action_id: 'blocklist_add' })
    expect(r.json).toMatchObject({ source: 'person', status: 'pending' })
    expect((await call<Blocklist>('admin', 'GET', '/response/blocklist')).json.entries.map((e) => e.value)).not.toContain('203.0.113.9') // nothing until approved
  })

  it('the panel: the source, why nothing can be done yet and where to connect; then one click asks for approval', async () => {
    renderApp('/response?incident=al-4', { role: 'operator' })
    const panel = await screen.findByRole('region', { name: 'Respond to this incident' })
    expect(await within(panel).findByText('192.168.10.107')).toBeInTheDocument()
    expect(within(panel).getByText('On your network')).toBeInTheDocument()
    expect(within(panel).getByText('Vedette cannot cut this machine off for you yet.')).toBeInTheDocument()
    expect(within(panel).getByRole('link', { name: 'Settings, Connections' })).toHaveAttribute('href', '/settings/connections')
    expect(within(panel).getByText(/The block list only carries public addresses, so it cannot hold 192.168.10.107/)).toBeInTheDocument()
    for (const b of within(panel).getAllByRole('button', { name: 'Ask for approval' })) expect(b).toBeDisabled()
  })

  it('the response module off (the default): Respond still shows what to do by hand and how to let Vedette help (W7-1)', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'response' ? { ...m, enabled: false } : m)))
    const inc = (await call<{ incident: { action: string } }>('viewer', 'GET', '/notify/incidents/al-4')).json.incident
    renderApp('/response?incident=al-4', { role: 'operator' })
    const panel = await screen.findByRole('region', { name: 'Respond to this incident' })
    expect(await within(panel).findByText('The response module is off, so Vedette cannot ask for any block here. Handle it by hand.')).toBeInTheDocument()
    expect(within(panel).getByText((_, el) => el?.tagName === 'LI' && el.textContent === `Do this now: ${inc.action}`)).toBeInTheDocument()
    expect(within(panel).queryByRole('button')).toBeNull()
    expect(screen.getByRole('link', { name: 'Open module settings' })).toHaveAttribute('href', '/settings/modules')
  })

  it('the panel with execution on: Ask for approval sends one request and says nothing changes until approved', async () => {
    await turnOn()
    renderApp('/response?incident=al-4', { role: 'operator' })
    const panel = await screen.findByRole('region', { name: 'Respond to this incident' })
    const row = (await within(panel).findByText('FortiGate: add an IP to the Vedette-Blocked address group: 192.168.10.107')).closest('li')!
    await userEvent.click(within(row as HTMLElement).getByRole('button', { name: 'Ask for approval' }))
    expect(await within(panel).findByRole('status')).toHaveTextContent('Nothing changes until someone approves it.')
    expect(actionsStore.get().filter((a) => a.source === 'person')).toHaveLength(1)
  })

  it('a scan that completed no connection, a resolved incident, an IPv6 source (review of #702)', async () => {
    await turnOn()
    const scan = (await call<Panel>('viewer', 'GET', '/response/incidents/in-scan')).json
    expect(scan.note).toMatch(/can be forged/)
    expect(scan.options.every((o) => !o.ready)).toBe(true)
    expect((await call('operator', 'POST', '/response/incidents/in-scan/request', { action_id: 'fgt_addrgrp_add' })).code).toBe('source_unconfirmed')
    const done = (await call<Panel>('viewer', 'GET', '/response/incidents/in-done')).json
    expect(done).toMatchObject({ options: [], note: expect.stringMatching(/resolved/) as unknown })
    expect((await call('operator', 'POST', '/response/incidents/in-done/request', { action_id: 'fgt_addrgrp_add' })).code).toBe('incident_resolved')
    expect((await call<Panel>('viewer', 'GET', '/response/incidents/in-v6')).json.source).toMatchObject({ ip: 'fd00::5', scope: 'lan' })
  })

  it('the panel with no source says so and links to Rules, without a button', async () => {
    renderApp('/response?incident=in-log', { role: 'operator' })
    const panel = await screen.findByRole('region', { name: 'Respond to this incident' })
    expect(await within(panel).findByText(/names no single address Vedette can act on/)).toBeInTheDocument()
    expect(within(panel).getByRole('link', { name: 'Rule templates' })).toHaveAttribute('href', '/response?tab=rules')
    expect(within(panel).queryByRole('button')).toBeNull()
  })

  it('a viewer sees a ready option with a disabled button', async () => {
    await turnOn()
    renderApp('/response?incident=al-4', { role: 'viewer' })
    const panel = await screen.findByRole('region', { name: 'Respond to this incident' })
    const row = (await within(panel).findByText('FortiGate: add an IP to the Vedette-Blocked address group: 192.168.10.107')).closest('li')!
    expect(within(row as HTMLElement).getByRole('button', { name: 'Ask for approval' })).toBeDisabled()
  })
})
