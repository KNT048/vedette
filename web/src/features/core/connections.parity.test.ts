// The same script of API calls that the Go backend runs (modules/core/handlers_connections_test.go) against the mock
// of Settings → Connections: the mock is the approved behaviour (GUI first), so every step records the status, code, field and
// message it gives, and the backend must answer the same. The script is src/features/core/testdata/connections_matrix.json; a step that
// the backend answers differently on purpose carries a `real` block that only the Go side reads.
import { describe, expect, it } from 'vitest'
import { sessionStore } from '@/mocks/stores'
import matrixJson from './testdata/connections_matrix.json'
import keyPlain from './testdata/keys/ed25519?raw'
import keyLocked from './testdata/keys/ed25519-passphrase?raw'

const matrix = matrixJson as unknown as { steps: Step[] }

interface Step {
  name: string
  role: 'admin' | 'operator' | 'viewer' | null
  method: string
  path: string
  body?: unknown
  status: number
  error?: { code: string; field?: string; message?: string }
  keep?: string
  expect?: unknown
  matches?: Record<string, string>
  matchesMessage?: string
  absent?: string[]
  listHas?: string[]
  listLacks?: string[]
}
const USER = { admin: 'u-admin', operator: 'u-op', viewer: 'u-view' } as const
const KEYS: Record<string, string> = { $KEY_PLAIN: keyPlain, $KEY_LOCKED: keyLocked }
const fill = (v: unknown): unknown => (typeof v === 'string' ? (KEYS[v] ?? v) : Array.isArray(v) ? v.map(fill) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, fill(x)])) : v)

/** Every key of `want` is in `got` with the same value; arrays match element by element. */
function subset(got: unknown, want: unknown, at: string): string | null {
  if (want === null || typeof want !== 'object') return Object.is(got, want) ? null : `${at}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`
  if (Array.isArray(want)) {
    if (!Array.isArray(got) || got.length !== want.length) return `${at}: got ${JSON.stringify(got)}, want ${want.length} items`
    for (const [i, w] of want.entries()) { const e = subset(got[i], w, `${at}[${i}]`); if (e) return e }
    return null
  }
  if (got === null || typeof got !== 'object') return `${at}: got ${JSON.stringify(got)}, want an object`
  for (const [k, w] of Object.entries(want)) { const e = subset((got as Record<string, unknown>)[k], w, `${at}.${k}`); if (e) return e }
  return null
}
const dig = (v: unknown, path: string) => path.split('.').reduce<unknown>((o, k) => (o as Record<string, unknown> | null)?.[k], v)

describe('Connections: the script the backend must answer the same way (src/features/core/testdata/connections_matrix.json)', () => {
  it('runs against the mock', async () => {
    const kept: Record<string, string> = {}
    for (const s of matrix.steps) {
      sessionStore.set({ userId: s.role ? USER[s.role] : null })
      const path = s.path.replace(/\{(\w+)\}/g, (_, k: string) => kept[k] ?? `{${k}}`)
      const r = await fetch(`${location.origin}/api/v1${path}`, { method: s.method, headers: { 'Content-Type': 'application/json' }, body: s.body === undefined ? undefined : JSON.stringify(fill(s.body)) })
      const text = await r.text()
      const body = text ? (JSON.parse(text) as Record<string, any>) : null // eslint-disable-line @typescript-eslint/no-explicit-any
      const at = `step "${s.name}"`
      expect(r.status, `${at}: ${text.slice(0, 200)}`).toBe(s.status)
      if (s.error) {
        expect(body?.error?.code, at).toBe(s.error.code)
        if (s.error.field) expect(body?.error?.field, at).toBe(s.error.field)
        if (s.error.message) expect(body?.error?.message, at).toBe(s.error.message)
      }
      if (s.matchesMessage) expect(body?.error?.message, at).toMatch(new RegExp(s.matchesMessage))
      if (s.expect !== undefined) expect(subset(body, s.expect, ''), at).toBeNull()
      for (const [p, re] of Object.entries(s.matches ?? {})) expect(String(dig(body, p)), `${at} ${p}`).toMatch(new RegExp(re))
      for (const a of s.absent ?? []) expect(text, `${at}: ${a} is in the answer`).not.toContain(a)
      if (s.keep) kept[s.keep] = body!.id
      for (const k of s.listHas ?? []) expect((body!.items as { id: string }[]).some((c) => c.id === kept[k]), `${at}: ${k} is not listed`).toBe(true)
      for (const k of s.listLacks ?? []) expect((body!.items as { id: string }[]).some((c) => c.id === kept[k]), `${at}: ${k} is still listed`).toBe(false)
    }
  })
})
