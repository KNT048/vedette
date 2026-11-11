// Every audit action the backend writes has a label in Settings → Audit log (D-180 (6), the drift found by WP-30: the rows showed the raw
// code `user.password_reset`). The list is read from the Go source, so a new action without a label fails here.
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import i18n from '@/lib/i18n'

const ROOT = resolve(process.cwd(), '..')
const SKIP_DIRS = new Set(['node_modules', '.git', 'web', 'oas', 'coredb', 'routes', 'testdata', 'docs'])

function goFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n)
    if (statSync(p).isDirectory()) return SKIP_DIRS.has(n) ? [] : goFiles(p)
    return n.endsWith('.go') && !n.endsWith('_test.go') ? [p] : []
  })
}

// An audit action is the literal `area.name` given as `Action: "..."`, assigned to a variable called action, or passed to the helpers that
// write one (`step`, `refuse` of the response module). Event names and secret purposes share the shape and are skipped.
const CALL = /\b(Action|action|auditAction)\b|\.step\(|\.refuse\(/
const LITERAL = /"([a-z][a-z0-9]*(?:\.[a-z0-9_]+)+)"/g
export function auditActionsInSource(): Map<string, string> {
  const found = new Map<string, string>()
  for (const f of goFiles(ROOT)) {
    for (const line of readFileSync(f, 'utf8').split('\n')) {
      const code = line.trim()
      if (code.startsWith('//') || !CALL.test(code) || /Event|[pP]urpose/.test(code)) continue
      for (const m of code.matchAll(LITERAL)) found.set(m[1]!, f.slice(ROOT.length + 1))
    }
  }
  return found
}

const labelled = (action: string) => i18n.exists(`core:audit.action.${action}`)

describe('audit action labels', () => {
  const actions = auditActionsInSource()
  it('the scan finds the actions of core/auth (the scan itself works)', () => {
    for (const a of ['auth.login', 'user.password_reset', 'user.disable', 'account.password']) expect(actions.has(a), a).toBe(true)
  })
  it('every action the backend writes has a label', () => {
    const missing = [...actions].filter(([a]) => !labelled(a)).map(([a, f]) => `${a} (${f})`)
    expect(missing).toEqual([])
  })
  it('every kind of action has a label for the filter', () => {
    const groups = new Set([...actions.keys()].map((a) => a.split('.')[0]!))
    expect([...groups].filter((g) => !i18n.exists(`core:audit.group.${g}`))).toEqual([])
  })
  it('auth.login_failed says it is a failed sign-in, not only a two-step code failure', () => {
    expect(i18n.t('core:audit.action.auth.login_failed')).toBe('Failed sign-in')
  })
})
