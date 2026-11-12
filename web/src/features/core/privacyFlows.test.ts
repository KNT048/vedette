import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import core from '../../locales/en/core.json'

// rules/legal.md: Settings → Privacy must match PRIVACY.md. Flow 6 is word for word (bold markers are not shown in the UI);
// every flow must name each host that PRIVACY.md lists in its "Where to" cell.
const rows = new Map<number, string[]>()
for (const line of readFileSync(resolve(__dirname, '../../../../PRIVACY.md'), 'utf8').split('\n')) {
  const m = /^\| (\d+) \| /.exec(line)
  if (m) rows.set(Number(m[1]!), line.replace(/^\||\|$/g, '').split(/ \| /).map((c) => c.trim()))
}
const flows = (core as { privacy: { flow: Record<string, { what: string; to: string; control: string }> } }).privacy.flow
const plain = (s: string) => s.replaceAll('**', '')

describe('Settings → Privacy flows match PRIVACY.md', () => {
  it('flow 6 is word for word', () => {
    const r = rows.get(6)!
    expect(flows['6']!.what).toBe(plain(r[2]!))
    expect(flows['6']!.to).toBe(plain(r[3]!))
    expect(flows['6']!.control).toBe(plain(r[4]!))
  })
  it.each([...rows.keys()])('flow %i names every host of its "Where to" cell', (id) => {
    const ui = `${flows[String(id)]!.what} ${flows[String(id)]!.to}`
    const hosts = (plain(rows.get(id)![3]!).match(/[a-z0-9*-]+(?:\.[a-z0-9-]+)+/g) ?? []).filter((h) => /\.(com|org|net|io|me|gov|dev|google|co)$/.test(h))
    for (const h of hosts) expect(ui, `flow ${id}: ${h}`).toContain(h)
  })
})
