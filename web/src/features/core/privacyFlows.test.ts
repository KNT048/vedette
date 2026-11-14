import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import core from '../../locales/en/core.json'

// rules/legal.md: Settings → Privacy must match PRIVACY.md. Flow 6 is word for word (bold markers are not shown in the UI);
// every flow must name each host that PRIVACY.md lists in its "Where to" cell.
const rows = new Map<number, string[]>()
const containerRows = new Map<number, string[]>() // "| 6 (container-only) | …": what a container-only install shows (D-381)
for (const line of readFileSync(resolve(__dirname, '../../../../PRIVACY.md'), 'utf8').split('\n')) {
  const m = /^\| (\d+)( \(container-only\))? \| /.exec(line)
  if (m) (m[2] ? containerRows : rows).set(Number(m[1]!), line.replace(/^\||\|$/g, '').split(/ \| /).map((c) => c.trim()))
}
type Texts = { name?: string; what: string; to: string; control: string; items?: string[] }
const flows = (core as { privacy: { flow: Record<string, Texts & { container?: Texts }> } }).privacy.flow
const plain = (s: string) => s.replaceAll('**', '')

describe('Settings → Privacy flows match PRIVACY.md', () => {
  it('flow 6 is word for word', () => {
    const r = rows.get(6)!
    expect(flows['6']!.what).toBe(plain(r[2]!))
    expect(flows['6']!.to).toBe(plain(r[3]!))
    expect(flows['6']!.control).toBe(plain(r[4]!))
  })
  it('flow 15 (Shodan, D-558) is sent only on an administrator\'s click, in PRIVACY.md and on the page', () => {
    const r = rows.get(15)!
    for (const text of [plain(r[1]!), flows['15']!.name ?? '']) expect(text).toMatch(/only when an administrator clicks it/)
    for (const text of [plain(r[4]!), flows['15']!.control]) expect(text).toMatch(/if nobody clicks, nothing is sent/)
  })
  it('flow 16 (Greenbone, D-563) says what it downloads word for word, the weekly feed update included (D-564)', () => {
    const r = rows.get(16)!
    expect(flows['16']!.what).toBe(`${plain(r[2]!)}.`)
    expect(flows['16']!.what).toMatch(/then once a week while it stays enabled, when Vedette updates the feed/)
  })
  it('flow 3 is a lead sentence and one item per AI job, word for word (D-407)', () => {
    const [lead, list] = rows.get(3)![2]!.split('<ul>')
    const items = list!.replace(/<\/ul>$/, '').split('</li>').filter(Boolean).map((i) => plain(i.replace(/^<li>/, '')))
    expect(flows['3']!.what).toBe(plain(lead!))
    expect(flows['3']!.items).toEqual(items)
    expect(items.length).toBeGreaterThan(10)
  })
  it.each([6, 10])('flow %i of a container-only install is word for word (S-CORE-4)', (id) => {
    const r = containerRows.get(id)!
    expect(flows[String(id)]!.container).toEqual({ what: plain(r[2]!), to: plain(r[3]!), control: plain(r[4]!) })
  })
  it('PRIVACY.md has container-only rows only for the flows the page swaps', () => expect([...containerRows.keys()]).toEqual([6, 10]))
  it.each([...rows.keys()])('flow %i names every host of its "Where to" cell', (id) => {
    const ui = `${flows[String(id)]!.what} ${(flows[String(id)]!.items ?? []).join(' ')} ${flows[String(id)]!.to}`
    const hosts = (plain(rows.get(id)![3]!).match(/[a-z0-9*-]+(?:\.[a-z0-9-]+)+/g) ?? []).filter((h) => /\.(com|org|net|io|me|gov|dev|google|co)$/.test(h))
    for (const h of hosts) expect(ui, `flow ${id}: ${h}`).toContain(h)
  })
})
