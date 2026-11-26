import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import core from '../../locales/en/core.json'

// Settings → Privacy must match PRIVACY.md. Flow 6 is word for word (bold markers are not shown in the UI);
// every flow must name each host that PRIVACY.md lists in its "Where to" cell.
const rows = new Map<number, string[]>()
const containerRows = new Map<number, string[]>() // "| 6 (container-only) | …": what a container-only install shows
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
  it('flow 15 (Shodan) is sent only on an administrator\'s click, in PRIVACY.md and on the page', () => {
    const r = rows.get(15)!
    for (const text of [plain(r[1]!), flows['15']!.name ?? '']) expect(text).toMatch(/only when an administrator clicks it/)
    for (const text of [plain(r[4]!), flows['15']!.control]) expect(text).toMatch(/if nobody clicks, nothing is sent/)
  })
  it('flow 16 (Greenbone) says what it downloads word for word, the weekly feed update included', () => {
    const r = rows.get(16)!
    expect(flows['16']!.what).toBe(`${plain(r[2]!)}.`)
    expect(flows['16']!.what).toMatch(/^Vedette's system helper vedette-host has this box's container engine download/) // review r1 M2: who downloads
    expect(flows['16']!.what).toMatch(/then once a week while it stays enabled \(Vedette's feed update/)
  })
  it('flow 9: Greenbone is re-checked against the IP like the other steps, and the name check is not Greenbone\'s', () => {
    expect(plain(rows.get(9)![2]!)).toMatch(/the box checks again right before it that the IP is still this box's own \(seen as the box's address within the last 90 days and after its current address was first seen\)/)
    expect(flows['9']!.what).toMatch(/one probe-log row for the run written before it starts \(the box checks again right before it that the IP is still its own\)\. For the names of your domain, one web-page check by name on ports 80 and 443\./)
  })
  it('flow 9: the DNS lookups of a domain scan go through the box\'s resolver, the same words in both (exposure INV-27)', () => {
    const sentence = "through this box's own DNS resolver (and from it the domain's DNS provider), the box looks up the A, AAAA and CNAME records"
    expect(plain(rows.get(9)![2]!)).toContain(sentence)
    expect(flows['9']!.what).toContain(sentence)
    for (const text of [plain(rows.get(9)![2]!), flows['9']!.what]) expect(text).toContain("Without a domain's testing terms, names on addresses that are not this box's get no scan beyond the existing check by name on ports 80 and 443.")
  })
  it('flow 9: with a domain\'s testing terms the deep scan reaches every address its names resolve to, the same words in both (LEGAL-2)', () => {
    for (const text of [plain(rows.get(9)![2]!), flows['9']!.what]) {
      expect(text).toContain("whatever serves it: your own server, a hosting provider, a CDN or a proxy, whose machines may also serve other people's systems (you need the provider's permission; Vedette does not check who owns those addresses).")
      expect(text).toContain('Private and IPv6 addresses are never contacted. No new kind of destination.')
    }
    for (const to of [plain(rows.get(9)![3]!), flows['9']!.to]) expect(to).toContain('with a domain\'s testing terms, every public address its names resolve to, including a hosting provider, CDN or proxy in front of them')
  })
  it('flow 9: scheduled scans and how to turn them off, the same words in both (exposure INV-36)', () => {
    const sentence = 'Each target is also scanned by itself on its schedule (daily, weekly by default, or monthly; Off scans it only when you select Scan now)'
    for (const text of [plain(rows.get(9)![2]!), flows['9']!.what]) expect(text).toContain(sentence)
    for (const text of [plain(rows.get(9)![4]!), flows['9']!.control]) expect(text).toContain("Set a target's scheduled scan to Off (on its page)")
  })
  it('flow 9: the testing terms can be withdrawn per target, the same words in both', () => {
    const sentence = "Withdraw a target's testing terms (Ownership tab) to keep its scans to the Scan now scope"
    expect(plain(rows.get(9)![4]!)).toContain(sentence)
    expect(flows['9']!.control).toContain(`${sentence}.`)
  })
  it('flow 3 is a lead sentence and one item per AI job, word for word', () => {
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
  it('the mirror-port paragraph is word for word on the page', () => {
    const md = readFileSync(resolve(__dirname, '../../../../PRIVACY.md'), 'utf8').split('\n').find((l) => l.startsWith('**Mirror port traffic stays on the box.**'))
    const note = (core as { privacy: { mirrorNote: { bodyInfo: string } } }).privacy.mirrorNote
    expect(note.bodyInfo).toBe(plain(md!))
    expect(note.bodyInfo).toContain('never the content of the traffic')
    expect(note.bodyInfo).toContain('keeps only the matches')
  })
  it('PRIVACY.md has container-only rows only for the flows the page swaps', () => expect([...containerRows.keys()]).toEqual([6, 10]))
  it.each([...rows.keys()])('flow %i names every host of its "Where to" cell', (id) => {
    const ui = `${flows[String(id)]!.what} ${(flows[String(id)]!.items ?? []).join(' ')} ${flows[String(id)]!.to}`
    const hosts = (plain(rows.get(id)![3]!).match(/[a-z0-9*-]+(?:\.[a-z0-9-]+)+/g) ?? []).filter((h) => /\.(com|org|net|io|me|gov|dev|google|co)$/.test(h))
    for (const h of hosts) expect(ui, `flow ${id}: ${h}`).toContain(h)
  })
})
