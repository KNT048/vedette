import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible } from '../helpers'
import { begin, noHScroll, stepper, THEMES } from './wp06-shared'

// WP-06 independent check, area 7: "As the IT operator I open a device whose sources disagree and want to know which value Vedette uses and why."
// Devices -> a device's details. Source priority: manual > agent > snmp > nmap/scan > passive; other values still listed.
const RANK: Record<string, number> = { manual: 5, agent: 4, snmp: 3, 'active scan': 2, nmap: 2, scan: 2, passive: 1 }
type Obs = { field: string; value: string; source: string; current: boolean }

const SRC = (s: string) => s.replace(/\(.*$/, '').trim().toLowerCase().replace('added by hand', 'manual')

/** Desktop: a table. Phone: a list of cards ("Field: value", source, "In use"). Both are read the way a person reads them. */
async function observations(page: Page): Promise<Obs[]> {
  const t = page.getByRole('table', { name: 'Observations for this device' })
  if (!(await t.isVisible().catch(() => false))) {
    const items = page.locator('#obs li')
    await expect(items.first()).toBeVisible()
    const cards = await items.evaluateAll((lis) => lis.map((l) => (l as HTMLElement).innerText.replace(/\s+/g, ' ').trim()))
    return cards.map((c) => {
      const m = /^([^:]+): (.*?)(?: In use)? (Manual|Added by hand|Agent|SNMP|Active scan|Passive|Scan|Nmap)\b/i.exec(c)
      return { field: m?.[1] ?? c, value: m?.[2] ?? c, source: SRC(m?.[3] ?? ''), current: /\bIn use\b/.test(c) }
    })
  }
  await expect(t).toBeVisible()
  const rows = await t.locator('tbody tr').evaluateAll((trs) => trs.map((r) => Array.from(r.querySelectorAll('td')).map((c) => (c.textContent ?? '').replace(/\s+/g, ' ').trim())))
  return rows.map((r) => ({ field: r[0]!, value: r[1]!, source: SRC(r[2]!), current: /In use/.test(r[4]!) }))
}

for (const theme of THEMES) {
  test(`device sources [${theme}]: the value in use follows source priority; weaker values stay listed`, async ({ page }, info) => {
    const errors = collectErrors(page)
    const shot = stepper(page, info, 'device-sources', theme)
    await begin(page, theme)
    // sample devices with disagreeing sources: agent vs passive, SNMP vs passive, active scan vs passive
    for (const [id, winner, loser] of [['a-box', 'agent', 'passive'], ['a-fw01', 'snmp', 'passive'], ['a-nas01', 'active scan', 'passive']] as const) {
      await page.goto(`/devices/${id}?tab=observations`)
      await expect(page.getByRole('heading', { name: 'All observations' })).toBeVisible()
      await shot(`${id}`)
      const obs = await observations(page)
      const os = obs.filter((o) => o.field === 'Operating system')
      console.log(id, JSON.stringify(os))
      expect(os.length, `${id}: both values listed`).toBe(2)
      const cur = os.filter((o) => o.current)
      expect(cur, `${id}: exactly one value in use`).toHaveLength(1)
      expect(cur[0]!.source, `${id}: ${winner} must beat ${loser}`).toBe(winner)
      expect(RANK[cur[0]!.source]).toBeGreaterThan(RANK[os.find((o) => !o.current)!.source]!)
      // every field: the one in use has the top rank among that field's values
      for (const f of new Set(obs.map((o) => o.field))) {
        const vals = obs.filter((o) => o.field === f)
        const top = Math.max(...vals.map((v) => RANK[v.source] ?? 0))
        expect(vals.filter((v) => v.current).map((v) => RANK[v.source] ?? 0), `${id}/${f}`).toEqual([top])
      }
    }
    // the page's own explanation of the rule must match the priority rule
    await page.goto('/devices/a-fw01?tab=observations')
    await expect(page.getByRole('heading', { name: 'All observations' })).toBeVisible()
    const intro = await page.locator('main').innerText()
    const line = intro.split('\n').find((l) => /kept for comparison/i.test(l) && /Vedette uses/i.test(l)) ?? ''
    console.log('EXPLANATION', line)
    expect.soft(line, 'the explanation says "highest confidence"; the rule is source priority (manual > agent > SNMP > scan > passive)').not.toMatch(/highest confidence/i)
    expect.soft(intro, 'nowhere on the page is the priority order explained').toMatch(/priority|agent.*SNMP|manual.*agent/i)
    // a manual value wins over everything and the old values are kept: change the type of the firewall to Router
    await page.getByLabel('Device type', { exact: true }).selectOption({ label: 'Router' }).catch(async () => { await page.getByText('Device type').first().locator('xpath=following::select[1]').selectOption({ label: 'Router' }) })
    await page.waitForTimeout(600)
    await shot('fw01-manual-router')
    const after = await observations(page)
    const kinds = after.filter((o) => o.field === 'Type')
    console.log('TYPE AFTER MANUAL', JSON.stringify(kinds))
    const manual = kinds.find((o) => o.source === 'manual')
    expect(manual?.value).toBe('Router')
    expect(manual?.current).toBe(true)
    expect(kinds.filter((o) => o.source === 'passive')).toHaveLength(1)
    expect(kinds.find((o) => o.source === 'passive')!.current).toBe(false)
    await expect(page.getByText('FW-HQ: Router').first()).toBeVisible() // the header follows the value in use
    await page.reload()
    await expect(page.getByText('FW-HQ: Router').first()).toBeVisible()
    await noHScroll(page, 'device')
    await expectAccessible(page, 'device details')
    expect(errors.filter((e) => !/status of (4|5)\d\d/.test(e))).toEqual([])
  })
}
