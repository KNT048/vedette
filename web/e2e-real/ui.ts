// Small page helpers shared by the real-backend specs; the same ones the mock specs use (e2e/qa/core.spec.ts), so the steps read alike.
import { readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { expect, type Page } from '@playwright/test'

export const h1 = (page: Page) => page.getByRole('heading', { level: 1 }).first()
export const next = (page: Page) => page.getByRole('button', { name: 'Continue' }).click()
/** No console or page error. A GUI whose bundle fails to load a module (`does not provide an export`) must still fail this, so nothing is filtered by default. */
export const noErrors = (errors: string[], extra?: RegExp) => expect(errors.filter((e) => !(extra && extra.test(e)))).toEqual([])

// Vietnamese letters must not reach the interface (the author's name "Kiên" in the license line is the one exception).
const VI = /[ăâđêôơưáàảãạấầẩẫậắằẳẵặéèẻẽẹếềểễệíìỉĩịóòỏõọốồổỗộớờởỡợúùủũụứừửữựýỳỷỹỵ]/i
const ALLOWED_VI = /Kiên|e2e\.test/
export async function noVietnamese(page: Page, label: string) {
  const text = await page.locator('body').innerText()
  const bad = text.split('\n').filter((l) => VI.test(l) && !ALLOWED_VI.test(l))
  expect(bad, `${label}: Vietnamese text in the interface`).toEqual([])
}

// axe-core on the real page. The shipped Content-Security-Policy blocks an injected <script> (addScriptTag), and the run must keep
// the policy on, so the library source is evaluated through the browser's debugging channel, which the policy does not govern.
const AXE_SOURCE = readFileSync(createRequire(import.meta.url).resolve('axe-core/axe.min.js'), 'utf8')
/** Fails on serious or critical axe violations, with colour contrast, like `expectAccessible` of the mock specs. */
export async function expectAccessible(page: Page, label: string) {
  // a toast fading in is read by axe mid-transition (contrast): wait until none is on screen
  await expect(page.locator('[data-sonner-toast]')).toHaveCount(0, { timeout: 15_000 })
  await page.evaluate(AXE_SOURCE)
  const violations = await page.evaluate(async () => {
    // @ts-expect-error axe is put on window by the evaluated source
    const r = await window.axe.run(document, { resultTypes: ['violations'] })
    return (r.violations as { id: string; impact: string; help: string; nodes: { target: string[] }[] }[])
      .filter((v) => v.impact === 'serious' || v.impact === 'critical')
      .map((v) => `${v.id} (${v.impact}): ${v.help} → ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`)
  })
  expect(violations, `${label}\n${violations.join('\n')}`).toEqual([])
}

/** GET /core/updates (the software part of Settings -> Updates) answers 501 on the real box: unbuilt backend (.ai/deferred/feat-core-os-updates.md:3).
 *  The whole page waits for that answer before it draws the operating system part, which IS built, so the specs of the OS part put an empty
 *  software state in its place and leave every other call real, `/core/updates/os*` included. While the real route still answers 501 the stub
 *  answers; once it answers 200 the real answer is passed through and this helper does nothing. Delete it with the 501 (KNOWN_501 in gaps.spec.ts). */
export async function stubSoftwareUpdates(page: Page) {
  await page.route((url) => url.pathname === '/api/v1/core/updates', async (route) => {
    if (route.request().method() !== 'GET') return route.fallback()
    const real = await route.fetch()
    if (real.status() !== 501) return route.fulfill({ response: real })
    return route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ channel: 'stable', mode: 'manual', check_enabled: true, last_check: new Date().toISOString(), components: [], available: [], history: [], advisories: [], managed: [] }),
    })
  })
}
