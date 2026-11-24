// Regenerates the screenshots of the user cookbook (docs/cookbook/images/) from the sample data of the dev build.
// Each shot opens a screen, finds the elements a recipe talks about, and draws numbered callouts and highlight boxes from
// their positions, so the guidance on the images stays right when the layout moves.
//
//   pnpm --dir web cookbook-shots            all shots (starts its own Vite dev server with the sample data)
//   pnpm --dir web cookbook-shots 03 04      only the shots whose name starts with 03 or 04
//   COOKBOOK_BASE_URL=http://localhost:5173  use a dev server that already runs
//
// Never point it at a real box: the shots must show sample data only.
import { spawn } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import net from 'node:net'
import path from 'node:path'
import { chromium } from '@playwright/test'
import { SHOTS } from './cookbook-shots.list.mjs'

const WEB = path.resolve(import.meta.dirname, '..')
const OUT = path.resolve(WEB, '../docs/cookbook/images')
// A fixed clock: the sample data is dated relative to "now", so a fixed now keeps the images stable between runs.
const NOW = new Date('2026-11-24T09:30:00+07:00')
const VIEWPORT = { width: 1280, height: 800 }

const freePort = () => new Promise((resolve, reject) => {
  const srv = net.createServer()
  srv.once('error', reject)
  srv.listen(0, '127.0.0.1', () => { const { port } = srv.address(); srv.close(() => resolve(port)) })
})

async function waitForServer(url, child, ms = 60_000) {
  const end = Date.now() + ms
  while (Date.now() < end) {
    if (child.exitCode !== null) throw new Error(`the dev server stopped (exit ${child.exitCode})`)
    try { if ((await fetch(url)).ok) return } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 300))
  }
  throw new Error(`the dev server did not answer at ${url} within ${ms / 1000} s`)
}

async function startServer() {
  if (process.env.COOKBOOK_BASE_URL) return { base: process.env.COOKBOOK_BASE_URL.replace(/\/$/, ''), stop: () => {} }
  const port = await freePort()
  const child = spawn(process.execPath, [path.join(WEB, 'node_modules/vite/bin/vite.js'), '--port', String(port), '--strictPort', '--host', '127.0.0.1'], { cwd: WEB, stdio: ['ignore', 'ignore', 'inherit'] })
  const base = `http://127.0.0.1:${port}`
  try { await waitForServer(base, child) } catch (e) { child.kill(); throw e }
  return { base, stop: () => child.kill() }
}

// The callout layer: highlight boxes and numbered badges, drawn above the page at the elements' positions.
const ANNOTATE = ({ marks }) => {
  document.getElementById('cookbook-callouts')?.remove()
  const sx = window.scrollX, sy = window.scrollY
  // What a badge must not cover, in document coordinates: every line of text and every control on the page, and the boxes.
  const obstacles = []
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
  const range = document.createRange()
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    if (!n.textContent.trim()) continue
    range.selectNodeContents(n)
    for (const r of range.getClientRects()) if (r.width && r.height) obstacles.push({ x: r.left + sx, y: r.top + sy, w: r.width, h: r.height })
  }
  for (const el of document.querySelectorAll('input, textarea, select, button, svg, img, [role=switch], [role=checkbox], [role=radio]')) {
    const r = el.getBoundingClientRect()
    if (r.width && r.height) obstacles.push({ x: r.left + sx, y: r.top + sy, w: r.width, h: r.height })
  }
  const layer = document.createElement('div')
  layer.id = 'cookbook-callouts'
  layer.setAttribute('aria-hidden', 'true')
  // Absolute in document coordinates (not fixed): a full-page or clipped shot keeps every mark on its element.
  Object.assign(layer.style, { position: 'absolute', left: '0', top: '0', width: '0', height: '0', overflow: 'visible', pointerEvents: 'none', zIndex: '2147483647' })
  const color = '#d9480f'
  const size = 24
  const docW = document.documentElement.scrollWidth
  const boxes = marks.map((m) => { const pad = m.pad ?? 4; return { x: m.x - pad, y: m.y - pad, w: m.width + pad * 2, h: m.height + pad * 2 } })
  const placed = []
  const overlap = (a, b) => Math.max(0, Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x)) * Math.max(0, Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y))
  marks.forEach((m, i) => {
    const b = boxes[i]
    const box = document.createElement('div')
    Object.assign(box.style, {
      position: 'absolute', left: `${b.x}px`, top: `${b.y}px`, width: `${b.w}px`, height: `${b.h}px`,
      border: `2.5px solid ${color}`, borderRadius: '8px', boxShadow: '0 0 0 3px rgba(255,255,255,0.75)', boxSizing: 'border-box',
    })
    layer.append(box)
    if (m.n == null) return
    // The badge goes beside the box where it covers the least text, controls, boxes and other badges: left, above, right,
    // below, then the corners. A shot can force a side.
    const midY = b.y + Math.min(b.h, 48) / 2 - size / 2
    const cand = {
      left: [b.x - size - 4, midY], top: [b.x, b.y - size - 3], right: [b.x + b.w + 4, midY], bottom: [b.x, b.y + b.h + 3],
      topRight: [b.x + b.w - size, b.y - size - 3], cornerLeft: [b.x - size / 2, b.y - size / 2],
    }
    const order = m.side ? [m.side] : Object.keys(cand)
    let best = null
    for (const k of order) {
      const [x, y] = cand[k]
      if (x < 2 || y < 2 || x + size > docW - 2) continue
      const r = { x: x - 2, y: y - 2, w: size + 4, h: size + 4 }
      const cost = obstacles.reduce((c, o) => c + overlap(r, o), 0) + 4 * boxes.reduce((c, o) => c + overlap(r, o), 0) + 10 * placed.reduce((c, o) => c + overlap(r, o), 0)
      if (!best || cost < best.cost) best = { x, y, cost }
      if (cost === 0) break
    }
    best ??= { x: Math.max(2, cand.cornerLeft[0]), y: Math.max(2, cand.cornerLeft[1]) }
    placed.push({ x: best.x, y: best.y, w: size, h: size })
    const badge = document.createElement('div')
    badge.textContent = String(m.n)
    Object.assign(badge.style, {
      position: 'absolute', left: `${best.x}px`, top: `${best.y}px`, width: `${size}px`, height: `${size}px`, borderRadius: '50%',
      background: color, color: '#fff', font: '700 13px/24px Inter, system-ui, sans-serif', textAlign: 'center',
      boxShadow: '0 0 0 2px #fff, 0 1px 4px rgba(0,0,0,0.35)',
    })
    layer.append(badge)
  })
  document.body.append(layer)
  // The area every box and badge covers, so a clipped shot can grow to keep them all.
  const all = [...boxes, ...placed]
  if (!all.length) return null
  const x = Math.min(...all.map((r) => r.x)) - 6, y = Math.min(...all.map((r) => r.y)) - 6
  return { x, y, w: Math.max(...all.map((r) => r.x + r.w)) + 6 - x, h: Math.max(...all.map((r) => r.y + r.h)) + 6 - y }
}

/** Shot helpers given to each shot: `mark` collects a callout for a locator; `shoot` draws them and saves the image. */
function helpers(page, name) {
  const marks = []
  return {
    page,
    async mark(locator, n, opts = {}) {
      const el = locator.first()
      await el.waitFor({ state: 'visible', timeout: 10_000 })
      await el.scrollIntoViewIfNeeded()
      marks.push({ locator: el, n, ...opts })
    },
    /** `area`: 'viewport' (the top of the page, the default), 'full' (the whole page), or a locator (that element and a margin,
     *  for example a dialog). Marks are placed in document coordinates, so any of them keeps the marks on their elements. */
    /*  `fixed`: the area does not scroll with the page (a dialog): clipped from the viewport. */
    /*  `toasts`: keep the toast messages on the image (hidden by default: they come and go). */
    /*  `maxHeight`: a long area is cut at this height (a table needs only its first rows). */
    async shoot({ area = 'viewport', margin = 16, fixed = false, toasts = false, maxHeight = fixed ? Infinity : 1100 } = {}) {
      await page.evaluate((show) => {
        let st = document.getElementById('cookbook-style')
        if (!st) { st = document.createElement('style'); st.id = 'cookbook-style'; document.head.append(st) }
        st.textContent = show ? '' : '[data-sonner-toaster]{display:none!important}'
      }, toasts)
      // No focus ring or open tooltip on the image.
      await page.evaluate(() => { if (document.activeElement instanceof HTMLElement) document.activeElement.blur() })
      await page.mouse.move(0, VIEWPORT.height - 1)
      const scroll = await page.evaluate(() => ({ x: window.scrollX, y: window.scrollY }))
      const boxes = []
      for (const m of marks) {
        // `tight`: the box hugs the element's text, not its full width (a heading is as wide as its column).
        const b = m.tight
          ? await m.locator.evaluate((el) => { const r = document.createRange(); r.selectNodeContents(el); const q = r.getBoundingClientRect(); return { x: q.left, y: q.top, width: q.width, height: q.height } })
          : await m.locator.boundingBox()
        if (!b) throw new Error(`${name}: callout ${m.n ?? '(box)'} has no position`)
        boxes.push({ x: b.x + scroll.x, y: b.y + scroll.y, width: b.width, height: b.height, n: m.n, pad: m.pad, side: m.side })
      }
      const drawn = await page.evaluate(ANNOTATE, { marks: boxes })
      const opts = { animations: 'disabled', caret: 'hide' }
      let png
      if (area === 'full') png = await page.screenshot({ ...opts, fullPage: true })
      else if (area === 'viewport') { await page.evaluate(() => window.scrollTo(0, 0)); png = await page.screenshot(opts) }
      else {
        const b = await area.first().boundingBox()
        if (!b) throw new Error(`${name}: the area has no position`)
        const doc = fixed ? { w: page.viewportSize().width, h: page.viewportSize().height } : await page.evaluate(() => ({ w: document.documentElement.scrollWidth, h: document.documentElement.scrollHeight }))
        const off = fixed ? { x: 0, y: 0 } : scroll
        // The area plus its margin, grown to every box and badge (drawn in document coordinates).
        let x0 = b.x + off.x - margin, y0 = b.y + off.y - margin, x1 = b.x + off.x + b.width + margin, y1 = b.y + off.y + b.height + margin
        if (drawn) {
          const dx = fixed ? scroll.x : 0, dy = fixed ? scroll.y : 0
          x0 = Math.min(x0, drawn.x - dx); y0 = Math.min(y0, drawn.y - dy); x1 = Math.max(x1, drawn.x - dx + drawn.w); y1 = Math.max(y1, drawn.y - dy + drawn.h)
        }
        const x = Math.max(0, x0), y = Math.max(0, y0)
        png = await page.screenshot({ ...opts, fullPage: !fixed, clip: { x, y, width: Math.min(doc.w, x1) - x, height: Math.min(doc.h, y1, y + maxHeight) - y } })
      }
      writeFileSync(path.join(OUT, `${name}.webp`), await toWebp(png))
      await page.evaluate(() => document.getElementById('cookbook-callouts')?.remove())
      marks.length = 0
    },
  }
}

// WebP at quality 0.9, encoded by the same Chromium (no extra tool): about half the size of the PNG, text still crisp.
let encoder
async function toWebp(png) {
  const url = await encoder.evaluate(async (b64) => {
    const img = new Image()
    img.src = `data:image/png;base64,${b64}`
    await img.decode()
    const c = document.createElement('canvas')
    c.width = img.naturalWidth; c.height = img.naturalHeight
    c.getContext('2d').drawImage(img, 0, 0)
    return c.toDataURL('image/webp', 0.9)
  }, png.toString('base64'))
  if (!url.startsWith('data:image/webp;base64,')) throw new Error('this Chromium cannot encode WebP')
  return Buffer.from(url.slice(url.indexOf(',') + 1), 'base64')
}

async function newPage(browser, base) {
  const ctx = await browser.newContext({ viewport: VIEWPORT, deviceScaleFactor: 1, locale: 'en-US', timezoneId: 'Asia/Ho_Chi_Minh', colorScheme: 'light', reducedMotion: 'reduce', baseURL: base })
  const page = await ctx.newPage()
  await page.clock.setFixedTime(NOW)
  return page
}

/** Through the setup wizard with "Use sample data", as a first visitor does. */
async function signInWithSample(page) {
  await page.goto('/setup')
  await page.getByRole('checkbox', { name: 'I have read, understood and agree to the terms of use' }).click()
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('button', { name: 'Use sample data' }).click()
  await page.getByRole('heading', { level: 1, name: /^Today/ }).waitFor()
}

const filters = process.argv.slice(2)
const todo = SHOTS.filter((s) => !filters.length || filters.some((f) => s.name.startsWith(f)))
if (!todo.length) { console.error(`no shot matches ${filters.join(' ')}`); process.exit(2) }
mkdirSync(OUT, { recursive: true })
const server = await startServer()
const browser = await chromium.launch()
encoder = await browser.newPage()
let failed = 0
try {
  let signedIn = null
  for (const shot of todo) {
    // A shot of the setup wizard needs a fresh visitor; every other shot shares one signed-in page with the sample data.
    let page
    if (shot.fresh) page = await newPage(browser, server.base)
    else {
      if (!signedIn) { signedIn = await newPage(browser, server.base); await signInWithSample(signedIn) }
      page = signedIn
    }
    try {
      await page.setViewportSize({ width: VIEWPORT.width, height: shot.height ?? VIEWPORT.height })
      await shot.run(helpers(page, shot.name))
      console.log(`ok   ${shot.name}`)
    } catch (e) {
      failed++
      console.error(`FAIL ${shot.name}: ${e.message.split('\n')[0]}`)
    } finally {
      if (shot.fresh) await page.context().close()
      else await page.keyboard.press('Escape').catch(() => {})
    }
  }
} finally {
  await browser.close()
  server.stop()
}
if (failed) { console.error(`${failed} shot(s) failed`); process.exit(1) }
