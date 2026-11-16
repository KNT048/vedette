// Renders the brand's raster files from the SVG sources (issue #826): app icons, favicon.ico, the GitHub social preview.
// Usage: make brand   (= pnpm --dir web exec node ../scripts/brand/render.mjs [--preview])
// Uses the repo's pinned Playwright Chromium (web/package.json); no other dependency. The output is committed: the box serves
// the icons from web/public, GitHub takes the social preview from docs/brand. --preview also writes docs/brand/preview/
// (icon grid, browser tab mock, README hero), which are review pictures, not shipped.
import { createRequire } from 'node:module'
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import path from 'node:path'

const root = path.resolve(import.meta.dirname, '../..')
const { chromium } = createRequire(path.join(root, 'web/package.json'))('@playwright/test')
const at = (p) => path.join(root, p)
const svg = (p) => `data:image/svg+xml;base64,${readFileSync(at(p)).toString('base64')}`

// [source svg, output, size]
const PNGS = [
  ['docs/brand/app-icon-ios.svg', 'web/public/apple-touch-icon.png', 180],
  ['docs/brand/app-icon.svg', 'web/public/icon-192.png', 192],
  ['docs/brand/app-icon.svg', 'web/public/icon-512.png', 512],
  ['docs/brand/app-icon-maskable.svg', 'web/public/icon-maskable-512.png', 512],
]
// favicon.ico: 16 and 32 from the 16 px-tuned favicon (heavier stroke), 48 from the app icon (Windows shortcuts)
const ICO = [['web/public/favicon.svg', 16], ['web/public/favicon.svg', 32], ['docs/brand/app-icon.svg', 48]]

const browser = await chromium.launch()
try {
  const page = await browser.newPage({ deviceScaleFactor: 1 })

  // One SVG at w x h CSS px (= device px), transparent where the SVG is.
  async function raster(src, w, h = w) {
    await page.setViewportSize({ width: w, height: h })
    await page.setContent(`<style>*{margin:0}img{display:block}</style><img src="${svg(src)}" width="${w}" height="${h}">`)
    await page.locator('img').evaluate((img) => img.decode())
    return page.screenshot({ omitBackground: true, clip: { x: 0, y: 0, width: w, height: h } })
  }
  const write = (p, buf) => { mkdirSync(path.dirname(at(p)), { recursive: true }); writeFileSync(at(p), buf); console.log(`${p} ${buf.length} B`) }

  const shown = {} // what the preview grid shows: the rendered files themselves
  for (const [src, out, size] of PNGS) write(out, (shown[out] = await raster(src, size)))
  write('docs/brand/social-preview.png', await raster('docs/brand/social-preview.svg', 1280, 640))

  // ICO container with PNG entries (Vista and later read PNG inside ICO): ICONDIR, one ICONDIRENTRY per size, then the PNGs.
  const imgs = []
  for (const [src, size] of ICO) imgs.push({ size, png: await raster(src, size) })
  const head = Buffer.alloc(6 + 16 * imgs.length)
  head.writeUInt16LE(0, 0); head.writeUInt16LE(1, 2); head.writeUInt16LE(imgs.length, 4)
  let off = head.length
  imgs.forEach(({ size, png }, i) => {
    const e = 6 + 16 * i
    head.writeUInt8(size % 256, e); head.writeUInt8(size % 256, e + 1) // 0 means 256
    head.writeUInt8(0, e + 2); head.writeUInt8(0, e + 3) // no palette, reserved
    head.writeUInt16LE(1, e + 4); head.writeUInt16LE(32, e + 6) // planes, bits per pixel
    head.writeUInt32LE(png.length, e + 8); head.writeUInt32LE(off, e + 12)
    off += png.length
  })
  write('web/public/favicon.ico', Buffer.concat([head, ...imgs.map((i) => i.png)]))

  for (const { size, png } of imgs) shown[`favicon.ico ${size}`] = png
  if (process.argv.includes('--preview')) await previews(page, write, shown)
} finally {
  await browser.close()
}

// Review pictures for the PR (docs/brand/preview/). A headless browser has no tab strip, so the "tab" picture is a drawn mock of
// one, with the favicon at its real 16 px size (and at 32 px for a 2x screen).
async function previews(page, write, shown) {
  const shot = async (out, w, html) => {
    await page.setViewportSize({ width: w, height: 100 })
    await page.setContent(`<style>*{margin:0;box-sizing:border-box}body{font:13px system-ui,sans-serif}</style>${html}`)
    await page.evaluate(() => Promise.all([...document.images].map((i) => i.decode())))
    write(out, await page.screenshot({ fullPage: true }))
  }
  const png = (b) => `data:image/png;base64,${b.toString('base64')}`
  const cells = [
    ['favicon.ico 16', 16, '16 (ico)'], ['favicon.ico 16', 64, '16, zoomed 4x', 'image-rendering:pixelated'], ['favicon.ico 32', 32, '32 (ico)'],
    ['favicon.ico 48', 48, '48 (ico)'], ['web/public/apple-touch-icon.png', 180, 'apple-touch 180'], ['web/public/icon-192.png', 192, 'PWA 192'],
    ['web/public/icon-512.png', 256, 'PWA 512, at ½'], ['web/public/icon-maskable-512.png', 160, 'maskable 512, circle mask, at ⅓', 'border-radius:50%'],
  ]
  const row = (bg, fg) => `<div style="background:${bg};color:${fg};padding:24px;display:flex;gap:24px;align-items:flex-end">${cells
    .map(([k, w, label, css = '']) => `<figure style="display:flex;flex-direction:column;align-items:center;gap:8px"><img src="${png(shown[k])}" width="${w}" height="${w}" style="${css}"><figcaption style="white-space:nowrap">${label}</figcaption></figure>`)
    .join('')}</div>`
  await shot('docs/brand/preview/icon-grid.png', 1240, row('#f8f9f7', '#56615c') + row('#11181b', '#9aa7a2'))

  const tab = (bg, bar, fg, active) => `<div style="background:${bar};padding:8px 8px 0;display:flex;gap:2px">
    <div style="background:${active};color:${fg};border-radius:8px 8px 0 0;padding:9px 14px;display:flex;gap:8px;align-items:center;width:240px">
    <img src="${svg('web/public/favicon.svg')}" width="16" height="16"><span>Vedette</span><span style="margin-left:auto;opacity:.6">✕</span></div>
    <div style="color:${fg};opacity:.6;padding:9px 14px;display:flex;gap:8px;align-items:center;width:200px"><span style="width:16px;height:16px;border-radius:50%;background:currentColor;opacity:.4"></span><span>Other tab</span></div></div>
    <div style="background:${active};color:${fg};padding:8px 14px;font-size:12px;opacity:.9">https://vedette.local:8443/login</div><div style="background:${bg};height:40px"></div>`
  await shot('docs/brand/preview/browser-tab.png', 560, tab('#f8f9f7', '#dee1e6', '#1f1f1f', '#ffffff') + tab('#11181b', '#1f2023', '#e3e3e3', '#35363a'))

  // Illustrations take the colour of the text around them (currentColor): shown inline, with the light and dark accent.
  const dir = 'web/src/assets/illustrations'
  const ill = readdirSync(at(dir)).filter((f) => f.endsWith('.svg')).sort()
  const grid = (bg, fg, cap) => `<div style="background:${bg};color:${fg};padding:24px;display:grid;grid-template-columns:repeat(3,1fr);gap:20px">${ill
    .map((f) => `<figure>${readFileSync(at(`${dir}/${f}`), 'utf8').replace('<svg ', '<svg width="100%" ')}<figcaption style="color:${cap}">${f}</figcaption></figure>`)
    .join('')}</div>`
  await shot('docs/brand/preview/illustrations.png', 900, grid('#ffffff', '#1d5a45', '#56615c') + grid('#172125', '#6bbe9c', '#9aa7a2'))

  const hero = (src, bg) => `<div style="background:${bg};padding:24px 32px"><img src="${svg(src)}" width="830"></div>`
  await shot('docs/brand/preview/readme-hero.png', 894, hero('docs/brand/readme-hero.svg', '#ffffff') + hero('docs/brand/readme-hero-dark.svg', '#0d1117'))
}
