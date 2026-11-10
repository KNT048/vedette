// Release-build gate (WP-08a): fails when the build output carries the mock layer.
// Usage: node scripts/check-release.mjs <distDir>
// Strings measured in a normal (mock) `pnpm build`: the MSW runtime chunks (assets/browser-*.js, assets/state-*.js)
// and public/mockServiceWorker.js all contain `[MSW]` (log prefix), `mswjs` (github.com/mswjs/msw, mswjs.io) and `msw/` (msw/passthrough).
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs'
import path from 'node:path'

const MARKERS = ['[MSW]', 'mswjs', 'msw/']
const TEXT_EXT = new Set(['.js', '.mjs', '.map', '.html'])

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const p = path.join(dir, name)
    return statSync(p).isDirectory() ? walk(p) : [p]
  })
}

const dir = process.argv[2]
if (!dir || !existsSync(dir) || !statSync(dir).isDirectory() || !existsSync(path.join(dir, 'index.html'))) {
  console.error(`check-release: ${dir ?? '(no dir)'} is missing or has no index.html`)
  process.exit(1)
}

const files = walk(dir)
const bad = []
for (const f of files) {
  if (path.basename(f) === 'mockServiceWorker.js') bad.push(`${f}: mock service worker file`)
  else if (TEXT_EXT.has(path.extname(f))) {
    const text = readFileSync(f, 'utf8')
    const hit = MARKERS.find((m) => text.includes(m))
    if (hit) bad.push(`${f}: contains ${JSON.stringify(hit)}`)
  }
}
if (bad.length > 0) {
  console.error(`check-release: ${bad.length} file(s) carry the mock layer:\n${bad.map((b) => `  ${b}`).join('\n')}`)
  process.exit(1)
}
console.log(`check-release: ${files.length} files checked, no mock layer in ${dir}`)
