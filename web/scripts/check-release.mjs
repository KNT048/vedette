// Release-build gate: fails when the build output carries the mock layer.
// Usage: node scripts/check-release.mjs <distDir>
// Strings measured in a normal (mock) `pnpm build`: the MSW runtime chunks (assets/browser-*.js, assets/state-*.js)
// and public/mockServiceWorker.js all contain `[MSW]` (log prefix), `mswjs` (github.com/mswjs/msw, mswjs.io) and `msw/` (msw/passthrough).
// It also fails when z.config({ jitless: true }) (src/lib/zodConfig.ts) is not in the chunk that holds zod's core (`__zod_globalConfig`): in
// another chunk it ran after the first schemas were built, whose `new Function` probe the shipped CSP reports in the console (issue #201;
// vite.config.ts codeSplitting group "zod").
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
const zodCore = files.filter((f) => path.extname(f) === '.js' && readFileSync(f, 'utf8').includes('__zod_globalConfig'))
if (zodCore.length === 0) bad.push('no chunk holds zod\'s core (__zod_globalConfig): the jitless check cannot run')
for (const f of zodCore) {
  if (!/jitless\s*:\s*(!0|true)/.test(readFileSync(f, 'utf8'))) bad.push(`${f}: holds zod's core but not z.config({ jitless: true }), so the first schemas probe new Function under the CSP`)
}
if (bad.length > 0) {
  console.error(`check-release: ${bad.length} problem(s) (mock layer, zod config):\n${bad.map((b) => `  ${b}`).join('\n')}`)
  process.exit(1)
}
console.log(`check-release: ${files.length} files checked, no mock layer in ${dir}, zod jitless in its core chunk`)
