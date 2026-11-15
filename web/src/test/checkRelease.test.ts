import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'

const script = path.resolve(import.meta.dirname, '../../scripts/check-release.mjs')
const dirs: string[] = []

function fixture(files: Record<string, string>) {
  const d = mkdtempSync(path.join(tmpdir(), 'check-release-'))
  dirs.push(d)
  files['index.html'] ??= '<html></html>'
  for (const [name, body] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(d, name)), { recursive: true })
    writeFileSync(path.join(d, name), body)
  }
  return d
}
const run = (d: string) => spawnSync(process.execPath, [script, d], { encoding: 'utf8' })

afterEach(() => { while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true }) })

describe('check-release', () => {
  // A release build has zod's core in one chunk with z.config({ jitless: true }) (D-621, vite.config.ts group "zod"), as rolldown minifies it.
  const zodChunk = 'var g=globalThis.__zod_globalConfig??(globalThis.__zod_globalConfig={});Object.assign(g,{jitless:!0});'
  it('passes a clean dist', () => {
    const r = run(fixture({ 'assets/app.js': 'console.log(1)', 'assets/zod-x.js': zodChunk, 'favicon.svg': '<svg/>' }))
    expect(r.status).toBe(0)
    expect(r.stdout).toContain('4 files checked')
  })
  it('fails and names the chunk with zod\'s core but without the jitless config (D-621, issue #201)', () => {
    const r = run(fixture({ 'assets/app.js': 'r({jitless:!0})', 'assets/contract-x.js': 'var g=globalThis.__zod_globalConfig??(globalThis.__zod_globalConfig={});' }))
    expect(r.status).toBe(1)
    expect(r.stderr).toContain('contract-x.js')
  })
  it('fails when no chunk holds zod\'s core (the check could not run)', () => {
    const r = run(fixture({ 'assets/app.js': 'console.log(1)' }))
    expect(r.status).toBe(1)
    expect(r.stderr).toContain('__zod_globalConfig')
  })
  it('fails and names a chunk containing [MSW]', () => {
    const r = run(fixture({ 'assets/state-x.js': 'console.error(`[MSW] boom`)' }))
    expect(r.status).toBe(1)
    expect(r.stderr).toContain('state-x.js')
  })
  it('fails when mockServiceWorker.js exists', () => {
    const r = run(fixture({ 'mockServiceWorker.js': '// worker' }))
    expect(r.status).toBe(1)
    expect(r.stderr).toContain('mockServiceWorker.js')
  })
  it('fails when the dir has no index.html', () => {
    const d = fixture({})
    rmSync(path.join(d, 'index.html'))
    expect(run(d).status).toBe(1)
  })
})
