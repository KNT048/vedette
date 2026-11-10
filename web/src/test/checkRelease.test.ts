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
  it('passes a clean dist', () => {
    const r = run(fixture({ 'assets/app.js': 'console.log(1)', 'favicon.svg': '<svg/>' }))
    expect(r.status).toBe(0)
    expect(r.stdout).toContain('3 files checked')
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
