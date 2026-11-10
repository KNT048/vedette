/// <reference types="node" />
// The mock pack (packs.ts) is the approved content of the GUI; modules/mitigation/testdata holds the same pack in the
// file format of the Go loader. They must say the same: same sources, steps, commands, titles and indicators.
// The file adds `status` and the `recheck` block, and omits `detected` (the box works that out from the inventory).
import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { compromise, packs } from './packs'

const DIR = join(import.meta.dirname, '../../../../modules/mitigation/testdata')
const files: Record<string, string> = Object.fromEntries(readdirSync(DIR).filter((f) => /^CVE-.*\.json$/.test(f)).map((f) => [f, readFileSync(join(DIR, f), 'utf8')]))

describe('mock packs and the Go test packs agree', () => {
  it('there is a test pack file for every mock pack, and no other', () => {
    expect(Object.keys(files).map((f) => /(CVE-[\d-]+)\.json$/.exec(f)![1]!).sort()).toEqual(Object.keys(packs()).sort())
  })
  for (const [path, raw] of Object.entries(files)) {
    const cve = /(CVE-[\d-]+)\.json$/.exec(path)![1]!
    it(`${cve}: pack, firewall guides and compromise indicators are the same`, () => {
      const file = JSON.parse(raw) as Record<string, unknown>
      const { status, recheck, compromise: fileCompromise, ...rest } = file
      expect(status).toBe('confirmed')
      expect(recheck).toBeDefined()
      const mock = JSON.parse(JSON.stringify(packs()[cve])) as { firewall: Record<string, unknown>[] }
      for (const g of mock.firewall) delete g.detected
      expect(rest).toEqual(mock)
      expect(fileCompromise).toEqual(compromise()[cve])
      expect(rest.firewall).toBeDefined()
    })
  }
})
