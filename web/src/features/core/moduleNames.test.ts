import { readdirSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'
import common from '../../locales/en/common.json'
import { modulesStore } from '@/mocks/stores'

// Walk-1 W1-25: Settings → Modules must show a name and a summary for every module the box can list. The ids come from
// modules/*/MANIFEST.yaml (what the Go registry loads; the _template and the host component have no switch) and from
// the mock API, so a new module without a display name fails here, not on a customer's screen.
const root = resolve(__dirname, '../../../../modules')
const manifestIds = readdirSync(root, { withFileTypes: true })
  .filter((d) => d.isDirectory() && !d.name.startsWith('_'))
  .filter((d) => !/^kind:\s*component\b/m.test(readFileSync(resolve(root, d.name, 'MANIFEST.yaml'), 'utf8')))
  .map((d) => d.name)
const names = common.modules as Record<string, { name?: string; summary?: string }>

describe('every module has a display name (W1-25)', () => {
  it('the mock API lists exactly the modules of the manifests', () => {
    expect(modulesStore.get().map((m) => m.id).sort()).toEqual([...manifestIds].sort())
  })
  for (const id of manifestIds) {
    it(`${id} has a name and a summary`, () => {
      expect(names[id]?.name?.trim()).toBeTruthy()
      expect(names[id]?.summary?.trim()).toBeTruthy()
    })
  }
})
