import { describe, expect, it } from 'vitest'
import common from '../../locales/en/common.json'
import { modulesStore } from '@/mocks/stores'

// Walk-1 W1-25: Settings → Modules must show a name and a summary for every module the box can list. The Go side
// (modules/manifests_test.go) holds every MANIFEST.yaml to these names; here every module of the mock API has one.
const names = common.modules as Record<string, { name?: string; summary?: string }>

describe('every module has a display name (W1-25)', () => {
  for (const id of modulesStore.get().map((m) => m.id)) {
    it(`${id} has a name and a summary`, () => {
      expect(names[id]?.name?.trim()).toBeTruthy()
      expect(names[id]?.summary?.trim()).toBeTruthy()
    })
  }
})
