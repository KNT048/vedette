import { describe, expect, it } from 'vitest'
import i18n, { loadNamespaces } from './i18n'
import { navItems, settingsSections, shellNamespaces } from '@/app/feature'

describe('lazy locale namespaces', () => {
  it('the shell reads its labels from the namespaces that ship in the first bundle', () => {
    // The sidebar, the settings tabs and the page title render before any feature chunk is loaded.
    expect(shellNamespaces.filter((n) => n !== 'common' && n !== 'core')).toEqual([])
    for (const label of [...navItems, ...settingsSections].map((i) => i.label)) {
      expect(i18n.exists(label), label).toBe(true)
    }
  })

  it('asks for a namespace that has no file without failing the navigation', async () => {
    await expect(loadNamespaces(['no-such-namespace'])).resolves.toBeUndefined()
  })

  it('loads a feature namespace on request', async () => {
    await loadNamespaces('findings')
    expect(i18n.hasLoadedNamespace('findings')).toBe(true)
    expect(i18n.exists('findings:titleLoading')).toBe(true)
  })
})
