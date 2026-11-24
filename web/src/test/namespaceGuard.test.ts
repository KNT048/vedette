// A screen never shows a raw key ("scope.confirm", "device.tab"): only `common` and `core` ship in the first bundle; every other
// namespace loads with its route or when a component asks for it with useTranslation (which waits for it). A component that reads
// another feature's words with t('inventory:…') while its own useTranslation names only its own namespace shows the key whenever
// that other namespace is not loaded yet (a page opened straight on a tab, a settings section reached from the menu).
// This guard reads every non-test .tsx under features/, components/ and app/ and fails on a t('<ns>:…') of a namespace that the
// file's useTranslation calls do not name.
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = resolve(process.cwd(), 'src')
const ROOTS = ['features', 'components', 'app']
const BUNDLED = new Set(['common', 'core'])
const NAMESPACES = new Set(readdirSync(join(SRC, 'locales/en')).map((f) => f.replace(/\.json$/, '')))

/** The namespaces a file reads with t('<ns>:…') that its useTranslation calls do not name. */
export function missing(text: string): string[] {
  const asked = new Set<string>()
  for (const m of text.matchAll(/useTranslation\(\s*(\[[^\]]*\]|['"`][^'"`]+['"`])?/g)) {
    for (const n of (m[1] ?? "'common'").matchAll(/['"`]([\w-]+)['"`]/g)) asked.add(n[1]!)
  }
  const used = new Set<string>()
  for (const m of text.matchAll(/(?<![.\w])t\(\s*['"`]([\w-]+):/g)) if (NAMESPACES.has(m[1]!) && !BUNDLED.has(m[1]!)) used.add(m[1]!)
  return [...used].filter((n) => !asked.has(n)).sort()
}

const files = ROOTS.flatMap((root) => readdirSync(join(SRC, root), { recursive: true, encoding: 'utf8' })
  .filter((f) => /\.tsx$/.test(f) && !/\.test\.tsx$/.test(f))
  .map((f) => ({ file: relative(SRC, join(SRC, root, f)).split('\\').join('/'), text: readFileSync(join(SRC, root, f), 'utf8') })))

/** Known cases outside this change, fixed in their own change; a listed case that is gone fails, so the list only shrinks. */
const KNOWN: string[] = []

describe('locale namespaces: no raw key', () => {
  it('a file that reads another namespace with t(\'<ns>:…\') names it in its useTranslation, so the words are there before it renders', () => {
    const hits = files.flatMap((f) => missing(f.text).map((n) => `${f.file}: ${n}`))
    expect(hits.filter((h) => !KNOWN.includes(h)), "Add the namespace to the component's useTranslation([own, other])").toEqual([])
    expect(KNOWN.filter((k) => !hits.includes(k)), 'known cases that are fixed: remove them').toEqual([])
  })

  it('the guard catches what it must', () => {
    expect(missing("const { t } = useTranslation('scanning'); t('inventory:scope.confirm')")).toEqual(['inventory'])
    expect(missing("const { t } = useTranslation(['scanning', 'inventory']); t('inventory:scope.confirm')")).toEqual([])
    expect(missing("const { t } = useTranslation('scanning'); t('common:cancel'); i18n.t('inventory:x')")).toEqual([])
    expect(missing("const { t } = useTranslation('inventory'); t(`findings:device.tab`)")).toEqual(['findings'])
  })
})

// A plain helper (a .ts module, no component) that another feature imports runs outside any useTranslation that would wait for its
// namespace: its i18n.t('<ns>:…') shows the raw key until that namespace happens to be loaded (a device called "makerDevice" in the
// Runs filter). Such a helper reads only the bundled namespaces.
const helpers = readdirSync(join(SRC, 'features'), { recursive: true, encoding: 'utf8' })
  .filter((f) => /\.ts$/.test(f) && !/\.test\.ts$/.test(f))
  .map((f) => ({ feature: f.split(/[\\/]/)[0]!, mod: f.replace(/\.ts$/, '').split('\\').join('/'), text: readFileSync(join(SRC, 'features', f), 'utf8') }))
const everyFile = ROOTS.flatMap((root) => readdirSync(join(SRC, root), { recursive: true, encoding: 'utf8' })
  .filter((f) => /\.tsx?$/.test(f) && !/\.test\.tsx?$/.test(f))
  .map((f) => ({ feature: root === 'features' ? f.split(/[\\/]/)[0]! : root, text: readFileSync(join(SRC, root, f), 'utf8') })))

/** The lazy namespaces a helper reads with i18n.t('<ns>:…') without loading them first (loadNamespaces('<ns>')). */
export function lazyReads(text: string): string[] {
  const loaded = new Set([...text.matchAll(/loadNamespaces\(\s*['"`]([\w-]+)['"`]/g)].map((m) => m[1]!))
  const out = new Set<string>()
  for (const m of text.matchAll(/i18n\.t\(\s*['"`]([\w-]+):/g)) if (NAMESPACES.has(m[1]!) && !BUNDLED.has(m[1]!) && !loaded.has(m[1]!)) out.add(m[1]!)
  return [...out].sort()
}

describe('locale namespaces: shared helpers', () => {
  it('a helper another feature imports reads only the bundled namespaces with i18n.t', () => {
    const hits = helpers.filter((h) => lazyReads(h.text).length > 0)
      .filter((h) => everyFile.some((f) => f.feature !== h.feature && f.text.includes(`'@/features/${h.mod}'`)))
      .map((h) => `features/${h.mod}.ts: ${lazyReads(h.text).join(', ')}`)
    expect(hits, 'Move the words to common (or core), or read them in a component that names the namespace').toEqual([])
  })

  it('the helper guard catches what it must', () => {
    expect(lazyReads("i18n.t('inventory:makerDevice', { maker })")).toEqual(['inventory'])
    expect(lazyReads("i18n.t('common:device.makerDevice', { maker })")).toEqual([])
    expect(lazyReads("await loadNamespaces('scan'); toast.error(i18n.t('scan:safety.changedElsewhere'))")).toEqual([])
  })
})
