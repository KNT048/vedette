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
