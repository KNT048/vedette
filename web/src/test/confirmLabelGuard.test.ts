// No bare "Confirm" button: a button that confirms names what it confirms ("Confirm vulnerability", "Confirm the scope", "Confirm
// ownership"), so a person never wonders what pressing it settles. This guard counts the whole class: every string of the English
// locale files that reads "Confirm" alone, and every literal "Confirm" label in the sources. A named exception goes in ALLOWED with
// why it stays; an entry no longer used fails too, so the list only shrinks.
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = resolve(process.cwd(), 'src') // vitest runs from web/
const ROOTS = ['features', 'components', 'app']

/** Named exceptions: "<namespace>:<key>" of a bare label, and why it stays. */
const ALLOWED: { key: string; why: string }[] = []

/** A label that confirms without saying what: "Confirm", "Confirm…", "Confirm!" (any case). */
export const bare = (s: string) => /^\s*confirm\s*[.…!]*\s*$/i.test(s)

function leaves(o: unknown, p = ''): [string, string][] {
  if (typeof o === 'string') return [[p, o]]
  if (o && typeof o === 'object') return Object.entries(o).flatMap(([k, v]) => leaves(v, p ? `${p}.${k}` : k))
  return []
}

function localeHits(): string[] {
  const dir = join(SRC, 'locales', 'en')
  return readdirSync(dir).filter((f) => f.endsWith('.json')).flatMap((f) => {
    const ns = f.replace(/\.json$/, '')
    return leaves(JSON.parse(readFileSync(join(dir, f), 'utf8'))).filter(([, v]) => bare(v)).map(([k]) => `${ns}:${k}`)
  })
}

function sourceHits(): string[] {
  return ROOTS.flatMap((root) => (readdirSync(join(SRC, root), { recursive: true }) as string[])
    .filter((f) => /\.tsx$/.test(f) && !/\.test\.tsx$/.test(f))
    .flatMap((f) => {
      const text = readFileSync(join(SRC, root, f), 'utf8')
      const file = relative(SRC, join(SRC, root, f)).split('\\').join('/')
      return [...text.matchAll(/>\s*Confirm\s*<|(?:aria-label|label|title)=["']Confirm["']/g)].map((m) => `${file}:${text.slice(0, m.index).split('\n').length}`)
    }))
}

describe('confirm label guard: every Confirm names its object', () => {
  const locales = localeHits()
  const sources = sourceHits()

  it('reports the count of the class', () => {
    // before this guard: 4 bare "Confirm" strings (findings confirm.button and confirm.col, inventory toScope.confirm, response
    // chatLink.confirm); after: 0
    console.info(`bare Confirm labels: ${locales.length} in locales, ${sources.length} in sources`)
    expect(locales.length + sources.length).toBeGreaterThanOrEqual(0)
  })

  it('no locale string is a bare "Confirm"', () => {
    const bad = locales.filter((k) => !ALLOWED.some((a) => a.key === k))
    expect(bad, 'Name what the button confirms ("Confirm vulnerability", "Confirm the scope"), or add a named exception').toEqual([])
  })

  it('no source writes a bare "Confirm" label', () => {
    expect(sources).toEqual([])
  })

  it('every exception is still used', () => {
    expect(ALLOWED.filter((a) => !locales.includes(a.key)).map((a) => a.key)).toEqual([])
  })

  it('catches what it must and leaves what it may', () => {
    expect(['Confirm', 'confirm', 'Confirm…', ' Confirm '].every(bare)).toBe(true)
    expect(['Confirm vulnerability', 'Confirm the scope', 'Confirm ownership', 'Confirming…', 'Confirm: {{kind}}'].some(bare)).toBe(false)
  })
})
