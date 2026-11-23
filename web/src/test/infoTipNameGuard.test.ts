// An ⓘ is never named after the action button next to it. InfoTip reads "About <topic>"; when the topic is the label of a button in
// the same component ("Applied" and "About Applied"), a role query by name, a voice-control "click Applied" and a screen reader's
// list of buttons all find two controls for one action, and the ⓘ is the one that is never disabled. The ⓘ next to an action
// explains the hint beside it, so it takes the hint's own short name or no topic ("More about this").
// This guard counts the whole class: every `InfoTip topic={X}` whose X is also the content of a <Button>/<button> in the same file.
import { readdirSync, readFileSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const SRC = resolve(process.cwd(), 'src') // vitest runs from web/
const ROOTS = ['features', 'components', 'app']

/** A JSX expression with at most one level of nested braces (`{t('a', { b })}`), right before a closing button tag. */
const BUTTON_CONTENT = /\{((?:[^{}]|\{[^{}]*\})*)\}\s*<\/(?:Button|button)>/g
const TOPIC = /<InfoTip\b[^>]*?\btopic=\{((?:[^{}]|\{[^{}]*\})*)\}/g

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

/** "<file>:<line> <topic>" for every ⓘ whose topic expression is (part of) a button's content in the same file. */
export function hits(): string[] {
  return ROOTS.flatMap((root) => (readdirSync(join(SRC, root), { recursive: true }) as string[])
    .filter((f) => /\.tsx$/.test(f) && !/\.test\.tsx$/.test(f))
    .flatMap((f) => {
      const text = readFileSync(join(SRC, root, f), 'utf8')
      const file = relative(SRC, join(SRC, root, f)).split('\\').join('/')
      const labels = [...text.matchAll(BUTTON_CONTENT)].map((m) => m[1]!)
      return [...text.matchAll(TOPIC)]
        .filter((m) => {
          const topic = m[1]!.trim()
          const word = new RegExp(`(^|[^\\w.'])${escape(topic)}($|[^\\w'(])`)
          return topic !== '' && labels.some((l) => word.test(l.trim()))
        })
        .map((m) => `${file}:${text.slice(0, m.index).split('\n').length} ${m[1]!.trim()}`)
    }))
}

describe('InfoTip name guard: an ⓘ is not named after the button beside it', () => {
  const found = hits()

  it('reports the count of the class', () => {
    // before this guard: 5 (findings "Applied" and "Ask my AI", the bug report's "Open GitHub issue", the VulnCheck key's
    // "Remove key", the credentialed scan's "Add a server"); after: 0
    console.info(`InfoTips named after a button: ${found.length}`)
    expect(found.length).toBeGreaterThanOrEqual(0)
  })

  it('no InfoTip topic is the label of a button in the same file', () => {
    expect(found, 'Give the ⓘ the name of the hint it explains, or no topic ("More about this")').toEqual([])
  })

  it('the scan finds a known case', () => {
    const sample = `<Button onClick={() => go()}>{t('x.go')}</Button><InfoTip topic={t('x.go')}>why</InfoTip>`
    expect([...sample.matchAll(BUTTON_CONTENT)].map((m) => m[1])).toEqual(["t('x.go')"])
    expect([...sample.matchAll(TOPIC)].map((m) => m[1])).toEqual(["t('x.go')"])
  })
})
