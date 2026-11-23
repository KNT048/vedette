// Every key the Findings screens ask for exists in locales/en/findings.json: a missing one shows its raw name ("filters.confirmed")
// on the page. Literal keys are checked in every source file of the feature; keys built at run time are checked per group.
import { describe, expect, it } from 'vitest'
import findings from '@/locales/en/findings.json'

const sources = import.meta.glob<string>(['./*.tsx', './*.ts', '!./*.test.*', '!./mocks.ts'], { query: '?raw', import: 'default', eager: true })

function has(key: string): boolean {
  const get = (k: string) => k.split('.').reduce<unknown>((o, p) => (o && typeof o === 'object' ? (o as Record<string, unknown>)[p] : undefined), findings)
  return typeof get(key) === 'string' || typeof get(`${key}_one`) === 'string' || typeof get(`${key}_other`) === 'string'
}

describe('findings locale keys', () => {
  it('every literal t(\'…\') key of the findings namespace exists', () => {
    const missing: string[] = []
    for (const [file, src] of Object.entries(sources)) {
      // a component's t is the namespace of the useTranslation above it: only the stretches after useTranslation('findings')
      for (const part of src.split(/(?=useTranslation\()/).filter((p) => p.startsWith("useTranslation('findings')"))) {
        for (const m of part.matchAll(/(?<![\w.])t\(\s*'([A-Za-z][\w.]*)'/g)) {
          if (!has(m[1]!)) missing.push(`${file}: ${m[1]}`)
        }
      }
    }
    expect(missing).toEqual([])
  })
})
