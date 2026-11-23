import { describe, expect, it } from 'vitest'

// The product is English only. There is no vi folder any more; no string in en has Vietnamese diacritics.
const en = import.meta.glob<{ default: Record<string, unknown> }>('../locales/en/*.json', { eager: true })
const vi = import.meta.glob('../locales/vi/*.json')
const VI = /[ăâđêôơưạảấầẩẫậắằẳẵặẹẻẽếềểễệỉịọỏốồổỗộớờởỡợụủứừửữựỳỵỷỹ]/i
function strings(o: unknown, p = ''): [string, string][] {
  if (typeof o === 'string') return [[p, o]]
  if (o && typeof o === 'object') return Object.entries(o).flatMap(([k, v]) => strings(v, p ? `${p}.${k}` : k))
  return []
}

describe('i18n (English only)', () => {
  it('no Vietnamese locale files remain', () => {
    expect(Object.keys(vi)).toEqual([])
  })
  for (const [file, mod] of Object.entries(en)) {
    it(`${file.split('/').pop()} has no Vietnamese text`, () => {
      expect(strings(mod.default).filter(([, s]) => VI.test(s)).map(([k, s]) => `${k}: ${s}`)).toEqual([])
    })
  }
})
