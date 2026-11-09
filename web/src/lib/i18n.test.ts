import { describe, expect, it } from 'vitest'

// D-28: sản phẩm chỉ có tiếng Anh. Không còn thư mục vi; không chuỗi nào trong en có dấu tiếng Việt.
const en = import.meta.glob<{ default: Record<string, unknown> }>('../locales/en/*.json', { eager: true })
const vi = import.meta.glob('../locales/vi/*.json')
const VI = /[ăâđêôơưạảấầẩẫậắằẳẵặẹẻẽếềểễệỉịọỏốồổỗộớờởỡợụủứừửữựỳỵỷỹ]/i
function strings(o: unknown, p = ''): [string, string][] {
  if (typeof o === 'string') return [[p, o]]
  if (o && typeof o === 'object') return Object.entries(o).flatMap(([k, v]) => strings(v, p ? `${p}.${k}` : k))
  return []
}

describe('i18n (D-28: English only)', () => {
  it('no Vietnamese locale files remain', () => {
    expect(Object.keys(vi)).toEqual([])
  })
  for (const [file, mod] of Object.entries(en)) {
    it(`${file.split('/').pop()} has no Vietnamese text`, () => {
      expect(strings(mod.default).filter(([, s]) => VI.test(s)).map(([k, s]) => `${k}: ${s}`)).toEqual([])
    })
  }
})
