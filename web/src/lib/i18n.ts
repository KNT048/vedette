// i18n: sản phẩm chỉ có tiếng Anh (D-28). Giữ i18next + t() để chuỗi tập trung ở src/locales/en/<ns>.json
// (mỗi module một namespace) và để thêm ngôn ngữ sau này mà không sửa component.
import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

const files = import.meta.glob<{ default: Record<string, unknown> }>('../locales/en/*.json', { eager: true })
const en: Record<string, Record<string, unknown>> = {}
for (const [path, mod] of Object.entries(files)) {
  const ns = path.match(/locales\/en\/([\w-]+)\.json$/)?.[1]
  if (ns) en[ns] = mod.default
}

void i18n.use(initReactI18next).init({
  resources: { en },
  lng: 'en',
  fallbackLng: 'en',
  defaultNS: 'common',
  ns: Object.keys(en),
  interpolation: { escapeValue: false },
  returnNull: false,
})

export default i18n
