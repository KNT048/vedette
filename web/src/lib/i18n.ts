// i18n: the product is English only. Keep i18next + t() so strings stay centralised in src/locales/en/<ns>.json
// (one namespace per module) and so a language can be added later without changing components.
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
