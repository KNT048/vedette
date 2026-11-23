// i18n: the product is English only. i18next + t() keep the strings in src/locales/en/<ns>.json (one namespace per module) so that
// a language can be added later without touching a component.
//
// `common` and `core` ship in the first bundle (the shell, sign-in and setup use them). Every other namespace is its own chunk,
// fetched the first time something asks for it: a route's feature namespace loads together with the route chunk (app/feature.ts),
// and a component that asks for a namespace that is not there yet suspends until it arrives (react-i18next), so a raw key never shows.
import i18n, { type BackendModule } from 'i18next'
import { initReactI18next } from 'react-i18next'
import common from '../locales/en/common.json'
import core from '../locales/en/core.json'

const loaders = import.meta.glob<{ default: Record<string, unknown> }>('../locales/en/*.json')

const byName: Record<string, () => Promise<{ default: Record<string, unknown> }>> = {}
for (const [path, load] of Object.entries(loaders)) {
  const ns = path.match(/locales\/en\/([\w-]+)\.json$/)?.[1]
  if (ns) byName[ns] = load
}

const lazyBackend: BackendModule = {
  type: 'backend',
  init() {},
  read(_lng, ns, callback) {
    const load = byName[ns]
    if (!load) return callback(new Error(`no locale file for namespace "${ns}"`), null)
    load().then((m) => callback(null, m.default), (e: unknown) => callback(e instanceof Error ? e : new Error(String(e)), null))
  },
}

void i18n.use(lazyBackend).use(initReactI18next).init({
  resources: { en: { common, core } },
  partialBundledLanguages: true, // some namespaces are bundled above, the rest come from the backend
  lng: 'en',
  fallbackLng: 'en',
  defaultNS: 'common',
  ns: ['common', 'core'],
  interpolation: { escapeValue: false },
  returnNull: false,
  react: { bindI18nStore: 'added' }, // a component that asked for a key before its namespace arrived re-renders when it does
  // A key of a namespace that is still on its way (a t('inventory:…') in a screen of another feature) loads it; the component re-renders when it lands.
  parseMissingKeyHandler: (key, defaultValue) => {
    const ns = key.includes(':') ? key.slice(0, key.indexOf(':')) : undefined
    if (ns && byName[ns] && !i18n.hasLoadedNamespace(ns)) void i18n.loadNamespaces(ns)
    return defaultValue ?? key
  },
})

/** Loads namespaces (a no-op for the ones already there). Resolves also when a file is missing, so a navigation never hangs on it. */
export function loadNamespaces(ns: string | readonly string[]): Promise<void> {
  const list = (Array.isArray(ns) ? ns : [ns]).filter((n) => byName[n])
  return i18n.loadNamespaces(list).then(() => undefined, () => undefined)
}

/** Namespace of a "ns:key" label, if it has one. */
export const nsOfKey = (key: string) => (key.includes(':') ? key.slice(0, key.indexOf(':')) : undefined)

/** Every namespace, loaded now: tests and tools that render any screen synchronously. */
export function loadAllNamespaces(): Promise<void> {
  return loadNamespaces(Object.keys(byName))
}

export default i18n
