// The data store of the mock API. Browser: kept in localStorage so what the user typed survives a reload;
// tests: in memory only. The "Restore sample data" button in Settings calls resetMockDb().
// Change the number when the data structure stored in the browser changes incompatibly: every browser starts clean again.
// v2: English. v3: response, Incidents, channels with an approver (2026-11-09). v4: table names by module prefix.
const KEY = 'vedette-mock-db-v4'
const persist = typeof window !== 'undefined' && import.meta.env.MODE !== 'test'

let cache: Record<string, unknown> | null = null
function load(): Record<string, unknown> {
  if (cache) return cache
  cache = {}
  if (persist) {
    try { cache = JSON.parse(localStorage.getItem(KEY) ?? '{}') as Record<string, unknown> } catch { cache = {} }
  }
  return cache
}
function save() {
  if (!persist || !cache) return
  try { localStorage.setItem(KEY, JSON.stringify(cache)) } catch { /* storage full: ignore, the data stays in the session */ }
}

export interface Collection<T> { get(): T; set(v: T): void; update(fn: (v: T) => T): T }

// Data mode: 'sample' = the preview with sample data (default); 'clean' = a real install, every table starts empty
// (the user declares devices, configures channels...). Initial setup picks the mode; "Delete all data" goes back to unset.
const MODE = '__mode'
export type DataMode = 'sample' | 'clean'
export const dataMode = (): DataMode => (load()[MODE] === 'clean' ? 'clean' : 'sample')
export function setDataMode(m: DataMode) { load()[MODE] = m; save() }

/**
 * A mock "table". `seed` runs only when there is no data yet. Name = the module prefix (modules rule).
 * `empty`: the value on a clean install. Required for a table that holds SAMPLE DATA (devices, events, history...);
 * leave it out for a table that only holds defaults that make sense for a real user.
 */
export function collection<T>(name: string, seed: () => T, empty?: () => T): Collection<T> {
  return {
    get() {
      const db = load()
      if (!(name in db)) { db[name] = dataMode() === 'clean' && empty ? empty() : seed(); save() }
      return db[name] as T
    },
    set(v) { load()[name] = v; save() },
    update(fn) { const v = fn(this.get()); this.set(v); return v },
  }
}

/** Read a table WITHOUT seeding data (undefined if absent). Used for cross-module reads in the mock. */
export function peek<T>(name: string): T | undefined {
  return load()[name] as T | undefined
}

export function resetMockDb() {
  cache = {}
  if (persist) { try { localStorage.removeItem(KEY) } catch { /* ignore */ } }
}

let seq = 0
export function newId(prefix: string) {
  seq += 1
  return `${prefix}-${Date.now().toString(36)}${seq.toString(36)}`
}

export const nowIso = () => new Date().toISOString()
export const daysAgo = (d: number, h = 0) => new Date(Date.now() - d * 864e5 - h * 36e5).toISOString()
