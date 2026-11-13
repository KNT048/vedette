// The Go backend (modules/inventory/catalog.go) ports searchCatalog/findCatalog. Both read the same data files and
// must give the same answers: content/catalog/search-golden.json is the shared proof (the Go test judges it too).
// After changing curated.json, kev-products.json or the search code, regenerate with
// `pnpm --dir web exec vitest run -u src/features/inventory/catalog.golden.test.ts`, then run `go test ./modules/inventory`.
import { describe, expect, it } from 'vitest'
import { findCatalog, searchCatalog } from './catalog'

const QUERIES = ['', 'forti', 'fortigate 60f', 'synology', 'windows server 2019', 'tuong lua', 'cisco asa', 'wordpress', 'office', 'qnap', 'zzzzqq', 'microsoft', 'apache', 'hikvision', 'camera', 'nas', 'vpn', 'ivanti', 'sophos', 'tường lửa', 'ms exchange', '  FortiGate  ', 'a', 'juniper ex']
const FINDS = ['FortiGate', 'Synology NAS (DSM)', 'wordpress', 'Microsoft Office', 'kev:fortinet:fortios', 'nothing like this', '', 'apache http server', 'Dns', 'Synology', 'php', 'Exchange Server']

function compute() {
  return {
    search: QUERIES.map((q) => { const r = searchCatalog(q, 30); return { q, total: r.total, items: r.items.map((e) => ({ id: e.id, kev_count: e.kev_count, kev: e.kev })) } }),
    find: FINDS.map((text) => ({ text, id: findCatalog(text)?.id ?? null })),
  }
}

describe('catalog golden file shared with the Go backend', () => {
  it('matches content/catalog/search-golden.json', async () => {
    await expect(JSON.stringify(compute(), null, 1) + '\n').toMatchFileSnapshot('../../../../content/catalog/search-golden.json')
  })
})
