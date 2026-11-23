// The Go backend (modules/inventory/catalog.go) ports searchCatalog/findCatalog. Both read the same data files and
// must give the same answers: content/catalog/search-golden.json is the shared proof (the Go test judges it too).
// After changing curated.json, kev-products.json or the search code, regenerate with
// `pnpm --dir web exec vitest run -u src/features/inventory/catalog.golden.test.ts`, then run `go test ./modules/inventory`.
import { describe, expect, it } from 'vitest'
import curatedData from '../../../../content/catalog/curated.json'
import kevProducts from '../../../../content/catalog/kev-products.json'
import { customEntry, findCatalog, fragmentMatch, searchCatalog } from './catalog'

const QUERIES = ['', 'forti', 'fortigate 60f', 'synology', 'windows server 2019', 'tuong lua', 'cisco asa', 'wordpress', 'office', 'qnap', 'zzzzqq', 'microsoft', 'apache', 'hikvision', 'camera', 'nas', 'vpn', 'ivanti', 'sophos', 'tường lửa', 'ms exchange', '  FortiGate  ', 'a', 'juniper ex']
const FINDS = ['FortiGate', 'Synology NAS (DSM)', 'wordpress', 'Microsoft Office', 'kev:fortinet:fortios', 'nothing like this', '', 'apache http server', 'Dns', 'Synology', 'php', 'Exchange Server', 'jdk', 'JRE', 'java', 'openjdk', 'iOS', 'NAS', 'USG', 'Backup', 'Web Server', 'Linux', 'linux', 'Ubuntu', 'rhel']
// A product a person typed (maker, product): the exploited products it is matched by, as the server's custom entry gives them.
const CUSTOM: [string, string][] = [['Red Hat', 'OpenJDK'], ['Fortinet', 'FortiGate'], ['Eclipse Adoptium', 'Temurin'], ['Acme', 'Widget Server'], ['Acme', 'FortiOS'], ['Cisco', 'PAN-OS']]

function compute() {
  return {
    search: QUERIES.map((q) => { const r = searchCatalog(q, 30); return { q, total: r.total, items: r.items.map((e) => ({ id: e.id, kev_count: e.kev_count, kev: e.kev })) } }),
    find: FINDS.map((text) => ({ text, id: findCatalog(text)?.id ?? null })),
    custom: CUSTOM.map(([vendor, product]) => { const e = customEntry(vendor, product); return { vendor, product, kev: [...e.kev].sort(), kev_count: e.kev_count } }),
  }
}

describe('catalog golden file shared with the Go backend', () => {
  it('matches content/catalog/search-golden.json', async () => {
    await expect(JSON.stringify(compute(), null, 1) + '\n').toMatchFileSnapshot('../../../../content/catalog/search-golden.json')
  })
})

// Every fragment of curated.json against every exploited-list name: the Go rule (core/productid/fragment.go) must give the same
// pairs (modules/inventory TestFragmentMatch_ParityWithTheWeb reads this file).
describe('kev_match fragments shared with the Go backend', () => {
  it('matches content/catalog/fragment-parity.txt', async () => {
    const fragments = [...new Set((curatedData as { kev_match?: string[] }[]).flatMap((r) => r.kev_match ?? []))]
    const lines = fragments.flatMap((f) => (kevProducts as { vendor: string; product: string }[]).filter((r) => fragmentMatch(f, r.vendor, r.product)).map((r) => `${f} => ${`${r.vendor}|${r.product}`.toLowerCase()}`))
    lines.sort()
    await expect(lines.join('\n') + '\n').toMatchFileSnapshot('../../../../content/catalog/fragment-parity.txt')
  })
})
