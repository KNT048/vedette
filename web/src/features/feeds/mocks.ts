// Mock API module feeds (S-FEED-1/2/3). Bảng nóng tính từ KEV THẬT (src/mocks/fixtures/kev.json, `pnpm fixtures`).
// Cửa sổ 24h/7 ngày tính theo thời điểm dữ liệu được kéo, để bản mẫu vẫn có nghĩa khi mở vài ngày sau.
import { http, HttpResponse } from 'msw'
import kev from '@/mocks/fixtures/kev.json'
import { API, audit, body, fail, guard, IPV4_RE } from '@/mocks/http'
import { assetsStore, isOn } from '@/mocks/stores'
import { collection, newId, nowIso } from '@/mocks/db'
import { epssDate, kevPublished, tierFact, tierOf, tierState, withinYear } from '@/mocks/tiers'
import type { Asset, AssetKind } from '@/lib/types'
import { actsAs } from '@/lib/deviceTypes'
import { feedOn, kevStatus, sourceHandlers } from './sourcesMock'
import { FEED_DOMAIN_RE } from './parsers'
import { displayOf, keyOf, kindOf } from './slug'
import { briefOfTier, briefOfVuln, esxiBrief } from './briefSamples'
import type { CveDetail, FeedStatus, HotRow, IocHit, MatchedAsset, SearchResult, TierCve, Vuln, WeeklyItem, YouHave } from './types'


const data = kev as { generated_at: string; kev_catalog_version: string; sources: FeedStatus['sources']; vulns: Vuln[] }
const ref = new Date(data.generated_at).getTime()
const inWindow = (v: Vuln, hours: number, end: number) => new Date(`${v.date_added}T23:59:59Z`).getTime() >= end - hours * 36e5 && new Date(`${v.date_added}T00:00:00Z`).getTime() <= end // a date after now is not counted

const weeklyAnswers = collection<Record<string, 'have' | 'not_relevant'>>('feeds_weekly_answers', () => ({}))

// IOC mẫu cho tra cứu (S-FEED-3). Bản thật: feeds/ioc/* từ builder (DATA_PIPELINE §2b).
const IOCS: Omit<IocHit, 'sources'>[] = [
  { value: '185.220.101.47', type: 'ip', category: 'Tor exit node, SSH scanning', score: 0.92, first_seen: '2026-09-12', last_seen: '2026-11-05', verdict: 'block' },
  { value: '45.148.10.95', type: 'ip', category: 'VPN vulnerability scanner', score: 0.81, first_seen: '2026-10-20', last_seen: '2026-11-04', verdict: 'block' },
  { value: '103.75.190.12', type: 'ip', category: 'RDP password guessing', score: 0.55, first_seen: '2026-10-30', last_seen: '2026-11-05', verdict: 'alert' },
  { value: 'update-dsm-synology.com', type: 'domain', category: 'Fake NAS update page', score: 0.88, first_seen: '2026-10-29', last_seen: '2026-11-05', verdict: 'block' },
  { value: 'cdn-telemetry-sync.net', type: 'domain', category: 'Malware command-and-control server', score: 0.7, first_seen: '2026-10-02', last_seen: '2026-11-01', verdict: 'alert' },
]

// The built-in feeds that list each sample indicator (id, name as shown). Like the box, a lookup names only feeds that are on, and an
// indicator that no feed that is on lists is not found (POST-4).
const LISTED: Record<string, [string, string][]> = {
  '185.220.101.47': [['tor-exit', 'Tor exit list'], ['ipsum', 'IPsum (8 sources)']],
  '45.148.10.95': [['et-open', 'ET Open compromised'], ['ipsum', 'IPsum (5 sources)']],
  '103.75.190.12': [['ipsum', 'IPsum (3 sources)']],
  'update-dsm-synology.com': [['hagezi-tif', 'hagezi TIF']],
  'cdn-telemetry-sync.net': [['hagezi-tif', 'hagezi TIF']],
}
function iocHit(value: string): IocHit | null {
  const base = IOCS.find((i) => i.value === value)
  const sources = (LISTED[value] ?? []).filter(([id]) => feedOn(id)).map(([, label]) => label)
  return base && sources.length ? { ...base, sources } : null
}

function matchAssets(vendor: string, product: string): MatchedAsset[] {
  const key = keyOf(vendor, product)
  const multi = product.toLowerCase() === 'multiple products'
  const out: MatchedAsset[] = []
  for (const a of assetsStore.get()) {
    let how: YouHave = 'no'
    for (const s of a.software) {
      if (!multi && s.kev.includes(key)) { how = 'yes'; break }
      if (multi && s.kev.some((k) => k.startsWith(`${vendor.toLowerCase()}|`))) how = 'maybe'
    }
    if (how !== 'no') out.push({ id: a.id, hostname: a.name ?? a.hostname, ip: a.ip, display: a.software[0]?.display ?? a.kind, how })
  }
  return out
}

/** The newly exploited board (Home, S-FEED-1); the weekly report mock counts from it too. `end` moves the window back for older weeks. */
export function hotRows(hours: number, end = ref): HotRow[] {
  const youHave = (matched: MatchedAsset[]): YouHave => (matched.some((m) => m.how === 'yes') ? 'yes' : matched.length ? 'maybe' : 'no')
  const inv = isOn('inventory')
  const groups = new Map<string, Vuln[]>()
  for (const v of data.vulns.filter((x) => inWindow(x, hours, end))) {
    const k = keyOf(v.vendor, v.product)
    groups.set(k, [...(groups.get(k) ?? []), v])
  }
  return [...groups.entries()].map(([key, vs]) => {
    const first = vs[0]!
    const matched = inv ? matchAssets(first.vendor, first.product) : []
    const epss = vs.map((v) => v.epss).filter((n): n is number => n !== null)
    // Δ7 ngày chỉ khi có điểm của 7 ngày trước (CVE mới chưa có điểm cũ thì không tính là tăng).
    const deltas = vs.map((v) => (v.epss === null || v.epss_7d_ago === null ? null : v.epss - v.epss_7d_ago)).filter((n): n is number => n !== null)
    return {
      key, vendor: first.vendor, product: first.product, display: displayOf(first.vendor, first.product),
      cves: vs.map((v) => ({ cve: v.cve, date_added: v.date_added, ransomware: v.ransomware, epss: v.epss, has_template: v.has_template })),
      max_epss: epss.length ? Math.max(...epss) : null,
      max_epss_delta: deltas.length ? Math.max(...deltas) : null,
      has_template: vs.some((v) => v.has_template),
      ransomware: vs.some((v) => v.ransomware),
      you_have: inv ? youHave(matched) : null,
      matched_assets: matched.map((m) => m.id),
    }
  }).sort((a, b) => Number(b.you_have === 'yes') - Number(a.you_have === 'yes') || b.cves.length - a.cves.length || (b.max_epss ?? 0) - (a.max_epss ?? 0))
}

/** Câu sinh bằng template, không cần AI (DATA_PIPELINE §3, S-FEED-2). Tiếng Anh. */
function weekly(): WeeklyItem[] {
  const answers = weeklyAnswers.get()
  const seen = new Set<string>()
  const items: WeeklyItem[] = []
  for (const v of data.vulns) {
    const key = keyOf(v.vendor, v.product)
    if (seen.has(key) || v.cve === 'CVE-2022-27593') continue
    seen.add(key)
    const d = new Date(`${v.date_added}T00:00:00`).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })
    const text = `${displayOf(v.vendor, v.product)} has a vulnerability ${v.ransomware ? 'that ransomware groups are exploiting' : 'that is being exploited in the wild'} (added to the CISA list on ${d}). If your company uses it, update it following the advisory from ${v.vendor} this week.`
    items.push({ id: key, key, cve: v.cve, date_added: v.date_added, answer: answers[key] ?? null, text })
    if (items.length >= 8) break
  }
  return items
}

export const handlers = [
  ...sourceHandlers,
  http.get(`${API}/feeds/status`, () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json({ generated_at: data.generated_at, kev_catalog_version: data.kev_catalog_version, sources: data.sources, inventory_on: isOn('inventory'), kev: kevStatus() } satisfies FeedStatus)
  }),

  http.get(`${API}/feeds/hot`, ({ request }) => {
    const denied = guard('viewer'); if (denied) return denied
    const w = new URL(request.url).searchParams.get('window')
    if (w !== '24h' && w !== '7d') return fail(400, 'bad_window', 'window must be 24h or 7d.')
    const latest = data.vulns[0]
    return HttpResponse.json({ window: w, rows: hotRows(w === '24h' ? 24 : 24 * 7), latest: latest ? { cve: latest.cve, date_added: latest.date_added, display: displayOf(latest.vendor, latest.product) } : null })
  }),

  http.get(`${API}/feeds/weekly`, () => {
    const denied = guard('viewer'); if (denied) return denied
    return HttpResponse.json({ items: weekly() })
  }),

  // "Tôi có" → thêm thiết bị khai tay để nhận cảnh báo (S-FEED-2 → S-INV-2). "Không liên quan" → ẩn.
  http.post(`${API}/feeds/weekly/:id`, async ({ params, request }) => {
    const denied = guard('operator'); if (denied) return denied
    const id = decodeURIComponent(String(params.id))
    const item = weekly().find((w) => w.id === id)
    if (!item) return fail(404, 'not_found', 'No such item.')
    const b = await body<{ answer: 'have' | 'not_relevant' }>(request)
    if (b.answer !== 'have' && b.answer !== 'not_relevant') return fail(400, 'bad_answer', 'answer must be have or not_relevant.')
    weeklyAnswers.update((m) => ({ ...m, [id]: b.answer! }))
    if (b.answer === 'have' && isOn('inventory')) {
      const v = data.vulns.find((x) => x.cve === item.cve)!
      const now = nowIso()
      const asset: Asset = {
        id: newId('a'), site: 'hq', ip: '—', mac: null, hostname: null, kind: (['pc', 'server', 'web'].includes(actsAs(kindOf(item.key))) ? 'unknown' : kindOf(item.key)) as AssetKind /* no device, no computer type */, vendor: { value: v.vendor, source: 'manual', confidence: 1, seen_at: now },
        model: null, os: null, services: [], first_seen: now, last_seen: now, approved: true, fragile: false, origin: 'manual',
        software: [{ id: newId('s'), display: displayOf(v.vendor, v.product), vendor: v.vendor, product: v.product, version: null, kev: [item.key], source: 'manual', confidence: 1 }],
      }
      assetsStore.update((l) => [asset, ...l])
      audit('inventory.add_manual', displayOf(v.vendor, v.product), 'from "This week"')
    }
    return HttpResponse.json({ items: weekly() })
  }),

  // The brief of any CVE the catalogue holds (feeds.Brief): an exploited-list entry, the full ESXi sample, or a tier CVE of the last
  // 12 months; "Do you have it?" only for a CVE on a list (by its product, as on Home).
  http.get(`${API}/feeds/cve/:id`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    const id = String(params.id).toUpperCase()
    const v = data.vulns.find((x) => x.cve === id)
    const f = tierFact(id)
    const brief = v ? briefOfVuln(v, kevPublished(v.cve)) : id === esxiBrief.cve ? esxiBrief : f && tierState.get().recent === 'ready' && withinYear(f) ? briefOfTier(f) : null
    if (!brief) return fail(404, 'not_in_data', 'The vulnerability data on this box does not hold this CVE.')
    const entry = brief.lists[0]
    const matched = entry && isOn('inventory') ? matchAssets(entry.vendor, entry.product) : null
    return HttpResponse.json({ ...brief, matched, not_affected: 0 } satisfies CveDetail)
  }),

  // S-TIER-1: a CVE on no exploited list, from the tier data (epss-all, nvd-recent).
  http.get(`${API}/feeds/cve/:id/tier`, ({ params }) => {
    const denied = guard('viewer'); if (denied) return denied
    const id = String(params.id).toUpperCase()
    const f = tierFact(id)
    const st = tierState.get()
    const recent = st.recent === 'ready' && f && withinYear(f) ? f : null
    const epss = st.epss === 'ready' && f ? f : null
    if (!recent && !epss) return fail(404, 'not_in_data', 'This CVE is not on an exploited list, and the EPSS and NVD data on this box do not hold it.')
    const r: TierCve = {
      cve: id, tier: recent ? tierOf(recent) : null, published: recent?.published ?? null, last_modified: recent?.last_modified ?? null, nvd_status: recent?.nvd_status ?? null,
      severity: recent?.severity ?? null, score: recent?.score ?? null, epss: epss?.epss ?? null, percentile: epss?.percentile ?? null, epss_date: epss ? epssDate() : null,
      products: recent?.products ?? [], ranges: recent?.ranges ?? false,
    }
    return HttpResponse.json(r)
  }),

  http.get(`${API}/feeds/search`, ({ request }) => {
    const denied = guard('viewer'); if (denied) return denied
    const q = (new URL(request.url).searchParams.get('q') ?? '').trim().slice(0, 200)
    if (!q) return fail(400, 'empty_query', 'Enter a CVE, product name, IP or domain.')
    let r: SearchResult
    if (/^cve-\d{4}-\d{4,}$/i.test(q)) r = { kind: 'cve', cve: q.toUpperCase(), found: data.vulns.some((v) => v.cve === q.toUpperCase()) }
    else if (IPV4_RE.test(q) || FEED_DOMAIN_RE.test(q)) r = { kind: 'ioc', value: q.toLowerCase(), type: IPV4_RE.test(q) ? 'ip' : 'domain', hit: iocHit(q.toLowerCase()) }
    else {
      const t = q.toLowerCase()
      r = { kind: 'text', q, vulns: data.vulns.filter((v) => `${v.vendor} ${v.product} ${v.name} ${displayOf(v.vendor, v.product)}`.toLowerCase().includes(t)).map((v) => ({ ...v, display: displayOf(v.vendor, v.product) })) }
    }
    return HttpResponse.json(r)
  }),
]
