// Danh mục sản phẩm cho khai tay (S-INV-2). Hai nguồn, gộp một danh sách:
// 1) TOÀN BỘ cặp hãng/sản phẩm từng có trong CISA KEV (content/catalog/kev-products.json, sinh bằng `pnpm fixtures`; backend Go nhúng cùng file) — mỗi cặp chọn được,
//    khoá khớp là đúng `hãng|sản phẩm` viết thường của KEV nên cảnh báo khớp chính xác. Nguồn: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (CC0).
// 2) Danh sách tuyển chọn: sản phẩm doanh nghiệp nhỏ ở Việt Nam hay dùng, gọi bằng tên thương mại. Mỗi mục trỏ tới khoá KEV thật (kevMatch) nếu KEV có,
//    không thì dùng khoá kiểu CPE `hãng|sản phẩm` (chưa có lỗ hổng bị khai thác nhưng khi có sẽ khớp). Bản thật: sinh từ feeds/cpe-dict (DATA_PIPELINE §3).
// Id ổn định: mục tuyển chọn có id cố định; mục KEV có id `kev:<hãng>:<sản phẩm>` (slug).
import kevProducts from '../../../../content/catalog/kev-products.json'
import curatedData from '../../../../content/catalog/curated.json'
import type { AssetKind } from '@/lib/types'

export interface CatalogEntry {
  id: string; display: string; category: string; hint: string; vendor: string; product: string; kind: AssetKind
  kev: string[]; aliases: string[]; version_hint: string; kev_count: number; curated: boolean; order: number
}

interface KevRow { vendor: string; product: string; kev_count: number; last_added: string; ransomware: boolean }
const KEV = kevProducts as KevRow[]
const kevKey = (r: { vendor: string; product: string }) => `${r.vendor}|${r.product}`.toLowerCase()
const kevCountOf = new Map(KEV.map((r) => [kevKey(r), r.kev_count]))

/** Bỏ dấu, hạ chữ thường, mọi ký tự lạ thành khoảng trắng: "Tường lửa FortiGate-60F" → "tuong lua fortigate 60f". */
export const fold = (s: string) => s.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '').replace(/đ/g, 'd').replace(/[^a-z0-9]+/g, ' ').trim()
const slug = (s: string) => fold(s).replace(/ /g, '-')

const OTHER = 'Other'

type K = AssetKind
/** content/catalog/curated.json: ONE data source for the web and the Go backend (modules/inventory embeds the same file). Array order = popularity. */
interface CuratedRow { display: string; category: string; kind: K; vendor: string; product: string; aliases: string; version_hint: string; kev_match?: string[] }
const CURATED = curatedData as CuratedRow[]

function kevKeysFor(matches: string[] | undefined, fallback: string): string[] {
  if (!matches?.length) return [fallback]
  const keys = new Set<string>()
  for (const m of matches) {
    const [v = '', p = ''] = m.toLowerCase().split('|')
    for (const r of KEV) if (r.vendor.toLowerCase().includes(v) && (!p || r.product.toLowerCase().includes(p))) keys.add(kevKey(r))
  }
  return keys.size ? [...keys] : [fallback]
}
const sumKev = (keys: string[]) => keys.reduce((n, k) => n + (kevCountOf.get(k) ?? 0), 0)

const curated: CatalogEntry[] = CURATED.map(({ display, category, kind, vendor, product, aliases, version_hint, kev_match }, i) => {
  const kev = kevKeysFor(kev_match, `${vendor}|${product}`.toLowerCase())
  return {
    id: slug(display), display, category, hint: `${vendor} ${product}`, vendor, product, kind, kev,
    aliases: aliases.split(',').map((s) => s.trim()).filter(Boolean), version_hint, kev_count: sumKev(kev), curated: true, order: i,
  }
})

// Đoán loại thiết bị từ tên khi KEV không nói; sai thì người dùng đổi loại ở trang chi tiết.
const KIND_HINT: [RegExp, K][] = [
  [/firewall|fortios|pan-os|asa|sonicos|firebox|utm/i, 'firewall'], [/router|routeros|vigor|archer|wan vpn/i, 'router'], [/switch/i, 'switch'],
  [/access point|\bwap\b|wireless|wifi/i, 'ap'], [/nas\b|storage|diskstation|qts/i, 'nas'], [/camera|ipc|dvr|surveillance/i, 'camera'], [/nvr/i, 'nvr'],
  [/printer|mfp|laserjet/i, 'printer'], [/wordpress|joomla|drupal|cms|plugin|wiki|webmail|\bphp\b|struts|laravel|magento/i, 'web'],
  [/windows|macos|ios|chrome|firefox|office|reader|acrobat|winrar|7-zip|desktop|client/i, 'pc'], [/phone|mobile|android|\biot\b/i, 'iot'],
]
const autoById = new Map<string, CatalogEntry>()
for (const [i, r] of KEV.entries()) {
  const key = kevKey(r)
  const id = `kev:${slug(r.vendor)}:${slug(r.product)}`
  const dup = autoById.get(id)
  // Hai dòng KEV chỉ khác nhau ở khoảng trắng lạ (ví dụ "Commerce and Magento") là cùng một sản phẩm: một mục, giữ cả hai khoá khớp.
  if (dup) { dup.kev.push(key); dup.kev_count += r.kev_count; continue }
  const display = r.product.toLowerCase().startsWith(r.vendor.toLowerCase()) ? r.product : `${r.vendor} ${r.product}`
  const kind = KIND_HINT.find(([re]) => re.test(`${r.product} ${r.vendor}`))?.[1] ?? 'server'
  autoById.set(id, {
    id, display, category: OTHER, hint: `${r.vendor}, ${r.product}`, vendor: r.vendor, product: r.product, kind,
    kev: [key], aliases: [], version_hint: 'The version shown in the product, its About page or its admin console.', kev_count: r.kev_count, curated: false, order: 1000 + i,
  })
}
const auto = [...autoById.values()]

export const CATALOG: CatalogEntry[] = [...curated, ...auto]
export const findById = (id: string | undefined) => (id ? CATALOG.find((e) => e.id === id) : undefined)

const HAY = new Map(CATALOG.map((e) => [e.id, {
  name: fold(e.display), vendor: fold(e.vendor), product: fold(e.product), cat: fold(e.category), al: e.aliases.map(fold),
  all: fold(`${e.display} ${e.vendor} ${e.product} ${e.category} ${e.aliases.join(' ')}`),
}]))

const wordsOf = (s: string) => s.split(' ').filter(Boolean)

/** Xếp hạng: khớp đúng tên > đầu tên > từ đầu trong tên > bí danh/hãng > loại; mục tuyển chọn và mục có nhiều lỗ hổng bị khai thác lên trước. */
function score(e: CatalogEntry, terms: string[]): number {
  const h = HAY.get(e.id)!
  const nameWords = wordsOf(h.name)
  let total = 0
  let matched = 0
  const q = terms.join(' ')
  if (h.name === q) total += 200
  else if (h.name.startsWith(q)) total += 120
  for (const t of terms) {
    let s = 0
    if (nameWords.some((w) => w === t)) s = 40
    else if (nameWords.some((w) => w.startsWith(t))) s = 32
    else if (h.al.some((a) => a === t || wordsOf(a).includes(t))) s = 30
    else if (h.al.some((a) => a.startsWith(t) || wordsOf(a).some((w) => w.startsWith(t)))) s = 24
    else if (wordsOf(h.vendor).some((w) => w.startsWith(t))) s = 22
    else if (wordsOf(h.product).some((w) => w.startsWith(t))) s = 20
    else if (h.cat.includes(t)) s = 8
    else if (t.length >= 3 && h.all.includes(t)) s = 5
    if (s) matched++
    total += s
  }
  // Số model, phiên bản ("60f", "2019") không cần khớp, miễn có ít nhất một từ chữ khớp.
  const unmatched = terms.length - matched
  const unmatchedOnlyNumbers = terms.filter((t) => !HAY.get(e.id)!.all.includes(t)).every((t) => /\d/.test(t))
  if (unmatched > 0 && !(matched > 0 && unmatchedOnlyNumbers)) return 0
  if (matched === 0) return 0
  return total + (e.curated ? 15 - Math.min(e.order, 150) / 10 : 0) + Math.min(e.kev_count, 50) / 10
}

export interface SearchResult { items: CatalogEntry[]; total: number }

export function searchCatalog(q: string, limit = 30): SearchResult {
  const terms = wordsOf(fold(q))
  if (!terms.length) return { items: CATALOG.filter((e) => e.curated).slice(0, limit), total: CATALOG.length }
  const hits = CATALOG.map((e) => ({ e, s: score(e, terms) })).filter((x) => x.s > 0).sort((a, b) => b.s - a.s || a.e.order - b.e.order)
  return { items: hits.slice(0, limit).map((x) => x.e), total: hits.length }
}

/** Khớp tên một ô CSV với danh sách: id, tên hiển thị, "hãng sản phẩm" hoặc kết quả tìm kiếm đầu tiên nếu khớp mọi từ. */
export function findCatalog(text: string): CatalogEntry | undefined {
  const n = fold(text)
  if (!n) return undefined
  const exact = CATALOG.find((e) => e.id === text.trim() || HAY.get(e.id)!.name === n || fold(`${e.vendor} ${e.product}`) === n || HAY.get(e.id)!.al.includes(n))
  if (exact) return exact
  const terms = wordsOf(n)
  return searchCatalog(text, 5).items.find((e) => terms.every((t) => HAY.get(e.id)!.all.includes(t)))
}

/** Sản phẩm người dùng tự nhập (hãng + sản phẩm): khớp theo đúng cặp trong KEV nếu có, không thì theo mọi sản phẩm của hãng. */
export function customEntry(vendor: string, product: string): CatalogEntry {
  const v = fold(vendor)
  const p = fold(product)
  const exact = KEV.filter((r) => fold(r.vendor) === v && fold(r.product) === p).map(kevKey)
  const byVendor = KEV.filter((r) => fold(r.vendor) === v).map(kevKey)
  const kev = exact.length ? exact : byVendor.length ? byVendor : [`${vendor}|${product}`.toLowerCase()]
  return {
    id: '', display: `${vendor} ${product}`.trim(), category: OTHER, hint: `${vendor}, ${product}`, vendor, product, kind: 'unknown', kev, aliases: [],
    version_hint: '', kev_count: sumKev(kev), curated: false, order: 9999,
  }
}
export { sumKev }
