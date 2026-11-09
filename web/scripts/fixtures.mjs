// Kéo dữ liệu THẬT cho prototype M0 (S-FEED-1, S-FEED-2, S-FEED-3). Chạy: `pnpm fixtures` (mỗi thứ Hai trong tuần phỏng vấn).
// Nguồn: CISA KEV (CC0), FIRST EPSS (ghi nguồn), nuclei-templates cves.json (MIT). Dữ liệu ngoài là không tin cậy (SYS-6):
// giới hạn kích thước, kiểm tra hình dạng, bỏ bản ghi lạ, chỉ giữ link https.
import { writeFileSync } from 'node:fs'

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
const EPSS_URL = 'https://api.first.org/data/v1/epss'
const NUCLEI_URL = 'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json'
const OUT = new URL('../src/mocks/fixtures/kev.json', import.meta.url)
const MAX_BYTES = 20 * 1024 * 1024
const WINDOW_DAYS = 30
// CVE của 3 phát hiện mẫu (src/mocks/fixtures/findings.ts) — luôn giữ dù cũ.
const PINNED = ['CVE-2022-27593', 'CVE-2026-119977', 'CVE-2026-96951']
const CVE_RE = /^CVE-\d{4}-\d{4,}$/
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/

async function get(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(30_000) })
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`)
  const buf = await res.arrayBuffer()
  if (buf.byteLength > MAX_BYTES) throw new Error(`${url}: quá ${MAX_BYTES} byte`)
  return new TextDecoder().decode(buf)
}

const str = (v, max = 2000) => (typeof v === 'string' ? v.slice(0, max) : '')
const httpsLinks = (s) => (str(s, 4000).match(/https:\/\/[^\s;,]+/g) ?? []).slice(0, 5)

const now = new Date()
const day = (d) => d.toISOString().slice(0, 10)
const since = day(new Date(now.getTime() - WINDOW_DAYS * 864e5))

const kev = JSON.parse(await get(KEV_URL))
if (!Array.isArray(kev?.vulnerabilities)) throw new Error('KEV: thiếu vulnerabilities[]')
const picked = kev.vulnerabilities
  .filter((v) => CVE_RE.test(v?.cveID) && DATE_RE.test(v?.dateAdded))
  .filter((v) => v.dateAdded >= since || PINNED.includes(v.cveID))

const ids = picked.map((v) => v.cveID)
async function epss(date) {
  const out = new Map()
  for (let i = 0; i < ids.length; i += 100) {
    const q = new URLSearchParams({ cve: ids.slice(i, i + 100).join(',') })
    if (date) q.set('date', date)
    const body = JSON.parse(await get(`${EPSS_URL}?${q}`))
    for (const r of body?.data ?? []) {
      const n = Number(r?.epss)
      if (CVE_RE.test(r?.cve) && Number.isFinite(n) && n >= 0 && n <= 1) out.set(r.cve, n)
    }
  }
  return out
}
const epssNow = await epss()
const epssWeekAgo = await epss(day(new Date(now.getTime() - 7 * 864e5)))

const templates = new Set()
for (const line of (await get(NUCLEI_URL)).split('\n')) {
  const id = line.match(/^\{"ID":"(CVE-\d{4}-\d{4,})"/)?.[1]
  if (id) templates.add(id)
}

const vulns = picked
  .map((v) => ({
    cve: v.cveID,
    vendor: str(v.vendorProject, 120),
    product: str(v.product, 160),
    name: str(v.vulnerabilityName, 300),
    description: str(v.shortDescription),
    required_action: str(v.requiredAction, 1000),
    links: httpsLinks(v.notes),
    date_added: v.dateAdded,
    due_date: DATE_RE.test(v.dueDate) ? v.dueDate : null,
    ransomware: v.knownRansomwareCampaignUse === 'Known',
    epss: epssNow.get(v.cveID) ?? null,
    epss_7d_ago: epssWeekAgo.get(v.cveID) ?? null,
    has_template: templates.has(v.cveID),
  }))
  .sort((a, b) => b.date_added.localeCompare(a.date_added))

// Danh mục sản phẩm cho "Khai thiết bị" (S-INV-2): MỌI cặp hãng/sản phẩm từng có trong KEV (toàn bộ lịch sử),
// để khai tay khớp đúng khoá KEV. Module inventory ghép thêm sản phẩm phổ biến ở SMB và cho khai tự do.
const products = new Map()
for (const v of kev.vulnerabilities) {
  if (!CVE_RE.test(v?.cveID) || !DATE_RE.test(v?.dateAdded)) continue
  const vendor = str(v.vendorProject, 120).trim(), product = str(v.product, 160).trim()
  if (!vendor || !product) continue
  const key = `${vendor}|${product}`.toLowerCase()
  const p = products.get(key) ?? { vendor, product, kev_count: 0, last_added: v.dateAdded, ransomware: false }
  p.kev_count += 1
  if (v.dateAdded > p.last_added) p.last_added = v.dateAdded
  if (v.knownRansomwareCampaignUse === 'Known') p.ransomware = true
  products.set(key, p)
}
writeFileSync(new URL('../../content/catalog/kev-products.json', import.meta.url), JSON.stringify([...products.values()].sort((a, b) => a.vendor.localeCompare(b.vendor) || a.product.localeCompare(b.product)), null, 1) + '\n')

const fetched_at = now.toISOString()
writeFileSync(
  OUT,
  JSON.stringify(
    {
      generated_at: fetched_at,
      kev_catalog_version: str(kev.catalogVersion, 40),
      sources: [
        { name: 'CISA KEV', url: KEV_URL, license: 'CC0', fetched_at },
        { name: 'FIRST EPSS', url: EPSS_URL, license: 'ghi nguồn: EPSS by FIRST', fetched_at },
        { name: 'nuclei-templates', url: NUCLEI_URL, license: 'MIT', fetched_at },
      ],
      vulns,
    },
    null,
    1,
  ) + '\n',
)
console.log(`kev-products.json: ${products.size} sản phẩm. kev.json: ${vulns.length} CVE (từ ${since} + ${PINNED.length} CVE ghim), KEV ${kev.catalogVersion}, EPSS ${epssNow.size}, có template ${vulns.filter((v) => v.has_template).length}`)
