// The words of the reference links of an exploited-list entry (its "notes": CISA pages, NVD, the vendor's advisories). One entry
// often has several links of one kind: the two pages of a CISA directive, five Apple advisories, a GitHub advisory and its fix
// commit. Each link gets a label that says what it is and no two links of one finding read the same.
import type { TFunction } from 'i18next'

export type LinkKind = 'cisa' | 'nvd' | 'vendor'

/** Links in the exploited list's notes: CISA's pages, NVD, everything else is taken as the vendor's advisory. */
export function linkKind(u: string): LinkKind {
  let host = ''
  try { host = new URL(u).hostname.toLowerCase() } catch { return 'vendor' }
  if (host === 'nvd.nist.gov') return 'nvd'
  if (host === 'cisa.gov' || host.endsWith('.cisa.gov')) return 'cisa'
  return 'vendor'
}

const hostOf = (u: URL) => u.hostname.replace(/^www\./, '')
/** The list separates links with ";" but some entries put "," or "." after one; it is not part of the address's name. */
const clean = (s: string) => s.replace(/[.,;:)\]]+$/, '')
const decode = (s: string) => { try { return decodeURIComponent(s) } catch { return s } }

/** The parts of an address that tell two pages of one site apart: its path segments, then its query values and fragment. */
function segments(u: URL): string[] {
  const path = clean(u.pathname).split('/').map(decode).filter((p) => /[a-z0-9]/i.test(p)) // not GitLab's "/-/"
  if (path.length) path[path.length - 1] = path.at(-1)!.replace(/\.(html?|aspx?|php|jsp|pdf)$/i, '')
  const query = [...u.searchParams.values()].map((v) => clean(decode(v))).filter(Boolean)
  const hash = clean(decode(u.hash.slice(1)))
  return [...path, ...query, ...(hash ? [hash] : [])]
}

/** A segment written as words ("bod-26-04-prioritizing-security-updates-based-risk"), not an id ("FG-IR-24-015", "GHSA-v4p8-mg3p-g94g"). */
function isSlug(seg: string) {
  const parts = seg.split(/[-_]+/).filter(Boolean)
  if (parts.length >= 2 && parts.every((p) => /^[a-z]+$/i.test(p))) return true // "technical-bulletin", "download-center"
  return parts.length >= 3 && parts.filter((p) => /^[a-z]{3,}$/i.test(p)).length * 2 > parts.length
}
const words = (seg: string) => seg.split(/[-_\s]+/).filter(Boolean)

/** Drops what every item of the group shares at its start and at its end, keeping each item's own part. */
function ownParts<T>(items: T[][], same: (a: T, b: T) => boolean): T[][] {
  const first = items[0] ?? []
  const shortest = Math.min(...items.map((x) => x.length))
  let head = 0
  while (head < shortest && items.every((x) => same(x[head]!, first[head]!))) head++
  let tail = 0
  while (tail < shortest - head && items.every((x) => same(x[x.length - 1 - tail]!, first[first.length - 1 - tail]!))) tail++
  return items.map((x) => x.slice(head, x.length - tail))
}

/** The name of a CISA page from its address: a directive (BOD/ED), an ICS or cybersecurity advisory, an alert with its date, a KEV entry. */
function cisaLabel(t: TFunction<'findings'>, u: URL): string {
  const path = clean(u.pathname).toLowerCase()
  const directive = path.match(/\/directives\/.*?\b(bod|ed)-(\d{2})-(\d{2})\b/)
  if (directive) return t('rec.cisa.directive', { id: `${directive[1]!.toUpperCase()} ${directive[2]}-${directive[3]}` })
  const ics = path.match(/\/(icsa-\d{2}-\d{3}-\d{2}[a-z]?)$/)
  if (ics) return t('rec.cisa.ics', { id: ics[1]!.toUpperCase() })
  const advisory = path.match(/\/cybersecurity-advisories\/(aa\d{2}-\d{3}[a-z])$/)
  if (advisory) return t('rec.cisa.advisory', { id: advisory[1]!.toUpperCase() })
  if (/\/news-events\/alerts\//.test(path)) return t('rec.cisa.alert')
  if (path.startsWith('/known-exploited-vulnerabilities')) return t('rec.cisa.kev')
  return t('rec.cisaLink')
}

function baseLabel(t: TFunction<'findings'>, raw: string): string {
  let u: URL
  try { u = new URL(raw) } catch { return t('rec.vendorLink', { host: raw }) }
  const kind = linkKind(raw)
  if (kind === 'nvd') return t('rec.nvdLink')
  if (kind === 'cisa') return cisaLabel(t, u)
  return t('rec.vendorLink', { host: hostOf(u) })
}

/**
 * The label of each link, in the order given. A link whose kind of label is its own keeps it ("CISA directive BOD 26-04", "Vendor
 * advisory (fortiguard.com)"); links that would read the same get what tells their addresses apart: the path past what they share,
 * a slug as words and an id as written ("Vendor advisory (support.apple.com): 121752", "CISA directive BOD 26-04: implementation
 * guidance"). Words already in the label are not repeated. Two addresses nothing tells apart are numbered.
 */
export function linkLabels(t: TFunction<'findings'>, links: string[]): string[] {
  const base = links.map((l) => baseLabel(t, l))
  const out = [...base]
  const groups = new Map<string, number[]>()
  base.forEach((b, i) => groups.set(b, [...(groups.get(b) ?? []), i]))
  for (const [label, idx] of groups) {
    if (idx.length < 2) continue
    const segs = idx.map((i) => { try { return segments(new URL(links[i]!)) } catch { return [links[i]!] } })
    const own = ownParts(segs, (a, b) => a.toLowerCase() === b.toLowerCase())
    const known = new Set(words(label.toLowerCase().replace(/[^a-z0-9]+/g, ' ')))
    // Two slugs of one place ("bod-26-04-prioritizing-…" and "bod-26-04-implementation-guidance-prioritizing-…"): compare their words.
    const slugs = own.every((s) => s.length === 1 && isSlug(s[0]!))
    const detail = slugs
      ? ownParts(own.map((s) => words(s[0]!).filter((w) => !known.has(w.toLowerCase()))), (a, b) => a.toLowerCase() === b.toLowerCase()).map((w) => w.join(' '))
      : own.map((s) => s.map((x) => (isSlug(x) ? words(x).join(' ') : x)).join(' / '))
    idx.forEach((i, n) => { out[i] = detail[n] ? t('rec.linkDetail', { label, detail: detail[n] }) : label })
    const seen = new Map<string, number>()
    for (const i of idx) {
      const k = out[i]!
      const count = (seen.get(k) ?? 0) + 1
      seen.set(k, count)
      if (count > 1) out[i] = t('rec.linkNumbered', { label: k, n: count })
    }
  }
  return out
}
