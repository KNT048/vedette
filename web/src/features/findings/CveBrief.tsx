// The summary card at the top of a finding: the CVE in one sentence, its key facts and the device's version (why the finding is
// urgent is its status lines under the title, the words every list says; what to do is the page's one "What to do" section, WhatToDo). It reads the CVE brief (GET /feeds/cve/{id}) and the finding; no AI, worked out again on every view. The fixed releases
// per release train, every affected version, the full facts and the sources sit behind one click.
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Card } from '@/components/common/Card'
import { fmtPercent } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useCve } from '@/features/feeds/api'
import { briefSentence } from '@/features/feeds/brief'
import { AffectedAll, BriefFacts, BriefSources, FixTable } from '@/features/feeds/BriefParts'
import type { CveBrief } from '@/features/feeds/types'
import { useView } from './api'
import { linkKind } from './links'
import type { FindingDetail, View } from './types'

const link = 'text-accent underline-offset-4 hover:underline'

const CODE_HOSTS = new Set(['github.com', 'gitlab.com', 'bitbucket.org'])
const squash = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, '')

// Words of a company or product name that name nobody on their own ("Palo Alto Networks", "Apache HTTP Server").
const GENERIC = new Set(['inc', 'corp', 'ltd', 'llc', 'gmbh', 'the', 'networks', 'network', 'systems', 'software', 'technologies', 'technology',
  'foundation', 'project', 'group', 'labs', 'security', 'enterprise', 'cloud', 'server', 'http', 'web', 'open', 'communications', 'solutions'])
// What a vendor adds to its name for its account ("nginxinc", "F5Networks", "PaloAltoNetworks").
const OWNER_SUFFIXES = ['', 'inc', 'corp', 'hq', 'labs', 'oss', 'io', 'dev', 'official', 'networks', 'software', 'security', 'project']

/**
 * A link on a code-hosting site is the vendor's only when the project's owner is the vendor's or the product's own account: one of
 * their names, whole or one distinctive word of it ("github.com/nginx/nginx" for nginx, "PaloAltoNetworks" for Palo Alto Networks),
 * possibly with a company suffix ("nginxinc", "F5Networks"). A fork ("chainguard-forks/ingress-nginx"), another project that uses the
 * product ("kubernetes/ingress-nginx") or an account whose name merely contains a product word ("nginx-hater") is not the vendor's
 * advisory, whatever tag the record gives it. Any other site keeps the record's word.
 */
export function vendorOwned(url: string, names: string[]): boolean {
  let u: URL
  try { u = new URL(url) } catch { return false }
  if (!CODE_HOSTS.has(u.hostname.replace(/^www\./, '').toLowerCase())) return true
  const owner = squash(u.pathname.split('/').filter(Boolean)[0] ?? '')
  if (!owner) return false
  const words = names.flatMap((n) => n.split(/[\s|/,()]+/).map(squash).filter((w) => w.length >= 2 && !GENERIC.has(w)))
  const bases = new Set([...names.map(squash).filter((n) => n.length >= 2), ...words])
  return [...bases].some((b) => OWNER_SUFFIXES.some((x) => owner === b + x))
}

/** The pages that name the fix: the brief's vendor advisories and patches, else the vendor links of the exploited-list entry. */
export function advisories(b: CveBrief | undefined, f: FindingDetail, view?: View): string[] {
  const names = [f.kev?.vendor, f.kev?.product, b?.display, ...(b?.products ?? []), view?.fix.product, f.known_version?.software].filter((x): x is string => !!x)
  const refs = b?.references.filter((r) => r.group === 'vendor-advisory' || r.group === 'patch').map((r) => r.url).filter((u) => vendorOwned(u, names)) ?? []
  const urls = refs.length ? refs : (f.kev?.links ?? []).filter((u) => linkKind(u) === 'vendor')
  return [...new Set(urls.filter((u) => /^https?:\/\//i.test(u)))].slice(0, 3)
}

export function CveBriefCard({ f }: { f: FindingDetail }) {
  const { t } = useTranslation('findings')
  const { t: tf } = useTranslation('feeds')
  const feedsOn = useModuleEnabled('feeds') !== false
  const q = useCve(feedsOn ? f.cve : '')
  const b = q.data
  // the finding's own software names the product when the exploited list and the CVE record do not (an update-recommended finding
  // is on no list): the version the box has, else the software line the finding is on, else the product its fix is for (the View
  // every list reads): never "the software" or "The product"
  const view = useView(f.id).data
  const known = f.known_version?.software || view?.software?.name || view?.fix.product || null
  const software = known ?? (f.kev?.display || b?.display || t('rec.theSoftware'))
  const version = f.known_version?.version ?? f.fixed_in?.version
  const cwe = b?.cwe[0]
  return (
    <Card id="cve-brief" title={t('brief.title', { cve: f.cve })} className="mb-8"
      actions={<Link to={`/cve/${f.cve}`} className={`text-sm ${link}`}>{t('aside.cvePage', { cve: f.cve })}</Link>}>
      <div className="grid gap-4">
        {b ? (
          <div className="grid gap-1.5">
            <p className="max-w-[72ch] text-base leading-relaxed" data-testid="brief-sentence">{briefSentence(tf, b, known)}</p>
            {cwe || b.epss ? (
              <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-meta">
                {cwe ? <span>{cwe.name ? `${cwe.id}: ${cwe.name}` : cwe.id}</span> : null}
                {b.epss ? <span>{t('brief.epss', { score: fmtPercent(b.epss.score) })}</span> : null}
              </p>
            ) : null}
          </div>
        ) : null}
        {!f.fixed_in && version ? <p className="text-sm font-medium" data-testid="brief-device">{t('brief.device', { software, version })}</p> : null}
        {b ? (
          <details className="grid gap-3 border-t border-rule pt-3">
            <summary className="w-fit cursor-pointer text-sm text-accent">{t('brief.more')}</summary>
            <div className="mt-3 grid gap-4">
              {/* no row is marked yet: the finding names its fixed release but not the product and release train it belongs to */}
              <FixTable b={b} />
              <AffectedAll b={b} />
              <BriefFacts b={b} />
              <BriefSources b={b} />
            </div>
          </details>
        ) : null}
      </div>
    </Card>
  )
}
