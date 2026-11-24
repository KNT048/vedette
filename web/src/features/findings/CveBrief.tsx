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

/**
 * A link on a code-hosting site is the vendor's only when the project's owner is the vendor or the product ("github.com/nginx/nginx"
 * for nginx): a fork ("chainguard-forks/ingress-nginx") or another project that uses the product ("kubernetes/ingress-nginx") is not
 * the vendor's advisory, whatever tag the record gives it. Any other site keeps the record's word.
 */
export function vendorOwned(url: string, names: string[]): boolean {
  let u: URL
  try { u = new URL(url) } catch { return false }
  if (!CODE_HOSTS.has(u.hostname.replace(/^www\./, '').toLowerCase())) return true
  const owner = squash(u.pathname.split('/').filter(Boolean)[0] ?? '')
  const words = names.flatMap((n) => n.split(/[\s|/,()]+/)).map(squash).filter((w) => w.length >= 3)
  return !!owner && words.some((w) => owner === w || owner.includes(w))
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
