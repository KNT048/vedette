// The summary card at the top of a finding: the CVE in one sentence, its key facts, and what to do on this device (why the finding is
// urgent is its status lines under the title, the words every list says). It reads the CVE brief (GET /feeds/cve/{id}) and the finding; no AI, worked out again on every view. The fixed releases
// per release train, every affected version, the full facts and the sources sit behind one click.
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Card } from '@/components/common/Card'
import { fmtPercent } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useCve } from '@/features/feeds/api'
import { briefSentence } from '@/features/feeds/brief'
import { AffectedAll, BriefFacts, BriefRemedy, BriefSources, FixTable } from '@/features/feeds/BriefParts'
import type { CveBrief } from '@/features/feeds/types'
import { FixedInNote } from './Recommendation'
import { deviceName, hasIp, isOpen } from './basis'
import { linkKind, linkLabels } from './links'
import type { FindingDetail } from './types'

const link = 'text-accent underline-offset-4 hover:underline'

/** The pages that name the fix: the brief's vendor advisories and patches, else the vendor links of the exploited-list entry. */
function advisories(b: CveBrief | undefined, f: FindingDetail): string[] {
  const refs = b?.references.filter((r) => r.group === 'vendor-advisory' || r.group === 'patch').map((r) => r.url) ?? []
  const urls = refs.length ? refs : (f.kev?.links ?? []).filter((u) => linkKind(u) === 'vendor')
  return [...new Set(urls.filter((u) => /^https?:\/\//i.test(u)))].slice(0, 3)
}

export function CveBriefCard({ f }: { f: FindingDetail }) {
  const { t } = useTranslation('findings')
  const { t: tf } = useTranslation('feeds')
  const feedsOn = useModuleEnabled('feeds') !== false
  const q = useCve(feedsOn ? f.cve : '')
  const b = q.data
  const urls = advisories(b, f)
  const labels = linkLabels(t, urls)
  // the finding's own software names the product when the exploited list and the CVE record do not (an update-recommended finding
  // is on no list): never "the software"
  const known = f.known_version?.software ?? null
  const product = f.kev?.display || b?.display || known || t('rec.theSoftware')
  const software = known ?? product
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
        <div className="grid gap-2">
          <h3 className="text-sm font-semibold">{t('brief.todo')}</h3>
          <ol className="grid max-w-[72ch] list-decimal gap-1.5 pl-5 text-sm">
            <li>
              <div className="grid gap-1">
                {f.fixed_in ? <FixedInNote finding={f} /> : q.isLoading ? null : <span>{urls.length ? t('brief.fix') : t(f.kev ? 'rec.noVendorLink' : 'rec.noAdvisoryLink', { cve: f.cve, product })}</span>}
                {urls.length ? (
                  <span className="flex flex-wrap gap-x-3 gap-y-0.5">
                    {urls.map((u, i) => <a key={u} className={`break-all ${link}`} href={u} target="_blank" rel="noopener noreferrer">{labels[i]}</a>)}
                  </span>
                ) : null}
              </div>
            </li>
            {b ? <BriefRemedy b={b} /> : null}
            {isOpen(f.status) && f.asset && hasIp(f.asset) ? (
              <li>{t('brief.check', { device: deviceName(f.asset, t('removedDevice')) })} <Link to={`/devices/${encodeURIComponent(f.asset.id)}`} className={link}>{t('brief.checkNow')}</Link></li>
            ) : null}
          </ol>
        </div>
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
