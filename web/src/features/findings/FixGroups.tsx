// D-545 (W-3, S-MIT-1): one missing update is one item, not one row per CVE, as top-tier scanners group by the fix (Defender's
// "Update Windows Server 2025" recommendation, Tenable's one plugin per cumulative update). Every CVE stays one click away.
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Notice } from '@/components/common/PageHeader'
import { FindingStatusChip } from './AcceptRisk'
import { deviceName } from './basis'
import { useFixAction, type FixGroup } from './fix'
import { RiskChip } from './Risk'

/** The groups as one list: the action, the device (on the Findings list), and the CVEs inside a disclosure. */
export function FixGroupList({ groups, showDevice }: { groups: FixGroup[]; showDevice: boolean }) {
  const { t } = useTranslation('findings')
  const action = useFixAction()
  if (groups.length === 0) return null
  return (
    <section aria-labelledby="fix-groups-title">
      <Notice tone="warn" title={<span id="fix-groups-title">{t('fix.title', { count: groups.length })}</span>} info={t('fix.helpInfo')}>
        <p>{t('fix.help')}</p>
        <ul aria-label={t('fix.listLabel')} className="mt-2 grid gap-3">
          {groups.map((g) => {
            const asset = g.members[0].asset
            return (
              <li key={g.key} className="grid gap-1">
                <p className="text-sm">
                  {showDevice ? <>{asset ? <Link to={`/devices/${asset.id}`} className="font-medium text-accent underline-offset-4 hover:underline">{deviceName(asset, t('removedDevice'))}</Link> : <span className="font-medium">{t('removedDevice')}</span>}{': '}</> : null}
                  <span className="font-medium">{action(g.fix)}</span>{': '}{t('fix.fixes', { count: g.members.length })}
                </p>
                <details>
                  <summary className="w-fit cursor-pointer text-meta text-accent underline-offset-4 hover:underline">{t('fix.show', { count: g.members.length })}</summary>
                  <ul className="mt-1 grid gap-1">
                    {g.members.map((f) => (
                      <li key={f.id} className="flex flex-wrap items-center gap-x-3 gap-y-1">
                        <Link to={`/findings/${f.id}`} className="font-medium text-accent underline-offset-4 hover:underline">{f.cve}</Link>
                        <span className="text-meta text-muted">{f.kev?.name ?? f.kev?.display ?? ''}</span>
                        <FindingStatusChip f={f} /><RiskChip f={f} />
                      </li>
                    ))}
                  </ul>
                  {/* empty-guard: a fix group has at least two findings by construction (fixGroups) */}
                  <Link to={`/findings?fix=${encodeURIComponent(g.key)}`} className="mt-1 inline-block text-meta text-accent underline underline-offset-4">{t('fix.select', { count: g.members.length })}</Link>
                </details>
              </li>
            )
          })}
        </ul>
      </Notice>
    </section>
  )
}
