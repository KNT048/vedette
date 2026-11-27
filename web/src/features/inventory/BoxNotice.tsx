import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Notice } from '@/components/common/PageHeader'
import { useInstallKind } from '@/lib/modules'
import { useOsState } from '@/features/core/api'
import { useDeviceFindingCounts } from '@/features/findings/notRelevant'

const link = 'text-accent underline-offset-4 hover:underline'

/**
 * The box is the first device; its findings are fixed by updating the operating system, not by a device vendor.
 * The fix is offered only when there is something to install. OS updates that fix open findings of the box → "Fix N
 * findings: install M operating system updates"; updates waiting that are not known to fix them → "M operating system updates are
 * waiting"; findings the kernel already installed fixes once the box restarts → "Fix N findings: restart the box to run the installed
 * kernel K" (to the OS updates, where the restart is); open findings and none of these → one honest line, "No update fixes these yet:
 * see each finding". Nothing open → no fix line.
 */
export function BoxNotice({ assetId }: { assetId: string }) {
  const { t } = useTranslation('inventory')
  const install = useInstallKind() // undefined while GET /modules loads: then neither claim about packages is made
  const packages = install === 'container' ? t('box.packagesContainer') : install === 'appliance' ? t('box.packagesAppliance') : ''
  const counts = useDeviceFindingCounts(assetId)
  const os = useOsState() // a container install has no OS updates of its own: an error or no check yet means none waiting
  const pending = install === 'container' ? [] : (os.data?.pending ?? [])
  const open = counts?.open ?? 0
  const cves = new Set(counts?.cves ?? [])
  const fixing = pending.filter((p) => p.cves.some((c) => cves.has(c)))
  const fixed = new Set(fixing.flatMap((p) => p.cves).filter((c) => cves.has(c))).size
  const restart = counts?.restart ?? 0
  const findingsLink = `/findings?tab=open&device=${encodeURIComponent(assetId)}`
  return (
    <Notice tone="accent" title={t('box.title')} info={[t('box.lead'), packages].filter(Boolean).join(' ')}>
      <p>{t('box.matched')}</p>
      <p className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-ink">
        {fixed > 0
          ? <Link to="/settings/updates#os" className={link}>{t('box.fixWith', { count: fixing.length, findings: t('box.fixFindings', { count: fixed }) })}</Link>
          : pending.length > 0
            ? <Link to="/settings/updates#os" className={link}>{t('box.updatesWaiting', { count: pending.length })}</Link>
            : null}
        {restart > 0
          ? <Link to="/settings/updates#os" className={link}>{t('box.restartFix', { findings: t('box.fixFindings', { count: restart }), version: counts?.restartTo ?? '' })}</Link>
          : null}
        {open > 0 && fixed === 0 && restart === 0 ? <span>{t('box.noFix')}</span> : null}
        {open > 0 ? <Link to={findingsLink} className="text-accent underline-offset-4 hover:underline">{t('box.findings', { count: open })}</Link> : null}
        <span className="text-meta text-muted">{t('box.noDelete')}</span>
      </p>
    </Notice>
  )
}
