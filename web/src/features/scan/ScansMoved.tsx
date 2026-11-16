import { Link, Navigate, useLocation } from 'react-router'
import { useTranslation } from 'react-i18next'
import { PageHeader } from '@/components/common/PageHeader'
import { ScanNowButton } from '@/features/scanning/ScanNow'
import { useDevice } from '@/features/inventory/api'
import { CREDENTIALED_IN_UI } from '@/lib/credentialed'

/** #850: the old tabs of Vulnerability scans → the tabs of Settings › Scanning. */
const OLD_TAB: Record<string, string> = { runs: 'history', safety: 'safety', auto: 'history', probes: 'probes', credentialed: CREDENTIALED_IN_UI ? 'credentialed' : 'engines' }

/** "Rescan this device" (a finding), "Scan <device>" (Updates to plan) and old /scans?target= links land here: the device and its
 *  "Check this device now", so the link never ends on a page without the button (review r1 H3). */
function CheckDevice({ id }: { id: string }) {
  const { t } = useTranslation('scanning')
  const d = useDevice(id)
  const a = d.data?.asset
  const name = a ? (a.hostname ?? a.ip) : id
  return (
    <>
      <PageHeader title={t('check.title', { name })} meta={a?.ip} breadcrumbs={[{ label: t('check.devices'), to: '/devices' }]} />
      <div className="grid max-w-3xl gap-4">
        <p className="text-sm">{t('check.body')}</p>
        <ScanNowButton targets={[id]} />
        <Link to={`/devices/${encodeURIComponent(id)}`} className="w-fit text-meta text-accent underline-offset-4 hover:underline">{t('check.open', { name })}</Link>
      </div>
    </>
  )
}

/** #850: the Vulnerability scans page is gone from the menu; its old links land on their new place. `?run=` wins over `?target=`
 *  (review r1 L5); an external target (`ext:<id>`) lands on its External exposure page. */
export default function ScansMoved() {
  const { search } = useLocation()
  const p = new URLSearchParams(search)
  const run = p.get('run')
  const target = p.get('target')
  if (run) return <Navigate to={`/settings/scanning?tab=history&run=${encodeURIComponent(run)}`} replace />
  if (target?.startsWith('ext:')) return <Navigate to={`/exposure/${encodeURIComponent(target.slice(4))}`} replace />
  if (target) return <CheckDevice id={target} />
  return <Navigate to={`/settings/scanning?tab=${OLD_TAB[p.get('tab') ?? ''] ?? 'engines'}`} replace />
}
