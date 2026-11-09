import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { ModuleOff, QueryState } from '@/components/common/States'
import { SeverityChip, StatusChip } from '@/components/common/StatusChip'
import { fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useFindings } from './api'

/** Slot device.panels (trang chi tiết thiết bị của module inventory): phát hiện của đúng thiết bị này. */
export function DevicePanel(props: Record<string, unknown>) {
  const assetId = String(props.assetId ?? '')
  const { t } = useTranslation('findings')
  const on = useModuleEnabled('mitigation')
  const q = useFindings(assetId)
  if (on === false) return <Section title={t('device.title')}><ModuleOff module="mitigation" /></Section>
  return (
    <Section id="device-findings" title={t('device.title')} description={t('device.description')} stories={['S-MIT-1']}>
      <QueryState query={q}>
        {(d) => d.items.length === 0 ? (
          <p className="text-sm text-muted">{t('device.none')}</p>
        ) : (
          <ul className="divide-y divide-rule rounded-md border border-rule bg-surface">
            {d.items.map((f) => (
              <li key={f.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3">
                <Link to={`/findings/${f.id}`} className="font-medium text-accent underline-offset-4 hover:underline">{f.cve}</Link>
                <span className="text-sm text-muted">{f.kev?.display ?? ''}</span>
                <StatusChip status={f.status} />
                <SeverityChip severity={f.severity} />
                <span className="ml-auto text-[12px] text-muted">{t('device.lastSeen', { time: fmtRelative(f.last_seen) })}</span>
              </li>
            ))}
          </ul>
        )}
      </QueryState>
    </Section>
  )
}
