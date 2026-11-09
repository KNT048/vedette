import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { Chip } from '@/components/common/StatusChip'
import { useModuleEnabled } from '@/lib/modules'
import { fmtDateTime } from '@/lib/format'
import { useHits } from './api'
import { hitName } from './hitName'

/** Slot device.panels: trap hits from this device (S-HP-1). Renders nothing when the module is off. */
export default function DevicePanel(props: Record<string, unknown>) {
  const assetId = String(props.assetId ?? '')
  const on = useModuleEnabled('honeypot')
  if (!on || !assetId) return null
  return <Inner assetId={assetId} />
}

function Inner({ assetId }: { assetId: string }) {
  const { t } = useTranslation('honeypot')
  const q = useHits(assetId)
  return (
    <Section id="device-hp" title={t('device.title')} description={t('device.description')}>
      {q.isPending ? <p className="text-sm text-muted">{t('common:loading')}</p>
        : q.error ? <p role="alert" className="text-sm text-danger">{q.error instanceof Error ? q.error.message : String(q.error)}</p>
        : q.data.items.length === 0 ? <p className="text-sm text-muted">{t('device.none')}</p>
        : (
          <ul className="grid divide-y divide-rule rounded-md border border-rule bg-surface">
            {q.data.items.map((h) => (
              <li key={h.id} className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 text-sm">
                <Link className="text-accent underline-offset-4 hover:underline" to={`/honeypot/hits/${h.id}`}>{t('device.item', { service: hitName(t, h), time: fmtDateTime(h.ts) })}</Link>
                {h.is_test ? <Chip tone="off">{t('hits.test')}</Chip> : <span className="text-[13px] text-muted">{h.excerpt.length > 70 ? `${h.excerpt.slice(0, 70)}…` : h.excerpt}</span>}
              </li>
            ))}
          </ul>
        )}
    </Section>
  )
}
