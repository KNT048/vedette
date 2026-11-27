import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { Card } from '@/components/common/Card'
import { Chip } from '@/components/common/StatusChip'
import { ListRow, RowList } from '@/components/common/ListParts'
import { useModuleEnabled } from '@/lib/modules'
import { fmtDateTime } from '@/lib/format'
import { useHits } from './api'
import { hitName } from './hitName'

/** Slot device.panels: trap hits from this device (S-HP-1). Renders nothing when the module is off or the device has no hits. */
export default function DevicePanel(props: Record<string, unknown>) {
  const assetId = String(props.assetId ?? '')
  const on = useModuleEnabled('honeypot')
  if (!on || !assetId) return null
  return <Inner assetId={assetId} />
}

function Inner({ assetId }: { assetId: string }) {
  const { t } = useTranslation('honeypot')
  const q = useHits(assetId)
  // A device with no hits has nothing to show here: no empty section (an error still says so).
  if (q.data && q.data.items.length === 0) return null
  return (
    <Section id="device-hp" title={t('device.title')} description={t('device.description')} info={t('device.descriptionInfo')}>
      {q.isPending ? <p className="text-sm text-muted">{t('common:loading')}</p>
        : q.error ? <p role="alert" className="text-sm text-danger">{q.error instanceof Error ? q.error.message : String(q.error)}</p>
        : (
          <Card flush>
          <RowList flush label={t('device.title')}>
            {q.data.items.map((h) => (
              <ListRow key={h.id} title={t('device.item', { service: hitName(t, h), time: fmtDateTime(h.ts) })} to={`/honeypot/hits/${h.id}`}
                badges={h.is_test ? <Chip tone="off">{t('hits.test')}</Chip> : null}
                meta={[h.is_test ? null : h.excerpt.length > 70 ? `${h.excerpt.slice(0, 70)}…` : h.excerpt]} />
            ))}
          </RowList>
          </Card>
        )}
    </Section>
  )
}
