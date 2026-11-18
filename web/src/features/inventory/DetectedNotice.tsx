import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { fmtRelative } from '@/lib/format'
import { kindLabel } from '@/lib/deviceTypes'
import { useCan } from '@/lib/session'
import { useDeviceAction } from './api'
import { errMsg } from './kinds'
import type { DetectedField, DeviceDetail } from './types'

/** A trusted source (agent, SNMP, the device's own statement) reads another value than the one a person entered (INV-47). The
 *  entered value still wins; this small notice, shown next to the field it concerns, lets the person use the detected value or
 *  keep their own. Nothing here when the field has no difference. */
export function DetectedNotice({ d, field }: { d: DeviceDetail; field: DetectedField }) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const act = useDeviceAction(d.asset.id)
  const diff = d.detected_differs.find((x) => x.field === field)
  if (!diff) return null
  const text = (v: string) => (field === 'kind' ? kindLabel(v) : v)
  const source = diff.basis === 'stated' ? t('detectedNotice.source.stated') : t(`detectedNotice.source.${diff.source}`, { defaultValue: diff.source })
  const needRole = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const busy = act.useDetected.isPending || act.keepEntered.isPending
  const input = { field, detected: diff.detected }
  return (
    <div role="group" aria-label={t('detectedNotice.label', { field: t(`detectedNotice.field.${field}`) })} data-testid={`detected-${field}`} className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1">
      <span className="text-meta text-muted [overflow-wrap:anywhere]">
        {t('detectedNotice.text', { field: t(`detectedNotice.field.${field}`), value: text(diff.detected), source, when: fmtRelative(diff.seen_at) })}
      </span>
      <span className="flex flex-wrap gap-2">
        <Button size="sm" disabled={!can || busy} busy={act.useDetected.isPending} busyLabel={t('common:busy.saving')} title={needRole}
          onClick={() => act.useDetected.mutate(input, { onSuccess: () => toast.success(t('detectedNotice.used', { field: t(`detectedNotice.field.${field}`), value: text(diff.detected) })), onError: (e) => toast.error(errMsg(e)) })}>{t('detectedNotice.use')}</Button>
        <Button size="sm" variant="ghost" disabled={!can || busy} busy={act.keepEntered.isPending} busyLabel={t('common:busy.saving')} title={needRole}
          onClick={() => act.keepEntered.mutate(input, { onSuccess: () => toast.success(t('detectedNotice.kept')), onError: (e) => toast.error(errMsg(e)) })}>{t('detectedNotice.keep')}</Button>
      </span>
    </div>
  )
}
