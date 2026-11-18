import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Chip } from '@/components/common/StatusChip'
import { useCan } from '@/lib/session'
import { useDeviceAction } from '@/features/inventory/api'
import { IgnoreDialog } from '@/features/inventory/IgnoreDevice'
import { errMsg } from './errors'
import type { FindingAsset } from './types'

/** Where a finding is listed for a device nobody approved yet: the mark "Device not added yet" and, right there, Add device
 *  (approve it) and Ignore (hide the device and all its findings for good). Nothing for an approved or an ignored device. */
export function NotAdded({ asset, findings = 1 }: { asset: FindingAsset | null; findings?: number }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const act = useDeviceAction(asset?.id ?? '')
  const [ign, setIgn] = useState(false)
  if (!asset || asset.approved || asset.ignored) return null
  const title = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const fail = (e: unknown) => toast.error(errMsg(e))
  return (
    // a click here never opens the finding row behind it
    <span onClick={(e) => e.stopPropagation()} className="flex flex-wrap items-center gap-x-2 gap-y-1">
      <Chip tone="warn">{t('notAdded.mark')}</Chip>
      <Button size="sm" variant="primary" disabled={!can} busy={act.approve.isPending} busyLabel={t('common:busy.approving')} title={title}
        onClick={() => act.approve.mutate(undefined, { onSuccess: () => toast.success(t('notAdded.added', { name: asset.name })), onError: fail })}>{t('notAdded.add')}</Button>
      <Button size="sm" disabled={!can} busy={act.ignore.isPending} busyLabel={t('common:busy.saving')} title={title} onClick={() => setIgn(true)}>{t('notAdded.ignore')}</Button>
      <IgnoreDialog open={ign} onOpenChange={setIgn} name={asset.name} mac={null} findings={findings} pending={act.ignore.isPending}
        onConfirm={() => act.ignore.mutate(true, { onSuccess: () => { setIgn(false); toast.success(t('notAdded.ignored', { name: asset.name })) }, onError: fail })} />
    </span>
  )
}
