import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Chip } from '@/components/common/StatusChip'
import { useCan } from '@/lib/session'
import { useDevice, useDeviceAction } from '@/features/inventory/api'
import { IgnoreDialog } from '@/features/inventory/IgnoreDevice'
import { errMsg } from './errors'
import type { FindingAsset } from './types'

/** A device nobody approved yet (and nobody ignored): its findings are listed, marked "Not added yet", with Add device and Ignore. */
export const notAdded = (asset: FindingAsset | null | undefined): asset is FindingAsset => !!asset && !asset.approved && !asset.ignored

/** The compact neutral mark next to a device name in a list. Nothing for an approved or an ignored device. */
export function NotAddedChip({ asset }: { asset: FindingAsset | null | undefined }) {
  const { t } = useTranslation('findings')
  if (!notAdded(asset)) return null
  return <Chip tone="off" title={t('notAdded.body')}>{t('notAdded.chip')}</Chip>
}

/** Add device (approve it) and Ignore (hide the device and all its findings for good), with Ignore's confirm dialog, where a
 *  finding or a device block of a device nobody approved yet is shown. Only the actions: the heading of the finding page or
 *  the chip next to the device name says "not added yet". Nothing for an approved or an ignored device. */
export function NotAdded({ asset, findings = 1 }: { asset: FindingAsset | null | undefined; findings?: number }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const act = useDeviceAction(asset?.id ?? '')
  const [ign, setIgn] = useState(false)
  // the Ignore dialog says what Ignore does to this device: its real finding count and, for a private address, the warning
  const detail = useDevice(asset?.id ?? '', ign)
  if (!notAdded(asset)) return null
  const title = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const fail = (e: unknown) => toast.error(errMsg(e))
  return (
    // a click here never opens the row or toggles the block behind it
    <span onClick={(e) => e.stopPropagation()} className="flex flex-wrap items-center gap-x-2 gap-y-1">
      <Button size="sm" variant="primary" disabled={!can} busy={act.approve.isPending} busyLabel={t('common:busy.approving')} title={title}
        onClick={() => act.approve.mutate(undefined, { onSuccess: () => toast.success(t('notAdded.added', { name: asset.name })), onError: fail })}>{t('notAdded.add')}</Button>
      <Button size="sm" disabled={!can} busy={act.ignore.isPending} busyLabel={t('common:busy.saving')} title={title} onClick={() => setIgn(true)}>{t('notAdded.ignore')}</Button>
      <IgnoreDialog open={ign} onOpenChange={setIgn} name={asset.name} mac={detail.data?.asset.mac ?? null} findings={detail.data?.findings_count ?? findings} pending={act.ignore.isPending}
        onConfirm={() => act.ignore.mutate(true, { onSuccess: () => { setIgn(false); toast.success(t('notAdded.ignored', { name: asset.name })) }, onError: fail })} />
    </span>
  )
}
