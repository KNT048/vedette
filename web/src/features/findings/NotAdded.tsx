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

/** The compact neutral mark next to a device name, wherever a device nobody added is named. Nothing for an approved or an ignored
 *  device. */
export function NotAddedChip({ asset }: { asset: { approved: boolean; ignored?: boolean } | null | undefined }) {
  const { t } = useTranslation('findings')
  if (!asset || asset.approved || asset.ignored) return null
  return <Chip tone="off" title={t('notAdded.body')}>{t('notAdded.chip')}</Chip>
}

/** Add device (approve it) and Ignore (hide the device and all its findings for good, after the inventory's Ignore dialog): the
 *  actions, the Ignore dialog to render, and whether this person may (operator). The buttons below and a finding row's menu use it. */
export function useNotAddedActions(asset: FindingAsset | null | undefined, findings = 1) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const act = useDeviceAction(asset?.id ?? '')
  const [ign, setIgn] = useState(false)
  // the Ignore dialog says what Ignore does to this device: its real finding count and, for a private address, the warning
  const detail = useDevice(asset?.id ?? '', ign)
  const fail = (e: unknown) => toast.error(errMsg(e))
  const name = asset?.name ?? ''
  return {
    can,
    title: can ? undefined : t('common:needRole', { role: t('common:role.operator') }),
    act,
    add: () => act.approve.mutate(undefined, { onSuccess: () => toast.success(t('notAdded.added', { name })), onError: fail }),
    ignore: () => setIgn(true),
    dialog: notAdded(asset) ? (
      <IgnoreDialog open={ign} onOpenChange={setIgn} name={name} mac={detail.data?.asset.mac ?? null} findings={detail.data?.findings_count ?? findings} pending={act.ignore.isPending}
        onConfirm={() => act.ignore.mutate(true, { onSuccess: () => { setIgn(false); toast.success(t('notAdded.ignored', { name })) }, onError: fail })} />
    ) : null,
  }
}

/** Add device and Ignore as buttons, once per device: the finding page's notice and the device blocks of By device and Needs your
 *  input. Only the actions: the heading or the chip next to the device name says "not added yet". Nothing for an approved or an
 *  ignored device. */
export function NotAdded({ asset, findings = 1 }: { asset: FindingAsset | null | undefined; findings?: number }) {
  const { t } = useTranslation('findings')
  const a = useNotAddedActions(asset, findings)
  if (!notAdded(asset)) return null
  return (
    // a click here never opens the row or toggles the block behind it
    <span onClick={(e) => e.stopPropagation()} className="flex flex-wrap items-center gap-x-2 gap-y-1">
      <Button size="sm" variant="primary" disabled={!a.can} busy={a.act.approve.isPending} busyLabel={t('common:busy.approving')} title={a.title}
        aria-label={t('notAdded.addOf', { name: asset.name })} onClick={a.add}>{t('notAdded.add')}</Button>
      <Button size="sm" disabled={!a.can} busy={a.act.ignore.isPending} busyLabel={t('common:busy.saving')} title={a.title}
        aria-label={t('notAdded.ignoreOf', { name: asset.name })} onClick={a.ignore}>{t('notAdded.ignore')}</Button>
      {a.dialog}
    </span>
  )
}
