import { useState } from 'react'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { GitMerge } from 'lucide-react'
import { Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useSplitAddress } from './api'
import { errMsg } from './kinds'
import { addressText, splitBlock } from './mergeLogic'
import type { DeviceAddress } from './types'

/** The id of the device page's Addresses section: the merge toast's Split link and a deep link open it. */
export const ADDRESSES_SECTION = 'addresses'

/**
 * The device page's Addresses (the undo of a merge): every IP and MAC the device was seen at, the main one and the agent's
 * marked, with what saw it and when. An admin splits off an address that belongs to another machine (a confirm first); the
 * agent's address, a device's only address and the box's addresses cannot be, and say why next to the button; the box's Merge is
 * off with its reason too.
 */
export function AddressesSection({ deviceId, name, isBox, addresses, onMerge }: { deviceId: string; name: string; isBox: boolean; addresses: DeviceAddress[]; onMerge?: () => void }) {
  const { t } = useTranslation('inventory')
  const admin = useCan('admin')
  const needAdmin = admin ? undefined : t('common:needRole', { role: t('common:role.admin') })
  const [splitting, setSplitting] = useState<DeviceAddress | null>(null)
  const source = (s: string) => (s === 'merge' ? t('addresses.sourceMerge') : t(`common:source.${s}`, { defaultValue: s }))
  const action = (a: DeviceAddress) => {
    const block = isBox ? 'box' : splitBlock(a, addresses)
    const why = block === 'box' ? t('addresses.blockBox') : block === 'agent' ? t('addresses.blockAgent') : block === 'only' ? t('addresses.blockOnly') : ''
    const whyId = `split-why-${addressText(a).replace(/[^0-9a-z]/gi, '-')}`
    return (
      <span className="flex flex-wrap items-center justify-end gap-x-3 gap-y-1">
        {why ? <span id={whyId} className="text-caption text-muted">{why}</span> : null}
        <Button size="sm" disabled={!admin || !!block} title={needAdmin} aria-describedby={why ? whyId : undefined}
          aria-label={t('addresses.splitLabel', { address: addressText(a) })} onClick={() => setSplitting(a)}>{t('addresses.split')}</Button>
      </span>
    )
  }
  const marks = (a: DeviceAddress) => (
    <>
      {a.main ? <Chip tone="accent">{t('addresses.main')}</Chip> : null}
      {a.agent ? <Chip tone="ok">{t('addresses.agent')}</Chip> : null}
    </>
  )
  const columns: ColumnDef<DeviceAddress>[] = [
    { id: 'ip', header: t('addresses.ip'), accessorFn: (a) => a.ip ?? '', cell: ({ row }) => (
      <span className="flex flex-wrap items-center gap-2"><span className="tabular-nums">{row.original.ip ?? <span className="text-muted">–</span>}</span>{marks(row.original)}</span>
    ) },
    { id: 'mac', header: t('addresses.mac'), accessorFn: (a) => a.mac ?? '', cell: ({ row }) => <span className="tabular-nums">{row.original.mac ?? <span className="text-muted">–</span>}</span> },
    { id: 'source', header: t('addresses.source'), accessorFn: (a) => source(a.source), cell: ({ row }) => <span className="text-meta">{source(row.original.source)}</span> },
    { id: 'seen', header: t('addresses.lastSeen'), accessorFn: (a) => Date.parse(a.last_seen), cell: ({ row }) => <time dateTime={row.original.last_seen} title={fmtDateTime(row.original.last_seen)} className="whitespace-nowrap text-meta text-muted">{fmtRelative(row.original.last_seen)}</time> },
    { id: 'actions', enableSorting: false, header: () => <span className="sr-only">{t('addresses.actions')}</span>, cell: ({ row }) => action(row.original) },
  ]
  return (
    <Section id={ADDRESSES_SECTION} title={t('addresses.title')} info={t('addresses.info')}
      actions={isBox ? <Button size="sm" disabled title={t('addresses.mergeBox')}><GitMerge />{t('addresses.mergeWith')}</Button>
        : onMerge ? <Button size="sm" disabled={!admin} title={needAdmin} onClick={onMerge}><GitMerge />{t('addresses.mergeWith')}</Button> : undefined}>
      {addresses.length ? (
        <DataTable urlKey="addresses" caption={t('addresses.title')} data={addresses} columns={columns} pageSize={100}
          mobileRow={(a) => (
            <div className="grid gap-1.5">
              <span className="flex flex-wrap items-center gap-2 text-sm"><span className="font-medium tabular-nums">{addressText(a)}</span>{a.ip && a.mac ? <span className="text-meta tabular-nums text-muted">{a.mac}</span> : null}{marks(a)}</span>
              <span className="flex flex-wrap gap-x-3 text-caption text-muted"><span>{source(a.source)}</span><time dateTime={a.last_seen} title={fmtDateTime(a.last_seen)}>{fmtRelative(a.last_seen)}</time></span>
              {action(a)}
            </div>
          )} />
      ) : <EmptyState title={t('addresses.none')}>{t('addresses.noneBody')}</EmptyState>}
      {splitting ? <SplitDialog key={addressText(splitting)} deviceId={deviceId} name={name} address={splitting} all={addresses} onClose={() => setSplitting(null)} /> : null}
    </Section>
  )
}

/** Split off: what becomes a device of its own and what stays, and which address becomes the main one when the main one goes.
 *  The box's refusal stays in the dialog, word for word; no closing while it runs. */
function SplitDialog({ deviceId, name, address, all, onClose }: { deviceId: string; name: string; address: DeviceAddress; all: DeviceAddress[]; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const navigate = useNavigate()
  const split = useSplitAddress(deviceId)
  const [error, setError] = useState('')
  const text = addressText(address)
  // the other address seen last becomes the main one (the list is the main one first, then the others seen last first)
  const next = address.main ? all.find((a) => !a.main) : undefined
  const confirm = () => {
    setError('')
    void split.mutateAsync(text).then((r) => {
      toast.success(t('addresses.splitDone', { address: text }), { action: { label: t('addresses.openNew'), onClick: () => void navigate(`/devices/${encodeURIComponent(r.id)}`) } })
      onClose()
    }, (e: unknown) => setError(errMsg(e)))
  }
  return (
    <Dialog open onOpenChange={(o) => { if (!o && !split.isPending) onClose() }}>
      <DialogContent title={t('addresses.splitTitle', { address: text, name })} description={t('addresses.splitBody')}>
        {next ? <p className="text-sm">{t('addresses.splitMain', { next: addressText(next), name })}</p> : null}
        <p className="text-sm text-muted">{t('addresses.splitStays', { name })}</p>
        {error ? <p role="alert" className="text-meta text-danger [overflow-wrap:anywhere]">{error}</p> : null}
        <DialogFooter>
          <DialogClose asChild><Button disabled={split.isPending}>{t('common:cancel')}</Button></DialogClose>
          <Button variant="primary" busy={split.isPending} busyLabel={t('addresses.splitting')} onClick={confirm}>{t('addresses.splitConfirm')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
