import { useState, type ReactNode } from 'react'
import { Link, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { Chip } from '@/components/common/StatusChip'
import { Card } from '@/components/common/Card'
import { fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useApproveAll, useDeviceAction, useForgetRemoved, useNotifyNew, useRemovedDevices } from './api'
import { Dialog, DialogContent, DialogFooter, DialogClose } from '@/components/ui/dialog'
import { TurnOnModule } from './Inline'
import { IgnoreDialog } from './IgnoreDevice'
import { errMsg } from './kinds'
import { nameOf } from './nameOf'
import type { DeviceRow, RemovedDevice } from './types'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { kindLabel } from '@/lib/deviceTypes'
import { InfoTip } from '@/components/common/InfoTip'
import { ListRow, ListSummary, RowList } from '@/components/common/ListParts'
import { SameHint } from './SameDevice'
import { RiskMarker } from './RiskMarker'

function PendingItem({ d, sameAs }: { d: DeviceRow; sameAs: string[] }) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const act = useDeviceAction(d.id)
  const navigate = useNavigate()
  const [ign, setIgn] = useState(false)
  const name = nameOf(d, kindLabel(d.kind))
  const title = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const busy = act.approve.isPending || act.ignore.isPending
  const fail = (e: unknown) => toast.error(errMsg(e))
  return (
    <>
    <ListRow title={name} to={`/devices/${d.id}`}
      badges={<><RiskMarker id={d.id} risk={d.risk} />{d.suspicious ? <Chip tone="warn">{t('chip.suspicious')}</Chip> : null}</>}
      meta={[
        `${[d.ip, d.mac, kindLabel(d.kind)].filter((x) => x && x !== '—').join(', ')}. ${t('pending.firstSeen', { when: fmtRelative(d.first_seen) })}`,
        <SameHint key="same" id={d.id} others={sameAs} />,
      ]}
      // mutateAsync: the row leaves this list when the list reloads, which would drop a mutate() callback and its toast (the toast links the device).
      actions={<>
        <Button size="sm" variant="primary" disabled={!can || busy} busy={act.approve.isPending} busyLabel={t('inventory:pending.adding')} title={title ?? t('pending.approveLabel', { name })}
          aria-label={t('pending.approveLabel', { name })} onClick={() => void act.approve.mutateAsync().then(() => toast.success(t('pending.approved', { name }), { description: t('pending.findLater'), action: { label: t('add.openDevice'), onClick: () => void navigate(`/devices/${d.id}`) } }), fail)}>{t('pending.approve')}</Button>
        {/* Ignore replaces "Remove unknown mark" here; marking stays on the device page. */}
        <Button size="sm" disabled={!can || busy} busy={act.ignore.isPending} busyLabel={t('common:busy.saving')} title={title} onClick={() => setIgn(true)}>{t('pending.ignore')}</Button>
      </>} />
      {/* mutateAsync: the row leaves this list when the list reloads (as Approve) */}
      <IgnoreDialog open={ign} onOpenChange={setIgn} name={name} mac={d.mac} findings={d.findings_count} pending={act.ignore.isPending}
        onConfirm={() => void act.ignore.mutateAsync(true).then(() => { setIgn(false); toast.success(t('pending.ignored', { name }), { description: t('pending.ignoredLater') }) }, fail)} />
    </>
  )
}

/** A device found and not added that shows nothing to look at (state seen: a private Wi-Fi address, no open service, less than a day):
 *  To review's collapsed Seen briefly group, outside its count and the new-device notice (INV-49). Closed by default, as endpoint
 *  tools keep discovered devices apart from the ones people manage; each row can still be added or ignored. */
function SeenBriefly({ items, sameAs }: { items: DeviceRow[]; sameAs?: ReadonlyMap<string, string[]> }) {
  const { t } = useTranslation('inventory')
  if (!items.length) return null
  const rows = [...items].sort((a, b) => b.last_seen.localeCompare(a.last_seen))
  return (
    <details data-testid="seen-briefly" className="rounded-md border border-rule p-3">
      <summary className="cursor-pointer text-sm font-medium">{t('pending.seenTitle', { count: rows.length })}</summary>
      <p className="mt-2 text-meta text-muted">{t('pending.seenBody')}</p>
      <div className="mt-3">
        <RowList boxed label={t('pending.seenTitle', { count: rows.length })}>
          {rows.map((d) => <PendingItem key={d.id} d={d} sameAs={sameAs?.get(d.id) ?? []} />)}
        </RowList>
      </div>
    </details>
  )
}

/** One removal: the device as it was named, when and by whom, and Forget. */
function RemovedRow({ r }: { r: RemovedDevice }) {
  const { t } = useTranslation('inventory')
  const forget = useForgetRemoved()
  const can = useCan('operator')
  return (
    <ListRow title={r.name} sub={r.ip ?? undefined}
      meta={[t(r.agent === 'stopped' ? 'removed.metaStopped' : 'removed.meta', { when: fmtRelative(r.removed_at), by: r.removed_by })]}
      actions={<Button size="sm" disabled={!can} busy={forget.isPending} busyLabel={t('common:busy.saving')}
        title={can ? t('removed.forgetHint') : t('common:needRole', { role: t('common:role.operator') })} aria-label={t('removed.forgetLabel', { name: r.name })}
        onClick={() => forget.mutate(r.id, { onSuccess: () => toast.success(t('removed.forgotten', { name: r.name })), onError: (e) => toast.error(errMsg(e)) })}>{t('removed.forget')}</Button>} />
  )
}

/** The devices a person removed that discovery keeps out (GET /inventory/removed): collapsed, only while there are any. Forget lets the
 *  device come back under To review the next time a sensor sees it. */
function RemovedGroup() {
  const { t } = useTranslation('inventory')
  const q = useRemovedDevices()
  const items = q.data?.items ?? []
  const columns: ColumnDef<RemovedDevice>[] = [{ id: 'text', header: t('removed.col'), accessorFn: (r) => [r.name, r.ip ?? '', r.removed_by].join(' ') }]
  if (!items.length) return null
  return (
    <details data-testid="removed-devices" className="rounded-md border border-rule p-3">
      <summary className="cursor-pointer text-sm font-medium">{t('removed.title', { count: items.length })}</summary>
      <p className="mt-2 text-meta text-muted">{t('removed.body')}</p>
      <div className="mt-3">
        <DataTable urlKey="removed" caption={t('removed.title', { count: items.length })} data={items} columns={columns} pageSize={50} list={(r) => <RemovedRow r={r} />} />
      </div>
    </details>
  )
}

/** S-INV-3, #849 "To review": devices found by a scan or by listening and not approved yet; approve, ignore or remove. Under them the
 *  collapsed Seen briefly group (`seen`) and the devices a person removed. The switch "notify me about new devices". `items` is the
 *  list after the search; `total` before it. */
export function PendingPanel({ items, seen = [], total, notifyNew, notifyAvailable, search, filtered, onClear, none, sameAs }: {
  items: DeviceRow[]; seen?: DeviceRow[]; total: number; notifyNew: boolean; notifyAvailable: boolean; search?: ReactNode; filtered?: boolean; onClear?: () => void
  /** What an empty filtered list says instead of "No devices match." (the search's software answer not in yet, or failed). */
  none?: ReactNode
  /** The names of the devices each row may be the same machine as (GET /inventory/possible-same). */
  sameAs?: ReadonlyMap<string, string[]>
}) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const admin = useCan('admin')
  const notify = useNotifyNew()
  const pending = [...items].sort((a, b) => b.first_seen.localeCompare(a.first_seen))
  const approveAll = useApproveAll()
  const [confirmAll, setConfirmAll] = useState(false)
  // Devices marked unknown are left for a person to look at one by one
  const ready = pending.filter((d) => !d.suspicious)
  return (
    <section aria-labelledby="pending-title" className="mb-8 grid min-w-0 gap-3">
      {total ? search : null}
      <ListSummary id="review" actions={
        <>
          {ready.length > 1 ? <Button size="sm" variant="primary" disabled={!can || approveAll.isPending} busy={approveAll.isPending} busyLabel={t('inventory:pending.adding')}
            title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })} onClick={() => setConfirmAll(true)}>{t('pending.approveAll', { count: ready.length })}</Button> : null}
          <span className="inline-flex items-center gap-2">
            <Switch id="notify-new" checked={notifyNew} disabled={!can || notify.isPending} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}
              onCheckedChange={(v) => notify.mutate(v, { onSuccess: () => toast.success(v ? t('pending.notifyOn') : t('pending.notifyOff')), onError: (e) => toast.error(errMsg(e)) })} />
            <label htmlFor="notify-new" className="text-sm">{t('pending.notify')}</label>
          </span>
        </>
      }>
        <span id="pending-title">{total ? t('pending.title', { count: total }) : t('pending.titleNone')}</span>
        <InfoTip topic={t('tabs.review')}><p>{t('pending.description')} {t('pending.choiceHint')}</p><p>{t('pending.descriptionInfo')}</p></InfoTip>
      </ListSummary>
      <Dialog open={confirmAll} onOpenChange={setConfirmAll}>
        <DialogContent title={t('pending.approveAllTitle', { count: ready.length })} description={t('pending.approveAllBody', { count: ready.length })}>
          <DialogFooter>
            <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
            <Button variant="primary" busy={approveAll.isPending} busyLabel={t('inventory:pending.adding')}
              onClick={() => approveAll.mutate(ready.map((d) => d.id), {
                onSuccess: (n) => { setConfirmAll(false); toast.success(t('pending.approveAllDone', { count: n })) },
                onError: (e) => { setConfirmAll(false); toast.error(t('pending.approveAllFailed', { done: (e as { done?: number }).done ?? 0, count: ready.length, error: errMsg(e) })) },
              })}>{t('pending.approveAllConfirm', { count: ready.length })}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {notifyNew && !notifyAvailable ? <TurnOnModule id="notify" reason={t('pending.notifyOff2')} /> : null}
      {/* The channels page is an administrator's: others get the sentence without a link they cannot open */}
      {notifyNew && notifyAvailable ? <p className="text-meta text-muted">{t('pending.notifyVia')}{admin ? <> <Link className="text-accent underline-offset-4 hover:underline" to="/settings/channels">{t('pending.openChannels')}</Link></> : null}</p> : null}
      {pending.length ? (
        <Card flush>
          <RowList flush label={t('pending.title', { count: pending.length })}>
            {pending.map((d) => <PendingItem key={d.id} d={d} sameAs={sameAs?.get(d.id) ?? []} />)}
          </RowList>
        </Card>
      ) : filtered && !seen.length ? (
        <Card className="py-6 text-center text-muted">
          <span className="inline-flex flex-wrap items-center justify-center gap-x-2">{none ?? t('search.none')}{onClear ? <Button size="sm" variant="link" onClick={onClear}>{t('search.clear')}</Button> : null}</span>
        </Card>
      ) : null}
      <SeenBriefly items={seen} sameAs={sameAs} />
      <RemovedGroup />
    </section>
  )
}
