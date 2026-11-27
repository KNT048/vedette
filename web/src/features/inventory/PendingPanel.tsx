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
import { useApproveAll, useDeviceAction, useNotifyNew } from './api'
import { Dialog, DialogContent, DialogFooter, DialogClose } from '@/components/ui/dialog'
import { TurnOnModule } from './Inline'
import { IgnoreDialog } from './IgnoreDevice'
import { errMsg } from './kinds'
import { nameOf } from './nameOf'
import type { DeviceRow } from './types'
import { kindLabel } from '@/lib/deviceTypes'
import { InfoTip } from '@/components/common/InfoTip'
import { ListSummary } from '@/components/common/ListParts'
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
    <li className="grid gap-3 px-4 py-3 md:grid-cols-[1fr_auto] md:items-center">
      <div className="grid gap-0.5">
        <div className="flex flex-wrap items-center gap-2">
          <Link to={`/devices/${d.id}`} className="font-medium text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">{name}</Link>
          <RiskMarker id={d.id} risk={d.risk} />
          {d.suspicious ? <Chip tone="warn">{t('chip.suspicious')}</Chip> : null}
        </div>
        <p className="text-meta text-muted">
          {[d.ip, d.mac, kindLabel(d.kind)].filter((x) => x && x !== '—').join(', ')}. {t('pending.firstSeen', { when: fmtRelative(d.first_seen) })}
        </p>
        <SameHint id={d.id} others={sameAs} />
      </div>
      {/* mutateAsync: the row leaves this list when the list reloads, which would drop a mutate() callback and its toast (the toast links the device). */}
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="primary" disabled={!can || busy} busy={act.approve.isPending} busyLabel={t('inventory:pending.adding')} title={title ?? t('pending.approveLabel', { name })}
          aria-label={t('pending.approveLabel', { name })} onClick={() => void act.approve.mutateAsync().then(() => toast.success(t('pending.approved', { name }), { description: t('pending.findLater'), action: { label: t('add.openDevice'), onClick: () => void navigate(`/devices/${d.id}`) } }), fail)}>{t('pending.approve')}</Button>
        {/* Ignore replaces "Remove unknown mark" here; marking stays on the device page. */}
        <Button size="sm" disabled={!can || busy} busy={act.ignore.isPending} busyLabel={t('common:busy.saving')} title={title} onClick={() => setIgn(true)}>{t('pending.ignore')}</Button>
      </div>
      {/* mutateAsync: the row leaves this list when the list reloads (as Approve) */}
      <IgnoreDialog open={ign} onOpenChange={setIgn} name={name} mac={d.mac} findings={d.findings_count} pending={act.ignore.isPending}
        onConfirm={() => void act.ignore.mutateAsync(true).then(() => { setIgn(false); toast.success(t('pending.ignored', { name }), { description: t('pending.ignoredLater') }) }, fail)} />
    </li>
  )
}

/** S-INV-3, #849 "To review": devices found by a scan or by listening and not approved yet; approve, ignore or remove.
 *  The switch "notify me about new devices". `items` is the list after the search; `total` before it. */
export function PendingPanel({ items, total, notifyNew, notifyAvailable, search, filtered, onClear, none, sameAs }: {
  items: DeviceRow[]; total: number; notifyNew: boolean; notifyAvailable: boolean; search?: ReactNode; filtered?: boolean; onClear?: () => void
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
          <ul className="divide-y divide-rule" aria-label={t('pending.title', { count: pending.length })}>
            {pending.map((d) => <PendingItem key={d.id} d={d} sameAs={sameAs?.get(d.id) ?? []} />)}
          </ul>
        </Card>
      ) : filtered ? (
        <Card className="py-6 text-center text-muted">
          <span className="inline-flex flex-wrap items-center justify-center gap-x-2">{none ?? t('search.none')}{onClear ? <Button size="sm" variant="link" onClick={onClear}>{t('search.clear')}</Button> : null}</span>
        </Card>
      ) : null}
    </section>
  )
}
