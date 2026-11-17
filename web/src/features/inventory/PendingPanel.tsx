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
import { useDeviceAction, useNotifyNew } from './api'
import { TurnOnModule } from './Inline'
import { DeleteDialog } from './DeleteDialog'
import { errMsg } from './kinds'
import { nameOf } from './nameOf'
import type { DeviceRow } from './types'
import { kindLabel } from '@/lib/deviceTypes'
import { InfoTip } from '@/components/common/InfoTip'
import { SameHint } from './SameDevice'
import { RiskMarker } from './RiskMarker'

function PendingItem({ d, sameAs }: { d: DeviceRow; sameAs: string[] }) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const act = useDeviceAction(d.id)
  const navigate = useNavigate()
  const [del, setDel] = useState(false)
  const name = nameOf(d, kindLabel(d.kind))
  const title = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const busy = act.approve.isPending || act.suspicious.isPending || act.remove.isPending
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
      {/* mutateAsync: the row leaves this list when the list reloads, which would drop a mutate() callback and its toast (D-471: the toast links the device). */}
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="primary" disabled={!can || busy} busy={act.approve.isPending} busyLabel={t('common:busy.approving')} title={title} onClick={() => void act.approve.mutateAsync().then(() => toast.success(t('pending.approved', { name }), { description: t('pending.findLater'), action: { label: t('add.openDevice'), onClick: () => void navigate(`/devices/${d.id}`) } }), fail)}>{t('pending.approve')}</Button>
        <Button size="sm" disabled={!can || busy} busy={act.suspicious.isPending} busyLabel={t('common:busy.saving')} title={title} onClick={() => act.suspicious.mutate(!d.suspicious, { onSuccess: () => toast.success(d.suspicious ? t('pending.unmarked', { name }) : t('pending.marked', { name })), onError: fail })}>
          {d.suspicious ? t('pending.unmark') : t('pending.mark')}
        </Button>
        <Button size="sm" disabled={!can || busy} busy={act.remove.isPending} busyLabel={t('common:busy.deleting')} title={title} onClick={() => setDel(true)}>{t('pending.delete')}</Button>
      </div>
      <DeleteDialog open={del} onOpenChange={setDel} name={name} findings={d.findings_count} pending={act.remove.isPending}
        onConfirm={() => act.remove.mutate(undefined, { onSuccess: () => { setDel(false); toast.success(t('delete.done', { name })) }, onError: fail })} />
    </li>
  )
}

/** S-INV-3, #849 "To review": devices found by a scan or by listening and not approved yet; approve, mark unknown or remove.
 *  The switch "notify me about new devices". `items` is the list after the search; `total` before it. */
export function PendingPanel({ items, total, notifyNew, notifyAvailable, search, filtered, onClear, sameAs }: {
  items: DeviceRow[]; total: number; notifyNew: boolean; notifyAvailable: boolean; search?: ReactNode; filtered?: boolean; onClear?: () => void
  /** D-599: the names of the devices each row may be the same machine as (GET /inventory/possible-same). */
  sameAs?: ReadonlyMap<string, string[]>
}) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const admin = useCan('admin')
  const notify = useNotifyNew()
  const pending = [...items].sort((a, b) => b.first_seen.localeCompare(a.first_seen))
  return (
    <section aria-labelledby="pending-title" className="mb-8 grid min-w-0 gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="grid gap-0.5">
          <div className="flex items-center gap-1">
            <h2 id="pending-title" className="text-base font-semibold">{total ? t('pending.title', { count: total }) : t('pending.titleNone')}</h2>
            <InfoTip topic={t('tabs.review')}>{t('pending.descriptionInfo')}</InfoTip>
          </div>
          <p className="max-w-3xl text-meta text-muted">{t('pending.description')}</p>
        </div>
        <div className="flex items-center gap-2">
          <Switch id="notify-new" checked={notifyNew} disabled={!can || notify.isPending} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}
            onCheckedChange={(v) => notify.mutate(v, { onSuccess: () => toast.success(v ? t('pending.notifyOn') : t('pending.notifyOff')), onError: (e) => toast.error(errMsg(e)) })} />
          <label htmlFor="notify-new" className="text-sm">{t('pending.notify')}</label>
        </div>
      </div>
      {notifyNew && !notifyAvailable ? <TurnOnModule id="notify" reason={t('pending.notifyOff2')} /> : null}
      {/* kien G5: the channels page is an administrator's: others get the sentence without a link they cannot open */}
      {notifyNew && notifyAvailable ? <p className="text-meta text-muted">{t('pending.notifyVia')}{admin ? <> <Link className="text-accent underline-offset-4 hover:underline" to="/settings/channels">{t('pending.openChannels')}</Link></> : null}</p> : null}
      {total ? search : null}
      {pending.length ? (
        <Card flush>
          <ul className="divide-y divide-rule" aria-label={t('pending.title', { count: pending.length })}>
            {pending.map((d) => <PendingItem key={d.id} d={d} sameAs={sameAs?.get(d.id) ?? []} />)}
          </ul>
        </Card>
      ) : filtered ? (
        <Card className="py-6 text-center text-muted">
          <span className="inline-flex flex-wrap items-center justify-center gap-x-2">{t('search.none')}{onClear ? <Button size="sm" variant="link" onClick={onClear}>{t('search.clear')}</Button> : null}</span>
        </Card>
      ) : null}
    </section>
  )
}
