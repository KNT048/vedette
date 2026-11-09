import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { Chip } from '@/components/common/StatusChip'
import { Panel } from '@/components/common/PageHeader'
import { fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useDeviceAction, useNotifyNew } from './api'
import { DeleteDialog } from './DeleteDialog'
import { errMsg } from './kinds'
import { nameOf } from './nameOf'
import type { DeviceRow, DevicesResponse } from './types'

function PendingItem({ d }: { d: DeviceRow }) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const act = useDeviceAction(d.id)
  const [del, setDel] = useState(false)
  const name = nameOf(d, t(`kind.${d.kind}`))
  const title = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const busy = act.approve.isPending || act.suspicious.isPending || act.remove.isPending
  const fail = (e: unknown) => toast.error(errMsg(e))
  return (
    <li className="grid gap-3 px-4 py-3 md:grid-cols-[1fr_auto] md:items-center">
      <div className="grid gap-0.5">
        <div className="flex flex-wrap items-center gap-2">
          <Link to={`/devices/${d.id}`} className="font-medium text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">{name}</Link>
          {d.suspicious ? <Chip tone="warn">{t('chip.suspicious')}</Chip> : null}
        </div>
        <p className="text-[13px] text-muted">
          {[d.ip, d.mac, t(`kind.${d.kind}`)].filter((x) => x && x !== '—').join(', ')}. {t('pending.firstSeen', { when: fmtRelative(d.first_seen) })}
        </p>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button size="sm" variant="primary" disabled={!can || busy} title={title} onClick={() => act.approve.mutate(undefined, { onSuccess: () => toast.success(t('pending.approved', { name })), onError: fail })}>{t('pending.approve')}</Button>
        <Button size="sm" disabled={!can || busy} title={title} onClick={() => act.suspicious.mutate(!d.suspicious, { onSuccess: () => toast.success(d.suspicious ? t('pending.unmarked', { name }) : t('pending.marked', { name })), onError: fail })}>
          {d.suspicious ? t('pending.unmark') : t('pending.mark')}
        </Button>
        <Button size="sm" disabled={!can || busy} title={title} onClick={() => setDel(true)}>{t('pending.delete')}</Button>
      </div>
      <DeleteDialog open={del} onOpenChange={setDel} name={name} findings={d.findings_count} pending={act.remove.isPending}
        onConfirm={() => act.remove.mutate(undefined, { onSuccess: () => { setDel(false); toast.success(t('delete.done', { name })) }, onError: fail })} />
    </li>
  )
}

/** S-INV-3: thiết bị mới vào "chưa duyệt"; duyệt, đánh dấu lạ hoặc xoá. Công tắc "báo khi có thiết bị mới". */
export function PendingPanel({ data }: { data: DevicesResponse }) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const notify = useNotifyNew()
  const pending = data.items.filter((d) => !d.approved).sort((a, b) => b.first_seen.localeCompare(a.first_seen))
  return (
    <section aria-labelledby="pending-title" className="mb-8">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div className="grid gap-0.5">
          <h2 id="pending-title" className="text-base font-semibold">{pending.length ? t('pending.title', { count: pending.length }) : t('pending.titleNone')}</h2>
          <p className="max-w-3xl text-[13px] text-muted">{t('pending.description')}</p>
        </div>
        <div className="flex items-center gap-2">
          <Switch id="notify-new" checked={data.notify_new} disabled={!can || notify.isPending} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}
            onCheckedChange={(v) => notify.mutate(v, { onSuccess: () => toast.success(v ? t('pending.notifyOn') : t('pending.notifyOff')), onError: (e) => toast.error(errMsg(e)) })} />
          <label htmlFor="notify-new" className="text-sm">{t('pending.notify')}</label>
        </div>
      </div>
      {data.notify_new && !data.notify_available ? <p className="mb-3 text-[13px] text-warn">{t('pending.notifyOff2')} <Link className="underline" to="/settings/modules">{t('pending.openModules')}</Link></p> : null}
      {data.notify_new && data.notify_available ? <p className="mb-3 text-[13px] text-muted">{t('pending.notifyVia')} <Link className="text-accent underline-offset-4 hover:underline" to="/settings/channels">{t('pending.openChannels')}</Link></p> : null}
      {pending.length ? (
        <Panel>
          <ul className="divide-y divide-rule" aria-label={t('pending.title', { count: pending.length })}>
            {pending.map((d) => <PendingItem key={d.id} d={d} />)}
          </ul>
        </Panel>
      ) : null}
    </section>
  )
}
