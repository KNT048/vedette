import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/common/Card'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Notice } from '@/components/common/PageHeader'
import { QueryState } from '@/components/common/States'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { kindLabel } from '@/lib/deviceTypes'
import { useDeviceAction, useIgnoredDevices } from './api'
import { errMsg } from './kinds'
import { nameOf } from './nameOf'
import type { DeviceDetail, DeviceRow } from './types'

/** A private (locally administered) MAC: the 0x02 bit of the first byte. Phones and laptops pick one per network and change it. */
const privateMAC = (mac: string | null | undefined) => !!mac && /^[0-9a-f]{2}/i.test(mac) && (parseInt(mac.slice(0, 2), 16) & 2) === 2

/** Confirm Ignore. Says what stops, what still alerts (trap hits, intrusion detection), and, for a private
 *  MAC, that a phone that changes it comes back in To review as a new device. */
export function IgnoreDialog({ open, onOpenChange, name, mac, findings, pending, onConfirm }: {
  open: boolean; onOpenChange: (o: boolean) => void; name: string; mac: string | null; findings: number; pending: boolean; onConfirm: () => void
}) {
  const { t } = useTranslation('inventory')
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={t('ignore.title', { name })} description={t('ignore.body')}>
        <ul className="grid list-disc gap-1 pl-5 text-sm">
          <li>{t('ignore.review')}</li>
          <li>{t('ignore.scans')}</li>
          <li>{findings > 0 ? t('ignore.findings') : t('ignore.noFindings')}</li>
        </ul>
        <p className="text-sm"><strong className="font-medium">{t('ignore.stillTitle')}</strong> {t('ignore.still')}</p>
        {privateMAC(mac) ? <p className="text-sm text-muted">{t('ignore.privateMac', { mac })}</p> : null}
        <p className="text-meta text-muted">{t('ignore.undo')}</p>
        <DialogFooter>
          <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
          <Button variant="primary" busy={pending} busyLabel={t('common:busy.saving')} onClick={onConfirm}>{t('ignore.confirm')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** The device page of an ignored device: when, what that means, and Stop ignoring (back to To review). */
export function IgnoredNotice({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const act = useDeviceAction(d.asset.id)
  const name = nameOf(d.asset, kindLabel(d.asset.kind))
  return (
    <Notice tone="accent" title={t('ignored.title')} actions={
      <Button disabled={!can || act.ignore.isPending} busy={act.ignore.isPending} busyLabel={t('common:busy.saving')} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}
        onClick={() => act.ignore.mutate(false, { onSuccess: () => toast.success(t('ignored.undone', { name })), onError: (e) => toast.error(errMsg(e)) })}>{t('ignored.stop')}</Button>
    }>
      {t('ignored.body', { when: fmtRelative(d.asset.ignored_at ?? d.asset.last_seen) })}
    </Notice>
  )
}

function IgnoredItem({ d }: { d: DeviceRow }) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const act = useDeviceAction(d.id)
  const name = nameOf(d, kindLabel(d.kind))
  return (
    <div className="grid gap-3 md:grid-cols-[1fr_auto] md:items-center">
      <div className="grid gap-0.5">
        <Link to={`/devices/${d.id}`} className="font-medium text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">{name}</Link>
        <p className="text-meta text-muted">
          {[d.ip, d.mac, kindLabel(d.kind)].filter((x) => x && x !== '—').join(', ')}. {t('ignored.since', { when: fmtRelative(d.ignored_at ?? d.last_seen) })}
        </p>
      </div>
      <div>
        <Button size="sm" disabled={!can || act.ignore.isPending} busy={act.ignore.isPending} busyLabel={t('common:busy.saving')} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}
          onClick={() => void act.ignore.mutateAsync(false).then(() => toast.success(t('ignored.undone', { name })), (e: unknown) => toast.error(errMsg(e)))}>{t('ignored.stop')}</Button>
      </div>
    </div>
  )
}

/** The Ignored tab of /devices: devices a person said need no watching, each with Stop ignoring. */
export function IgnoredPanel() {
  const { t } = useTranslation('inventory')
  const q = useIgnoredDevices()
  // what the list's search reads: the name, the address, the MAC and the type
  const searchCols: ColumnDef<DeviceRow>[] = [{ id: 'text', accessorFn: (d) => [nameOf(d, kindLabel(d.kind)), d.ip, d.mac, kindLabel(d.kind)].join(' ') }]
  return (
    <section aria-labelledby="ignored-title" className="mb-8 grid min-w-0 gap-3">
      <div className="grid gap-0.5">
        <h2 id="ignored-title" className="text-base font-semibold">{t('ignored.listTitle')}</h2>
        <p className="max-w-3xl text-meta text-muted">{t('ignored.description')}</p>
      </div>
      <QueryState query={q}>
        {(r) => r.items.length ? (
          <DataTable urlKey="ignored-devices" caption={t('ignored.listTitle')} columns={searchCols} pageSize={25}
            data={[...r.items].sort((a, b) => (b.ignored_at ?? '').localeCompare(a.ignored_at ?? ''))} list={(d) => <IgnoredItem d={d} />} />
        ) : <Card className="py-6 text-center text-muted">{t('ignored.none')}</Card>}
      </QueryState>
    </section>
  )
}
