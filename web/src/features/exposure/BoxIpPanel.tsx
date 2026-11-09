import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { RefreshCw, Trash2 } from 'lucide-react'
import { Panel, Section } from '@/components/common/PageHeader'
import { EmptyState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Label, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { fmtDate, fmtDateTime, fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { OwnerChip } from './OwnerChip'
import { useDeleteTarget, useDetectBoxIp, useSaveBoxIpSettings } from './api'
import type { BoxIpSettings, Target } from './types'

const PRESETS = [1, 5, 10, 15, 30, 60, 120, 360, 720, 1440]
const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

/**
 * S-EXP-1, public IPs of this box. The box finds its own public IPs (first at start, then every interval, three probes each) and renews each one it
 * sees for 30 days. The customer can turn auto-detect off, change the interval, run a check now and remove an IP. No IP is ever typed in.
 */
export function BoxIpPanel({ items, settings }: { items: Target[]; settings: BoxIpSettings }) {
  const { t } = useTranslation('exposure')
  const can = useCan('admin')
  const save = useSaveBoxIpSettings()
  const detect = useDetectBoxIp()
  const every = (n: number) => (PRESETS.includes(n) ? t(`boxIp.every.${n}`) : t('boxIp.every.other', { count: n }))
  const options = PRESETS.includes(settings.interval_min) ? PRESETS : [...PRESETS, settings.interval_min].sort((a, b) => a - b)
  const locked = !can ? t('common:needRole', { role: t('common:role.admin') }) : undefined
  const run = settings.last_run

  const setAuto = (auto: boolean) =>
    save.mutate({ auto, interval_min: settings.interval_min }, { onSuccess: () => toast.success(auto ? t('boxIp.toastOn') : t('boxIp.toastOff')), onError: (e) => toast.error(errMsg(e)) })
  const changeInterval = (n: number) =>
    save.mutate({ auto: settings.auto, interval_min: n }, { onSuccess: () => toast.success(t('boxIp.toastInterval', { every: every(n) })), onError: (e) => toast.error(errMsg(e)) })
  const detectNow = () => detect.mutate(undefined, { onSuccess: (r) => toast.success(t('boxIp.toast', { message: r.message })), onError: (e) => toast.error(errMsg(e)) })

  const columns: ColumnDef<Target>[] = [
    { id: 'ip', header: t('boxIp.col.ip'), accessorFn: (r) => r.value, cell: ({ row }) => <Link className="font-medium text-accent underline-offset-4 hover:underline" to={`/exposure/${row.original.id}`}>{row.original.value}</Link> },
    { id: 'status', header: t('boxIp.col.status'), accessorFn: (r) => r.status, cell: ({ row }) => <OwnerChip target={row.original} /> },
    { id: 'seen', header: t('boxIp.col.seen'), accessorFn: (r) => r.verified_at ?? '', cell: ({ row }) => <span title={fmtDateTime(row.original.verified_at)}>{fmtRelative(row.original.verified_at)}</span> },
    { id: 'expires', header: t('boxIp.col.expires'), accessorFn: (r) => r.expires_at ?? '', cell: ({ row }) => <span>{fmtDate(row.original.expires_at)}</span> },
    { id: 'scan', header: t('boxIp.col.scan'), enableSorting: false, cell: ({ row }) => (row.original.blocked_reason ? <span className="text-[13px] text-warn">{t(`blocked.${row.original.blocked_reason}`)}</span> : <span className="text-[13px]">{t('targets.ready')}</span>) },
    { id: 'remove', header: t('boxIp.col.remove'), enableSorting: false, cell: ({ row }) => <RemoveIp target={row.original} /> },
  ]

  return (
    <Section id="box-ip" title={t('boxIp.title')} description={t('boxIp.description')}>
      <div className="grid gap-4">
        <Panel className="grid gap-4 p-4">
          <p className="text-sm font-medium">{settings.auto ? t('boxIp.state.on', { every: every(settings.interval_min) }) : t('boxIp.state.off')}</p>
          <div className="flex flex-wrap items-end gap-x-6 gap-y-3">
            <div className="flex min-h-10 items-center gap-3">
              <Switch id="box-auto" checked={settings.auto} disabled={!can || save.isPending} onCheckedChange={setAuto} title={locked} />
              <Label htmlFor="box-auto">{t('boxIp.switch')}</Label>
            </div>
            {settings.auto ? (
              <Field label={t('boxIp.interval')} htmlFor="box-interval" className="w-44">
                <Select id="box-interval" value={settings.interval_min} disabled={!can || save.isPending} title={locked} onChange={(e) => changeInterval(Number(e.target.value))}>
                  {options.map((n) => <option key={n} value={n}>{PRESETS.includes(n) ? t(`boxIp.option.${n}`) : t('boxIp.option.other', { count: n })}</option>)}
                </Select>
              </Field>
            ) : null}
            <Button onClick={detectNow} disabled={!can || detect.isPending} title={locked}>
              <RefreshCw className={detect.isPending ? 'animate-spin motion-reduce:animate-none' : undefined} />{detect.isPending ? t('boxIp.detecting') : t('boxIp.detect')}
            </Button>
          </div>
          <p className="max-w-3xl text-[13px] text-muted">{t('boxIp.switchHint')}</p>
          {!can ? <p className="text-[13px] text-muted">{locked}</p> : null}
          {run ? (
            <div role="status" className={`rounded-md border px-3 py-2 text-sm ${run.ok ? 'border-ok/40 bg-ok-soft' : 'border-warn/50 bg-warn-soft/60'}`}>
              <p className="mb-1 flex flex-wrap items-center gap-2">
                <Chip tone={run.ok ? 'ok' : 'warn'}>{run.ok ? t('boxIp.last.ok') : t('boxIp.last.failed')}</Chip>
                <span className="text-[12px] text-muted">{t('boxIp.last.title')} {t('boxIp.last.at', { time: fmtDateTime(run.at) })}</span>
              </p>
              <p>{run.message}</p>
            </div>
          ) : <p className="text-[13px] text-muted">{t('boxIp.last.never')}</p>}
          <details className="max-w-3xl text-[13px] text-muted">
            <summary className="cursor-pointer text-sm text-ink">{t('boxIp.help.summary')}</summary>
            <ul className="mt-2 grid list-disc gap-1.5 pl-5">
              <li>{t('boxIp.help.how')}</li><li>{t('boxIp.help.result')}</li><li>{t('boxIp.help.why')}</li><li>{t('boxIp.help.refuse')}</li><li>{t('boxIp.help.limit')}</li>
            </ul>
          </details>
        </Panel>
        <DataTable caption={t('boxIp.caption')} data={items} columns={columns} pageSize={20}
          mobileRow={(r) => (
            <div className="grid gap-1.5">
              <div className="flex items-center justify-between gap-2">
                <Link className="break-all font-medium text-accent underline-offset-4 hover:underline" to={`/exposure/${r.id}`}>{r.value}</Link>
                <RemoveIp target={r} />
              </div>
              <div className="flex flex-wrap items-center gap-2"><OwnerChip target={r} /></div>
              <p className="text-[13px] text-muted">{t('boxIp.col.seen')}: {fmtRelative(r.verified_at)}. {t('boxIp.col.expires')}: {fmtDate(r.expires_at)}.</p>
              <p className="text-[13px] text-muted">{r.blocked_reason ? t(`blocked.${r.blocked_reason}`) : t('targets.ready')}</p>
            </div>
          )}
          empty={<EmptyState title={t('boxIp.empty.title')}>{settings.auto ? t('boxIp.empty.on', { every: every(settings.interval_min) }) : t('boxIp.empty.off')}</EmptyState>} />
        <p className="max-w-3xl text-[13px] text-muted">{t('boxIp.comeBack')}</p>
      </div>
    </Section>
  )
}

function RemoveIp({ target }: { target: Target }) {
  const { t } = useTranslation('exposure')
  const can = useCan('admin')
  const del = useDeleteTarget()
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button onClick={() => setOpen(true)} disabled={!can} aria-label={t('boxIp.removeLabel', { value: target.value })} title={can ? undefined : t('common:needRole', { role: t('common:role.admin') })}><Trash2 />{t('boxIp.col.remove')}</Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent title={t('boxIp.remove.title', { value: target.value })} description={t('boxIp.remove.body')}>
          <p className="text-sm">{t('boxIp.comeBack')}</p>
          <DialogFooter>
            <Button onClick={() => setOpen(false)}>{t('common:cancel')}</Button>
            <Button variant="danger" disabled={del.isPending} onClick={() => { del.mutateAsync(target.id).then(() => { toast.success(t('boxIp.remove.toast', { value: target.value })); setOpen(false) }, (e: unknown) => toast.error(errMsg(e))) }}>{t('boxIp.remove.confirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
