import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { RefreshCw } from 'lucide-react'
import { Panel, Section } from '@/components/common/PageHeader'
import { EmptyState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Button } from '@/components/ui/button'
import { Field, FieldHint, Label, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { InfoTip } from '@/components/common/InfoTip'
import { BusyNote } from '@/components/common/BusyNote'
import { fmtDate, fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { InfoLine } from '@/components/common/InfoLine'
import { useDetectBoxIp, useRestoreIgnored, useSaveBoxIpSettings } from './api'
import type { BoxIpSettings, IgnoredIp } from './types'

const PRESETS = [5, 10, 15, 30, 60, 120, 360, 720, 1440]
const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

/**
 * S-EXP-1, the box's public-IP settings (the Settings tab). The box finds its own public IPs (first at start, then every interval, three probes each),
 * adds each one to the target list and renews it for 90 days each time it sees it. The customer can turn auto-detect off, change the interval and run a
 * check now; the IPs themselves are rows of the target list, and the Ignored list below keeps the ones detection must not add again.
 */
export function BoxIpPanel({ settings, ignored }: { settings: BoxIpSettings; ignored: IgnoredIp[] }) {
  const { t } = useTranslation('exposure')
  const can = useCan('admin')
  const save = useSaveBoxIpSettings()
  const detect = useDetectBoxIp()
  const every = (n: number) => (PRESETS.includes(n) ? t(`boxIp.every.${n}`) : t('boxIp.every.other', { count: n }))
  const options = PRESETS.includes(settings.interval_min) ? PRESETS : [...PRESETS, settings.interval_min].sort((a, b) => a - b)
  const locked = !can ? t('common:needRole', { role: t('common:role.admin') }) : undefined
  const run = settings.last_run
  // The 10 attempts an hour are used up: say so on the button and next to it, not only in a toast.
  const wait = settings.retry_in_min ?? null
  const waitText = wait === null ? undefined : t('boxIp.retry', { count: wait })
  const setAuto = (auto: boolean) =>
    save.mutate({ auto, interval_min: settings.interval_min }, { onSuccess: () => toast.success(auto ? t('boxIp.toastOn') : t('boxIp.toastOff')), onError: (e) => toast.error(errMsg(e)) })
  const changeInterval = (n: number) =>
    save.mutate({ auto: settings.auto, interval_min: n }, { onSuccess: () => toast.success(t('boxIp.toastInterval', { every: every(n) })), onError: (e) => toast.error(errMsg(e)) })
  const detectNow = () => detect.mutate(undefined, { onSuccess: (r) => toast.success(t('boxIp.toast', { message: r.message })), onError: (e) => toast.error(errMsg(e)) })

  return (
    <>
    <Section id="box-ip" title={t('boxIp.title')} description={t('boxIp.description')} info={<>
      <p>{t('boxIp.help.how')}</p><p>{t('boxIp.help.result')}</p><p>{t('boxIp.help.why')}</p><p>{t('boxIp.help.refuse')}</p><p>{t('boxIp.help.limit')}</p><p>{t('boxIp.comeBack')}</p>
    </>}>
      <div className="grid gap-4">
        <Panel className="grid gap-4 p-4">
          <p className="text-sm font-medium">{settings.auto ? t('boxIp.state.on', { every: every(settings.interval_min) }) : t('boxIp.state.off')}</p>
          <div className="grid gap-2">
          <div className="flex flex-wrap items-end gap-x-6 gap-y-3">
            <div className="flex min-h-10 items-center gap-3">
              <Switch id="box-auto" checked={settings.auto} disabled={!can || save.isPending} onCheckedChange={setAuto} title={locked} />
              <span className="flex items-center gap-1"><Label htmlFor="box-auto">{t('boxIp.switch')}</Label><InfoTip topic={t('boxIp.switch')}>{t('boxIp.switchHint')}</InfoTip></span>
            </div>
            {settings.auto ? (
              <Field label={t('boxIp.interval')} htmlFor="box-interval" className="w-44">
                <Select id="box-interval" value={settings.interval_min} disabled={!can || save.isPending} title={locked} onChange={(e) => changeInterval(Number(e.target.value))}>
                  {options.map((n) => <option key={n} value={n}>{PRESETS.includes(n) ? t(`boxIp.option.${n}`) : t('boxIp.option.other', { count: n })}</option>)}
                </Select>
              </Field>
            ) : null}
            <Button onClick={detectNow} disabled={!can || wait !== null} busy={detect.isPending} busyLabel={t('boxIp.detecting')} title={locked ?? waitText}>
              <RefreshCw />{t('boxIp.detect')}
            </Button>
          </div>
          {settings.auto ? <FieldHint>{t('boxIp.limit')}</FieldHint> : null}
          </div>
          {/* A full check asks three public services over 5 rounds (5 s each at most) */}
          <BusyNote busy={detect.isPending}>{t('boxIp.detectWaiting')}</BusyNote>
          {waitText ? <FieldHint tone="warn">{waitText}</FieldHint> : null}
          {!can ? <FieldHint>{locked}</FieldHint> : null}
          {run ? (
            <div role="status" className={`rounded-md border px-3 py-2 text-sm ${run.ok ? 'border-ok/40 bg-ok-soft' : 'border-warn/50 bg-warn-soft/60'}`}>
              <p className="mb-1 flex flex-wrap items-center gap-2">
                <Chip tone={run.ok ? 'ok' : 'warn'}>{run.ok ? t('boxIp.last.ok') : t('boxIp.last.failed')}</Chip>
                <span className="text-caption text-muted">{t('boxIp.last.title')} {t('boxIp.last.at', { time: fmtDateTime(run.at) })}</span>
              </p>
              <p>{run.message}</p>
            </div>
          ) : <InfoLine className="text-meta text-muted" topic={t('boxIp.last.title')} info={t('boxIp.last.neverInfo')}>{t('boxIp.last.never')}</InfoLine>}
        </Panel>
      </div>
    </Section>
    <IgnoredList ignored={ignored} />
    </>
  )
}

/** The Ignored list. It only blocks: Restore lets detection add the IP again, it never adds or allows anything itself. */
function IgnoredList({ ignored }: { ignored: IgnoredIp[] }) {
  const { t } = useTranslation('exposure')
  const can = useCan('admin')
  const restore = useRestoreIgnored()
  const go = (ip: string) => restore.mutate(ip, { onSuccess: () => toast.success(t('boxIp.ignored.toast', { value: ip })), onError: (e) => toast.error(errMsg(e)) })
  const btn = (r: IgnoredIp) => <Button onClick={() => go(r.value)} disabled={!can || restore.isPending} busy={restore.isPending && restore.variables === r.value} busyLabel={t('common:busy.restoring')} aria-label={t('boxIp.ignored.restoreLabel', { value: r.value })} title={can ? undefined : t('common:needRole', { role: t('common:role.admin') })}>{t('boxIp.ignored.restore')}</Button>
  const columns: ColumnDef<IgnoredIp>[] = [
    { id: 'ip', header: t('boxIp.ignored.col.ip'), accessorFn: (r) => r.value, cell: ({ row }) => <span className="font-medium">{row.original.value}</span> },
    { id: 'by', header: t('boxIp.ignored.col.by'), accessorFn: (r) => r.ignored_by },
    { id: 'at', header: t('boxIp.ignored.col.at'), accessorFn: (r) => r.ignored_at, cell: ({ row }) => <span title={fmtDateTime(row.original.ignored_at)}>{fmtDate(row.original.ignored_at)}</span> },
    { id: 'restore', header: t('boxIp.ignored.col.restore'), enableSorting: false, cell: ({ row }) => btn(row.original) },
  ]
  return (
    <Section id="box-ignored" title={t('boxIp.ignored.title')} description={t('boxIp.ignored.description')} info={t('boxIp.ignored.descriptionInfo')}>
      <DataTable urlKey="boxip-ignored" caption={t('boxIp.ignored.caption')} data={ignored} columns={columns} pageSize={20} summary={t('boxIp.ignored.summary', { count: ignored.length })}
        mobileRow={(r) => (
          <div className="grid gap-1.5">
            <div className="flex items-center justify-between gap-2"><span className="font-medium">{r.value}</span>{btn(r)}</div>
            <FieldHint>{t('boxIp.ignored.col.by')}: {r.ignored_by}. {t('boxIp.ignored.col.at')}: {fmtDate(r.ignored_at)}.</FieldHint>
          </div>
        )}
        empty={<EmptyState title={t('boxIp.ignored.emptyTitle')}>{t('boxIp.ignored.emptyBody')}</EmptyState>} />
    </Section>
  )
}
