import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { CalendarClock, Power, RefreshCw, ShieldCheck } from 'lucide-react'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Chip } from '@/components/common/StatusChip'
import { QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Checkbox, RadioGroup, RadioItem } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Input, Label } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { Switch } from '@/components/ui/switch'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useOsMutations, useOsRun, useOsState } from './api'
import { Band, errMsg, useGate } from './parts'
import type { MaintenanceWindow, OsPackage, OsRun, OsState } from './types'

const DAYS = [1, 2, 3, 4, 5, 6, 7]
const monthYear = (d: string) => new Intl.DateTimeFormat('en-GB', { month: 'long', year: 'numeric' }).format(new Date(`${d}T12:00:00`))

/** Hết hạn hỗ trợ: đã qua, sắp tới (trong 12 tháng) hay còn dài. Debian có thêm giai đoạn LTS. */
function support(os: OsState['os'], now = Date.now()): 'ok' | 'soon' | 'extended' | 'ended' {
  const std = new Date(`${os.support_end}T23:59:59`).getTime()
  if (now > std) return os.extended_end && now < new Date(`${os.extended_end}T23:59:59`).getTime() ? 'extended' : 'ended'
  return std - now < 365 * 864e5 ? 'soon' : 'ok'
}

function WindowSummary({ w }: { w: MaintenanceWindow }) {
  const { t } = useTranslation('core')
  if (w.mode === 'always') return <>{t('updates.os.window.anytime')}</>
  return <>{w.days.map((d) => t(`updates.os.dayShort.${d}`)).join(', ')}, {w.from} {t('updates.os.window.to')} {w.to}</>
}

function WindowForm({ s, disabled, title }: { s: OsState; disabled: boolean; title?: string }) {
  const { t } = useTranslation('core')
  const m = useOsMutations()
  const [w, setW] = useState<MaintenanceWindow>(s.window)
  const same = JSON.stringify(w) === JSON.stringify(s.window) || (w.mode === 'always' && s.window.mode === 'always')
  const problem = w.mode === 'window' ? (w.days.length === 0 ? t('updates.os.window.noDays') : w.from === w.to ? t('updates.os.window.empty') : null) : null
  const toggle = (d: number, on: boolean) => setW({ ...w, days: on ? [...w.days, d].sort() : w.days.filter((x) => x !== d) })
  return (
    <fieldset disabled={disabled} title={title} className="m-0 grid min-w-0 gap-3 border-0 p-0">
      <legend className="mb-1 text-sm font-medium">{t('updates.os.window.title')}</legend>
      <Segmented label={t('updates.os.window.modeLabel')} value={w.mode} onChange={(mode) => setW({ ...w, mode })} options={[{ value: 'always', label: t('updates.os.window.anytime') }, { value: 'window', label: t('updates.os.window.only') }]} />
      {w.mode === 'window' ? (
        <div className="grid gap-3">
          <div role="group" aria-label={t('updates.os.window.days')} className="flex flex-wrap gap-x-4 gap-y-2">
            {DAYS.map((d) => (
              <span key={d} className="inline-flex items-center gap-2 text-sm">
                <Checkbox id={`win-day-${d}`} checked={w.days.includes(d)} onCheckedChange={(v) => toggle(d, v === true)} />
                <Label htmlFor={`win-day-${d}`} className="font-normal">{t(`updates.os.day.${d}`)}</Label>
              </span>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <Label htmlFor="win-from" className="font-normal">{t('updates.os.window.from')}</Label>
            <Input id="win-from" type="time" className="w-32" value={w.from} onChange={(e) => setW({ ...w, from: e.target.value })} />
            <Label htmlFor="win-to" className="font-normal">{t('updates.os.window.until')}</Label>
            <Input id="win-to" type="time" className="w-32" value={w.to} onChange={(e) => setW({ ...w, to: e.target.value })} />
          </div>
        </div>
      ) : null}
      <p className="max-w-2xl text-[13px] text-muted">{w.mode === 'always' ? t('updates.os.window.hintAnytime') : t('updates.os.window.hintWindow')}</p>
      {problem ? <p role="alert" className="text-[13px] text-danger">{problem}</p> : null}
      <div><Button disabled={disabled || same || !!problem || m.settings.isPending} onClick={() => void m.settings.mutateAsync({ window: w }).then(() => toast.success(t('updates.os.window.saved'))).catch((e) => toast.error(errMsg(e, t)))}>{t('updates.os.window.save')}</Button></div>
    </fieldset>
  )
}

type RebootChoice = 'window' | 'custom'
function RebootDialog({ s, open, onClose }: { s: OsState; open: boolean; onClose: () => void }) {
  const { t } = useTranslation('core')
  const m = useOsMutations()
  const noWindow = s.window.mode !== 'window'
  const [choice, setChoice] = useState<RebootChoice>(noWindow ? 'custom' : 'window')
  const [at, setAt] = useState('')
  const pick = (c: RebootChoice) => { setChoice(c); if (c !== 'custom') setAt('') }
  async function go() {
    try {
      await m.reboot.mutateAsync(choice === 'window' ? { when: 'window' } : { when: 'custom', at })
      toast.success(t('updates.os.reboot.scheduled'))
      onClose()
    } catch (e) { toast.error(errMsg(e, t)) }
  }
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={t('updates.os.reboot.scheduleTitle')} description={t('updates.os.reboot.scheduleBody', { window: s.window.mode === 'always' ? t('updates.os.window.anytime') : `${s.window.days.map((d) => t(`updates.os.dayShort.${d}`)).join(', ')} ${s.window.from} ${t('updates.os.window.to')} ${s.window.to}` })}>
        <RadioGroup aria-label={t('updates.os.reboot.scheduleTitle')} value={choice} onValueChange={(v) => pick(v as RebootChoice)}>
          <span className="inline-flex items-center gap-2 text-sm">
            <RadioItem id="rb-window" value="window" disabled={noWindow} />
            <Label htmlFor="rb-window" className="font-normal">{t('updates.os.reboot.optWindow')}</Label>
          </span>
          {noWindow ? <p className="ml-6 text-[13px] text-muted">{t('updates.os.reboot.windowLocked')}</p> : null}
          <span className="inline-flex items-center gap-2 text-sm">
            <RadioItem id="rb-custom" value="custom" />
            <Label htmlFor="rb-custom" className="font-normal">{t('updates.os.reboot.optCustom')}</Label>
          </span>
        </RadioGroup>
        {choice === 'custom' ? (
          <div className="ml-6 grid max-w-xs gap-1.5">
            <Label htmlFor="rb-at">{t('updates.os.reboot.at')}</Label>
            <Input id="rb-at" type="time" value={at} onChange={(e) => setAt(e.target.value)} />
            <p className="text-[13px] text-muted">{noWindow ? t('updates.os.reboot.atHintAny') : t('updates.os.reboot.atHintWindow')}</p>
          </div>
        ) : null}
        <DialogFooter>
          <Button onClick={onClose}>{t('common:cancel')}</Button>
          <Button variant="primary" disabled={m.reboot.isPending || (choice === 'custom' && !at)} onClick={() => void go()}>{t('updates.os.reboot.scheduleConfirm')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function RunPanel({ run }: { run: OsRun }) {
  const { t } = useTranslation('core')
  const qc = useQueryClient()
  const log = useRef<HTMLPreElement>(null)
  const seen = useRef<string | null>(null)
  useEffect(() => { if (log.current) log.current.scrollTop = log.current.scrollHeight }, [run.lines.length])
  useEffect(() => {
    // Lần chạy vừa xong: làm mới danh sách chờ và trạng thái khởi động lại; báo một lần.
    if (run.status !== 'done') { seen.current = `${run.id}:running`; return }
    void qc.invalidateQueries({ queryKey: ['core', 'os'] })
    void qc.invalidateQueries({ queryKey: ['core', 'updates'] })
    if (seen.current === `${run.id}:running`) toast.success(t('updates.os.run.finished', { count: run.result?.installed ?? 0 }))
    seen.current = `${run.id}:done`
  }, [run.id, run.status, run.result?.installed, qc, t])
  const r = run.result
  return (
    <div className="grid gap-3 rounded-md border border-rule bg-surface p-4" aria-live="polite">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="text-sm font-semibold">{t('updates.os.run.title')}</h3>
        {run.status === 'running' ? <Chip tone="accent">{t('updates.os.run.running')}</Chip> : <Chip tone="ok">{t('updates.os.run.done')}</Chip>}
        <span className="text-[13px] text-muted">{t(`updates.os.run.scope.${run.scope}`)}, {fmtDateTime(run.started_at)}, {run.user}</span>
      </div>
      <pre ref={log} tabIndex={0} role="log" aria-label={t('updates.os.run.log')} className="max-h-60 overflow-auto whitespace-pre-wrap rounded-md border border-rule bg-sunken p-3 font-mono text-[12px] leading-5 [overflow-wrap:anywhere]">{run.lines.join('\n') || ' '}</pre>
      {r ? (
        <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-[minmax(140px,max-content)_1fr]">
          <dt className="text-[13px] text-muted">{t('updates.os.run.installed')}</dt><dd>{t('updates.os.run.installedValue', { count: r.installed, security: r.security })}</dd>
          <dt className="text-[13px] text-muted">{t('updates.os.run.backup')}</dt><dd className="font-mono text-[12.5px] [overflow-wrap:anywhere]">{r.backup}</dd>
          <dt className="text-[13px] text-muted">{t('updates.os.run.health')}</dt>
          <dd className="flex flex-wrap gap-1.5">{r.health.map((h) => <Chip key={h.name} tone={h.ok ? 'ok' : 'danger'}>{h.name}{h.ok ? '' : `: ${t('updates.os.run.failed')}`}</Chip>)}</dd>
          <dt className="text-[13px] text-muted">{t('updates.os.run.reboot')}</dt>
          <dd>{r.reboot_required ? <Chip tone="warn">{t('updates.os.rebootRequired')}</Chip> : <Chip tone="ok">{t('updates.os.rebootNotNeeded')}</Chip>}</dd>
        </dl>
      ) : null}
    </div>
  )
}

function Body({ s }: { s: OsState }) {
  const { t } = useTranslation('core')
  const admin = useGate('admin')
  const operator = useGate('operator')
  const m = useOsMutations()
  const runQ = useOsRun()
  const run = runQ.data ?? null
  const [scheduling, setScheduling] = useState(false)
  const [rebooting, setRebooting] = useState(false)
  const [installAll, setInstallAll] = useState(false)
  const sup = support(s.os)
  const sec = s.pending.filter((p) => p.security).length
  const act = async (fn: () => Promise<unknown>, ok: string) => { try { await fn(); toast.success(ok) } catch (e) { toast.error(errMsg(e, t)) } }
  const install = (scope: 'security' | 'all') => void m.install.mutateAsync(scope).then(() => toast.success(t('updates.os.run.started'))).catch((e) => toast.error(errMsg(e, t)))

  const cols: ColumnDef<OsPackage>[] = [
    { id: 'name', header: t('updates.os.col.package'), accessorFn: (p) => p.name, cell: ({ row }) => <span className="font-mono text-[12.5px]">{row.original.name}</span> },
    { id: 'cur', header: t('updates.os.col.current'), accessorFn: (p) => p.current, cell: ({ getValue }) => <span className="font-mono text-[12.5px] text-muted">{getValue() as string}</span> },
    { id: 'new', header: t('updates.os.col.new'), accessorFn: (p) => p.new, cell: ({ getValue }) => <span className="font-mono text-[12.5px]">{getValue() as string}</span> },
    { id: 'sec', header: t('updates.os.col.security'), accessorFn: (p) => Number(p.security), cell: ({ row }) => (row.original.security ? <Chip tone="danger">{t('common:yes')}</Chip> : <span className="text-muted">{t('common:no')}</span>) },
    { id: 'cves', header: t('updates.os.col.cves'), accessorFn: (p) => p.cves.join(' '), cell: ({ row }) => (row.original.cves.length ? <div className="flex flex-wrap gap-x-2">{row.original.cves.map((c) => <span key={c} className="whitespace-nowrap text-[12.5px]">{c}</span>)}</div> : <span className="text-muted">–</span>) },
  ]

  return (
    <>
      <section id="os" aria-labelledby="os-band">
        <Band id="os-band" n="1" title={t('updates.os.title')} desc={t('updates.os.desc')}
          actions={<Button onClick={() => void act(() => m.check.mutateAsync(), t('updates.os.checked'))} disabled={operator.disabled || m.check.isPending} title={operator.title}><RefreshCw />{t('updates.os.checkNow')}</Button>} />
        <div className="grid gap-5">
          <div className="grid gap-x-6 gap-y-3 rounded-md border border-rule bg-surface p-4 sm:grid-cols-[minmax(160px,max-content)_1fr]">
            <span className="text-[13px] text-muted">{t('updates.os.distro')}</span>
            <span className="flex flex-wrap items-center gap-2 text-sm font-medium">{s.os.name}</span>
            <span className="text-[13px] text-muted">{t('updates.os.kernel')}</span>
            <span className="font-mono text-[12.5px]">{s.os.kernel}</span>
            <span className="text-[13px] text-muted">{t('updates.os.lastCheck')}</span>
            <span className="text-sm">{fmtDateTime(s.os.last_check)} ({fmtRelative(s.os.last_check)})</span>
            <span className="text-[13px] text-muted">{t('updates.os.support')}</span>
            <span className="grid gap-1 text-sm">
              <span className="flex flex-wrap items-center gap-2">
                {t('updates.os.supportUntil', { date: monthYear(s.os.support_end) })}
                {sup === 'ok' ? <Chip tone="ok">{t('updates.os.sup.ok')}</Chip> : null}
                {sup === 'soon' ? <Chip tone="warn">{t('updates.os.sup.soon')}</Chip> : null}
                {sup === 'extended' ? <Chip tone="warn">{t('updates.os.sup.extended')}</Chip> : null}
                {sup === 'ended' ? <Chip tone="danger">{t('updates.os.sup.ended')}</Chip> : null}
              </span>
              {s.os.extended_end ? <span className="text-[13px] text-muted">{t('updates.os.extendedUntil', { date: monthYear(s.os.extended_end) })}</span> : null}
              {sup === 'extended' || sup === 'ended' || sup === 'soon' ? <span className="max-w-2xl text-[13px]">{t(`updates.os.supHint.${sup}`)}</span> : null}
            </span>
            <span className="text-[13px] text-muted">{t('updates.os.rebootLabel')}</span>
            <span className="grid gap-1 text-sm">
              <span className="flex flex-wrap items-center gap-2">
                {s.reboot_required ? <Chip tone="warn">{t('updates.os.rebootRequired')}</Chip> : <Chip tone="ok">{t('updates.os.rebootNotNeeded')}</Chip>}
                <span className="text-[13px] text-muted">{t('updates.os.bootedAt', { time: fmtRelative(s.os.booted_at) })}</span>
              </span>
              {s.reboot_required ? <span className="text-[13px]">{t('updates.os.rebootWhy', { packages: s.reboot_reasons.join(', ') })}</span> : null}
              {s.reboot_scheduled_at ? (
                <span className="flex flex-wrap items-center gap-2 text-[13px]">
                  <CalendarClock className="size-4" aria-hidden />{t('updates.os.rebootScheduled', { time: fmtDateTime(s.reboot_scheduled_at) })}
                  <Button size="sm" variant="ghost" disabled={admin.disabled || m.cancelReboot.isPending} title={admin.title} onClick={() => void act(() => m.cancelReboot.mutateAsync(), t('updates.os.reboot.cancelled'))}>{t('updates.os.reboot.cancel')}</Button>
                </span>
              ) : null}
            </span>
            <span className="text-[13px] text-muted"><Label htmlFor="os-auto" className="text-[13px] font-normal text-muted">{t('updates.os.auto')}</Label></span>
            <span className="flex flex-wrap items-center gap-3">
              <Switch id="os-auto" checked={s.auto_security} disabled={admin.disabled || m.settings.isPending} title={admin.title}
                onCheckedChange={(v) => void act(() => m.settings.mutateAsync({ auto_security: v }), v ? t('updates.os.autoOn') : t('updates.os.autoOff'))} />
              <span className="max-w-xl text-[13px] text-muted">{s.auto_security ? t('updates.os.autoHintOn') : t('updates.os.autoHintOff')}</span>
            </span>
            <span className="text-[13px] text-muted">{t('updates.os.windowLabel')}</span>
            <span className="text-sm"><WindowSummary w={s.window} /></span>
          </div>

          <WindowForm key={JSON.stringify(s.window)} s={s} disabled={admin.disabled} title={admin.title} />

          <div className="flex flex-wrap items-center gap-2">
            <Button variant="primary" disabled={admin.disabled || m.install.isPending} title={admin.title} onClick={() => install('security')}><ShieldCheck />{t('updates.os.installSecurity')}{sec ? ` (${sec})` : ''}</Button>
            <Button disabled={admin.disabled || m.install.isPending} title={admin.title} onClick={() => setInstallAll(true)}>{t('updates.os.installAll')}</Button>
            <Button disabled={admin.disabled} title={admin.title} onClick={() => setRebooting(true)}><Power />{t('updates.os.reboot.now')}</Button>
            <Button disabled={admin.disabled} title={admin.title} onClick={() => setScheduling(true)}><CalendarClock />{t('updates.os.reboot.schedule')}</Button>
          </div>
          <p className="max-w-3xl text-[13px] text-muted">{t('updates.os.helper')}</p>

          <div>
            <h3 className="mb-2 text-sm font-semibold">{t('updates.os.pending', { count: s.pending.length, security: sec })}</h3>
            <DataTable data={s.pending} columns={cols} caption={t('updates.os.pendingCaption')} pageSize={20} empty={t('updates.os.pendingEmpty')}
              mobileRow={(p) => (
                <div className="grid gap-1">
                  <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-[13px] font-medium [overflow-wrap:anywhere]">{p.name}</span>{p.security ? <Chip tone="danger">{t('updates.os.col.security')}</Chip> : null}</div>
                  <span className="font-mono text-[12px] text-muted [overflow-wrap:anywhere]">{p.current} {'>'} {p.new}</span>
                  {p.cves.length ? <span className="text-[12px]">{p.cves.join(', ')}</span> : null}
                </div>
              )} />
          </div>

          {run ? <RunPanel run={run} /> : null}

          {s.release_upgrade ? (
            <div className="rounded-md border border-dashed border-warn bg-warn-soft/60 p-4">
              <h3 className="text-sm font-semibold">{t('updates.os.upgrade.title', { to: s.release_upgrade.to })}</h3>
              <p className="mt-1 max-w-3xl text-[13px]">{t('updates.os.upgrade.warn')}</p>
              <ol className="mt-2 grid max-w-3xl list-decimal gap-1 pl-5 text-sm">{s.release_upgrade.steps.map((st) => <li key={st} className="[overflow-wrap:anywhere]">{st}</li>)}</ol>
            </div>
          ) : null}
        </div>
      </section>

      <Dialog open={rebooting} onOpenChange={(o) => !o && setRebooting(false)}>
        <DialogContent title={t('updates.os.reboot.nowTitle')} description={t('updates.os.reboot.nowBody')}>
          <DialogFooter>
            <Button onClick={() => setRebooting(false)}>{t('common:cancel')}</Button>
            <Button variant="danger" disabled={m.reboot.isPending} onClick={() => void act(() => m.reboot.mutateAsync({ when: 'now' }), t('updates.os.reboot.done')).then(() => setRebooting(false))}>{t('updates.os.reboot.nowConfirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog open={installAll} onOpenChange={(o) => !o && setInstallAll(false)}>
        <DialogContent title={t('updates.os.installAllTitle', { count: s.pending.length })} description={t('updates.os.installAllBody')}>
          <DialogFooter>
            <Button onClick={() => setInstallAll(false)}>{t('common:cancel')}</Button>
            <Button variant="primary" disabled={m.install.isPending} onClick={() => { install('all'); setInstallAll(false) }}>{t('updates.os.installAllConfirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      {scheduling ? <RebootDialog s={s} open onClose={() => setScheduling(false)} /> : null}
    </>
  )
}

/** Khối a của Settings → Updates: hệ điều hành của chính hộp (D-53, S-CORE-7). */
export function OsBlock() {
  const q = useOsState()
  return <QueryState query={q}>{(s) => <Body s={s} />}</QueryState>
}
