import { useState, type FormEvent } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Plus } from 'lucide-react'
import { Notice, PageHeader, Section } from '@/components/common/PageHeader'
import { KpiStrip, PageTabs } from '@/components/common/PageFrame'
import { EmptyState, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { DependencyLink } from '@/components/common/DependencyLink'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter, DialogTrigger } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { fmtDate, fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { AnchorRedirect, ScrollToHash } from './anchors'
import { BoxIpPanel } from './BoxIpPanel'
import { GreenboneSetting } from './GreenbonePanel'
import { InfoLine } from './InfoLine'
import { CommitChip, OwnerChip } from './OwnerChip'
import { ScanProgress } from './ScanProgress'
import { useAddTarget, useTargets } from './api'
import { portLabel } from './services'
import type { Target, TargetKind } from './types'
import { blockedKey } from './types'

// Old #anchor → tab: before the tabs these were stacked blocks of one page, and before the targets' own pages the open ports and what the
// Internet sees had tabs of their own, which now live on each target.
const ANCHOR_TAB: Record<string, string> = { targets: 'targets', 'box-ip': 'settings', 'box-ignored': 'settings', greenbone: 'settings', open: 'targets', 'outside-list': 'targets' }
/** Tabs the page had before each target held its own open exposures and outside view: they land on Targets, with a note. */
const MOVED_TABS = ['open', 'outside']

// modules.md: the module's API is read only while the module is on; off, the page says so and calls nothing.
export default function ExposurePage() {
  return <RequireModule module="exposure" page><ExposureView /></RequireModule>
}

function ExposureView() {
  const { t } = useTranslation('exposure')
  const q = useTargets()
  const [params] = useSearchParams()
  // Đọc rõ các trường query ở đây để react-query theo dõi đúng khi chuyển sang lỗi.
  const { data, error, isPending, refetch } = q
  const items = data?.items
  const scanned = items?.filter((x) => x.latest) ?? []
  const admin = scanned.reduce((n, x) => n + (x.latest?.admin_panels ?? 0), 0)
  const certs = scanned.reduce((n, x) => n + (x.latest?.certs_expiring ?? 0), 0)
  const pending = items?.filter((x) => !x.scannable).length ?? 0
  // Say what is open before saying what is not (the open ports of each target's newest scan).
  const ports = scanned.reduce((n, x) => n + (x.open_exposures ?? 0), 0)
  const open = scanned.flatMap((x) => (x.open_ports ?? []).map((p) => ({ ...p, target: x })))
  const shown = open.slice(0, 3).map(portLabel).join(', ')
  const list = ports > 3 ? t('title.more', { list: shown, count: ports - 3 }) : shown
  const title = !items ? t('titleLoading')
    : items.length === 0 ? t('title.none')
    : scanned.length === 0 ? (pending > 0 ? t('title.pending', { count: pending }) : t('title.ready', { count: items.length }))
    : admin > 0 ? t('title.admin', { count: admin })
    : ports > 0 ? t('title.ports', { count: ports, list })
    : pending > 0 ? t('title.cleanPartial', { count: pending })
    : t('title.clean')
  return (
    <>
      <PageHeader title={title} stories={['S-EXP-1']} actions={<AddTarget />} info={<p>{t('rule')}</p>}
        meta={<span className="flex flex-wrap items-center gap-2"><SampleDataNote />{certs > 0 ? `${t('meta.certs', { count: certs })} ` : null}{t('meta.rule')}</span>} />
      <ScanProgress />
      <AnchorRedirect map={ANCHOR_TAB} />
      <QueryState query={{ data, error, isPending, refetch }}>
        {(d) => {
          const lastScan = d.items.map((x) => x.last_scan_at).filter((x): x is string => !!x).sort().at(-1)
          // The open exposures live on each target: with one target that has any, the tile opens that target's; else the list, where each row says its count.
          const withPorts = d.items.filter((x) => x.open_exposures > 0)
          const openTo = withPorts.length === 1 ? `/exposure/${withPorts[0]!.id}?tab=exposures` : '?tab=targets'
          const kpis = d.items.length > 0 ? [
            { value: d.items.filter((x) => x.status !== 'unverified' && !!x.commitment).length, label: t('kpi.targets'), to: '?tab=targets' },
            { value: ports, label: t('kpi.open'), to: openTo },
            { value: lastScan ? fmtRelative(lastScan) : t('kpi.never'), label: t('kpi.scan'), to: '?tab=targets' },
          ] : []
          return (
            <>
              <ScrollToHash />
              {kpis.length ? <KpiStrip label={t('kpi.label')} items={kpis} /> : null}
              {MOVED_TABS.includes(params.get('tab') ?? '') ? <Notice tone="accent" role="status" title={t('moved.title')} info={t('moved.info')} /> : null}
              <PageTabs label={t('tabs.label')} tabs={[
                { id: 'targets', label: t('tabs.targets'), panel: (
                  <Section id="targets" title={t('targets.title')} description={t('targets.description')} info={t('targets.descriptionInfo')}>
                    <TargetsTable items={d.items} />
                  </Section>
                ) },
                { id: 'settings', label: t('tabs.settings'), panel: <>
                  <BoxIpPanel settings={d.box_ip} ignored={d.ignored} />
                  <GreenboneSetting />
                  <Section id="scan-settings" title={t('settings.scanTitle')} description={t('settings.scanDescription')}>
                    <DependencyLink reason={t('settings.scanReason')} to="/settings/scanning" label={t('settings.scanLink')} />
                  </Section>
                </> },
              ]} />
            </>
          )
        }}
      </QueryState>
    </>
  )
}

/** What the row says about scanning: why it cannot be scanned (an auto-detected IP whose terms are not accepted is not a problem: a small note), else when it was last scanned. */
function ScanCell({ r }: { r: Target }) {
  const { t } = useTranslation('exposure')
  if (r.scan_state === 'scanning') return <span className="text-meta">{t('targets.scanning')}</span>
  if (r.origin === 'box' && r.scan_state === 'needs_terms') return <span className="grid"><span className="text-meta text-muted">{t('targets.neverScannedShort')}</span><span className="text-caption text-muted">{t('targets.termsNotAccepted')}</span></span>
  if (r.blocked_reason) return <span className="text-meta text-warn">{t(`blocked.${blockedKey(r)}`)}</span>
  return <span className="grid"><span>{r.last_scan_at ? fmtRelative(r.last_scan_at) : t('targets.neverScanned')}</span><span className="text-caption text-muted">{t('targets.ready')}</span></span>
}

/** Ownership with, for an IP, when its proof runs out: every IP proof lasts 30 days and is checked again by the box. */
function OwnershipCell({ r }: { r: Target }) {
  const { t } = useTranslation('exposure')
  return (
    <span className="grid gap-0.5">
      <OwnerChip target={r} />
      {r.kind === 'ip' && r.expires_at && r.status !== 'unverified' ? <span className="text-caption text-muted">{t('targets.proofUntil', { date: fmtDate(r.expires_at) })}</span> : null}
    </span>
  )
}

function TargetsTable({ items }: { items: Target[] }) {
  const { t } = useTranslation('exposure')
  const columns: ColumnDef<Target>[] = [
    { id: 'value', header: t('targets.col.target'), accessorFn: (r) => r.value, cell: ({ row }) => (
      <span className="grid gap-0.5"><Link className="font-medium text-accent underline-offset-4 hover:underline" to={`/exposure/${row.original.id}`}>{row.original.value}</Link><span><Chip tone="off">{t(`kind.${row.original.kind}`)}</Chip></span></span>
    ) },
    { id: 'owner', header: t('targets.col.owner'), accessorFn: (r) => r.status, cell: ({ row }) => <OwnershipCell r={row.original} /> },
    { id: 'commit', header: t('targets.col.commit'), accessorFn: (r) => (r.commitment ? 1 : 0), cell: ({ row }) => <CommitChip target={row.original} /> },
    { id: 'scan', header: t('targets.col.scan'), accessorFn: (r) => r.last_scan_at ?? '', cell: ({ row }) => <ScanCell r={row.original} /> },
    { id: 'latest', header: t('targets.col.latest'), enableSorting: false, cell: ({ row }) => {
      const c = row.original.latest
      return c ? <span className="text-meta">{t('targets.latest', { admin: c.admin_panels, ports: c.ports, certs: c.certs_expiring })}</span> : <span className="text-meta text-muted">{t('targets.noResult')}</span>
    } },
    { id: 'open', header: t('targets.col.open'), accessorFn: (r) => r.open_exposures, cell: ({ row }) => (
      row.original.open_exposures > 0 ? <Link className="font-medium text-accent underline-offset-4 hover:underline" to={`/exposure/${row.original.id}?tab=exposures`} aria-label={t('targets.openLabel', { count: row.original.open_exposures, value: row.original.value })}>{row.original.open_exposures}</Link>
        : <span className="text-muted">0</span>
    ) },
  ]
  return <DataTable caption={t('targets.caption')} data={items} columns={columns} pageSize={20}
    mobileRow={(r) => (
      <div className="grid gap-1.5">
        <Link className="break-all font-medium text-accent underline-offset-4 hover:underline" to={`/exposure/${r.id}`}>{r.value}</Link>
        <div className="flex flex-wrap items-center gap-2">
          <Chip tone="off">{t(`kind.${r.kind}`)}</Chip>
          <OwnerChip target={r} />
          <CommitChip target={r} />
        </div>
        {r.kind === 'ip' && r.expires_at && r.status !== 'unverified' ? <p className="text-meta text-muted">{t('targets.proofUntil', { date: fmtDate(r.expires_at) })}</p> : null}
        <ScanCell r={r} />
        {r.latest ? <p className="text-meta">{t('targets.latest', { admin: r.latest.admin_panels, ports: r.latest.ports, certs: r.latest.certs_expiring })}</p> : null}
        {r.open_exposures > 0 ? <Link className="text-meta text-accent underline-offset-4 hover:underline" to={`/exposure/${r.id}?tab=exposures`}>{t('targets.openLabel', { count: r.open_exposures, value: r.value })}</Link> : null}
      </div>
    )}
    empty={<EmptyState title={t('targets.emptyTitle')}><InfoLine topic={t('targets.emptyTitle')} info={t('targets.emptyBodyInfo')}>{t('targets.emptyBody')}</InfoLine></EmptyState>} />
}

function AddTarget() {
  const { t } = useTranslation('exposure')
  const can = useCan('admin')
  const add = useAddTarget()
  const nav = useNavigate()
  const [open, setOpen] = useState(false)
  const [kind, setKind] = useState<TargetKind>('domain')
  const [value, setValue] = useState('')
  const [error, setError] = useState<string | null>(null)
  // Cancel, Esc and X all drop the draft and its error, so the next opening never shows an error for text that is gone;
  // while the target is being added the dialog stays open, so a late answer never lands on a closed or new draft.
  const toggle = (o: boolean) => { if (!o && add.isPending) return; setOpen(o); if (!o) { setError(null); setValue(''); setKind('domain') } }
  function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (!value.trim()) return setError(t(`add.empty.${kind}`))
    add.mutate({ value: value.trim(), kind }, {
      // After adding, the person goes into the target to prove ownership there (the proof steps are on its Ownership tab); a name another proof covers needs none.
      onSuccess: (tg) => { toast.success(t('add.toast', { value: tg.value })); setOpen(false); setValue(''); void nav(tg.status === 'unverified' ? `/exposure/${tg.id}?tab=ownership` : `/exposure/${tg.id}`) },
      onError: (er) => setError(er instanceof Error ? er.message : String(er)),
    })
  }
  return (
    <Dialog open={open} onOpenChange={toggle}>
      <DialogTrigger asChild>
        <Button variant="primary" disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.admin') })}><Plus />{t('add.button')}</Button>
      </DialogTrigger>
      <DialogContent title={t('add.title')} description={t('add.description')} info={t('add.descriptionInfo')}>
        <form onSubmit={submit} noValidate className="grid gap-4">
          <div className="grid justify-items-start gap-1">
            <span className="text-sm font-medium">{t('add.kind')}</span>
            <Segmented<TargetKind> label={t('add.kind')} value={kind} onChange={(k) => { setKind(k); setError(null) }}
              options={[{ value: 'domain', label: t('add.kindOption.domain') }, { value: 'ip', label: t('add.kindOption.ip') }]} />
          </div>
          <Field label={t(`add.label.${kind}`)} htmlFor="ex-new" hint={t(`add.hint.${kind}`)} info={t(`add.hintInfo.${kind}`)} error={error ?? undefined}>
            <Input id="ex-new" value={value} onChange={(e) => setValue(e.target.value)} autoFocus autoComplete="off" spellCheck={false} aria-invalid={error ? true : undefined} aria-describedby={error ? 'ex-new-error' : 'ex-new-hint'} />
          </Field>
          <DialogFooter>
            <Button onClick={() => toggle(false)} disabled={add.isPending}>{t('common:cancel')}</Button>
            <Button type="submit" variant="primary" busy={add.isPending} busyLabel={t('common:busy.adding')}>{t('add.submit')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
