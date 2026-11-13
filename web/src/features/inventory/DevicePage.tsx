import { useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ArrowLeft, Pencil, Plus, Trash2 } from 'lucide-react'
import { PageHeader, Section, Panel } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, ErrorState, Loading, ModuleOff, RequireModule, SampleDataNote } from '@/components/common/States'
import { SourceBadge } from '@/components/common/SourceBadge'
import { Slot } from '@/components/common/Slot'
import { Chip } from '@/components/common/StatusChip'
import { Button, buttonVariants } from '@/components/ui/button'
import { Field, Input, Select, Textarea, Label } from '@/components/ui/input'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Switch } from '@/components/ui/switch'
import { ApiError } from '@/lib/api'
import { fmtDateTime, fmtRelative, rawProductLine } from '@/lib/format'
import { useCan } from '@/lib/session'
import type { AssetKind, Service } from '@/lib/types'
import { cn } from '@/lib/utils'
import { categoryLabel, categoryOf, kindLabel, TYPES_BY_CATEGORY } from '@/lib/deviceTypes'
import { AddDeviceDialog } from './AddDeviceDialog'
import { useDevice, useDeviceAction } from './api'
import { useInstallKind } from '@/lib/modules'
import { DeleteDialog } from './DeleteDialog'
import { errMsg } from './kinds'
import { nameOf } from './nameOf'
import type { DeviceDetail, Observation, RegularScan, SoftwareView } from './types'

function Overview({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const act = useDeviceAction(d.asset.id)
  const needRole = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const a = d.asset
  const fail = (e: unknown) => toast.error(errMsg(e))
  const guess = a.kind === 'unknown' ? a.guess : null
  const setKind = (kind: AssetKind) => act.patch.mutate({ kind }, { onSuccess: () => toast.success(t('detail.kindSaved', { kind: kindLabel(kind) })), onError: fail })
  const row = (label: string, value: React.ReactNode) => (
    <div className="contents"><dt className="text-[13px] text-muted">{label}</dt><dd className="text-sm">{value}</dd></div>
  )
  return (
    <dl className="grid grid-cols-1 items-center gap-x-6 gap-y-3 sm:grid-cols-[minmax(160px,max-content)_1fr]">
      <dt className="text-[13px] text-muted"><Label htmlFor="device-kind" className="text-[13px] font-normal text-muted">{t('detail.kind')}</Label></dt>
      <dd>
        <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <Select id="device-kind" className="max-w-xs" value={a.kind} disabled={!can || act.patch.isPending} title={needRole}
            onChange={(e) => setKind(e.target.value as AssetKind)}>
            {TYPES_BY_CATEGORY.map(({ category, types }) => {
              const listed = types.filter((ty) => d.kinds.includes(ty.id))
              return listed.length ? <optgroup key={category.id} label={category.label}>{listed.map((ty) => <option key={ty.id} value={ty.id}>{ty.label}</option>)}</optgroup> : null
            })}
          </Select>
          {a.kind !== 'unknown' ? <span className="text-[13px] text-muted">{categoryLabel(categoryOf(a.kind))}</span> : null}
          {a.kind_source ? <span className="text-[12px] text-muted">{t('detail.kindFrom')} <SourceBadge source={a.kind_source} /></span> : null}
        </span>
        {guess ? (
          <div className="mt-2 grid max-w-2xl gap-1.5 rounded-md border border-border p-3" data-testid="kind-guess">
            <p className="text-sm">
              <span className="font-medium">{t('guess.title', { kind: kindLabel(guess.kind), category: categoryLabel(categoryOf(guess.kind)) })}</span>
              {guess.model ? <span className="text-muted"> {t('guess.model', { model: guess.model })}</span> : null}
            </p>
            <p className="text-[13px] text-muted [overflow-wrap:anywhere]">{guess.evidence}</p>
            <p className="text-[12px] text-muted">{t('guess.hint')}</p>
            {guess.alternatives?.length ? <p className="text-[12px] text-muted">{t('guess.alternatives', { list: guess.alternatives.map(kindLabel).join(', ') })}</p> : null}
            <span className="flex flex-wrap gap-2">
              <Button size="sm" disabled={!can || act.patch.isPending} title={needRole} onClick={() => setKind(guess.kind)}>{t('guess.confirm', { kind: kindLabel(guess.kind) })}</Button>
              {(guess.alternatives ?? []).map((k) => <Button key={k} size="sm" variant="ghost" disabled={!can || act.patch.isPending} title={needRole} onClick={() => setKind(k)}>{t('guess.instead', { kind: kindLabel(k) })}</Button>)}
            </span>
          </div>
        ) : null}
      </dd>
      <dt className="text-[13px] text-muted"><Label htmlFor="device-fragile" className="text-[13px] font-normal text-muted">{t('detail.fragile')}</Label></dt>
      <dd className="flex flex-wrap items-center gap-3">
        <Switch id="device-fragile" checked={a.fragile} disabled={!can || act.patch.isPending} title={needRole}
          onCheckedChange={(v) => act.patch.mutate({ fragile: v }, { onSuccess: () => toast.success(v ? t('detail.fragileOn') : t('detail.fragileOff')), onError: fail })} />
        <span className="max-w-xl text-[13px] text-muted">{a.fragile ? t('detail.fragileOnHint') : t('detail.fragileOffHint')}</span>
      </dd>
      {a.fragile ? (
        <>
          <dt className="text-[13px] text-muted"><Label htmlFor="device-regular" className="text-[13px] font-normal text-muted">{t('detail.regularScan')}</Label></dt>
          <dd className="flex flex-wrap items-center gap-3">
            <Select id="device-regular" className="max-w-xs" value={a.regular_scan} disabled={!can || act.patch.isPending} title={needRole}
              onChange={(e) => act.patch.mutate({ regular_scan: e.target.value as RegularScan }, { onSuccess: () => toast.success(t('detail.regularScanSaved')), onError: fail })}>
              {(['follow', 'allow', 'never'] as const).map((o) => <option key={o} value={o}>{t(`detail.regularScanOpt.${o}`)}</option>)}
            </Select>
            <span className="max-w-xl text-[13px] text-muted">{t('detail.regularScanHint')}</span>
          </dd>
          {row(t('detail.firstScan'), a.first_scan_at ? fmtDateTime(a.first_scan_at) : <span className="text-muted">{t('detail.firstScanNone')}</span>)}
        </>
      ) : null}
      {row(t('detail.ip'), a.ip)}
      {row(t('detail.mac'), a.mac ?? <span className="text-muted">{t('common:unknown')}</span>)}
      {row(t('detail.firstSeen'), fmtDateTime(a.first_seen))}
      {row(t('detail.lastSeen'), `${fmtDateTime(a.last_seen)} (${fmtRelative(a.last_seen)})`)}
      {row(t('detail.origin'), a.is_box ? t('box.origin') : a.origin === 'manual' ? t('detail.originManual') : t('detail.originDiscovered'))}
    </dl>
  )
}

function Observations({ list }: { list: Observation[] }) {
  const { t } = useTranslation('inventory')
  const columns: ColumnDef<Observation>[] = [
    { id: 'field', header: t('obs.field'), accessorFn: (o) => t(`obs.fields.${o.field}`), cell: ({ getValue }) => <span className="whitespace-nowrap font-medium">{getValue() as string}</span> },
    { id: 'value', header: t('obs.value'), accessorFn: (o) => (o.field === 'kind' ? kindLabel(o.value) : o.value) },
    { id: 'source', header: t('obs.source'), accessorFn: (o) => o.confidence, cell: ({ row }) => <SourceBadge source={row.original.source} confidence={row.original.confidence} /> },
    { id: 'at', header: t('obs.at'), accessorFn: (o) => new Date(o.seen_at).getTime(), cell: ({ row }) => <time dateTime={row.original.seen_at} className="whitespace-nowrap text-[13px] text-muted">{fmtDateTime(row.original.seen_at)}</time> },
    { id: 'current', header: t('obs.state'), enableSorting: false, accessorFn: (o) => Number(o.current), cell: ({ row }) => (row.original.current ? <Chip tone="ok">{t('obs.current')}</Chip> : <span className="text-[13px] text-muted">{t('obs.kept')}</span>) },
  ]
  return (
    <DataTable caption={t('obs.caption')} data={list} columns={columns} pageSize={100}
      mobileRow={(o) => (
        <div className="grid gap-1">
          <div className="flex items-start justify-between gap-3">
            <span className="min-w-0 text-sm [overflow-wrap:anywhere]"><span className="font-medium">{t(`obs.fields.${o.field}`)}:</span> {o.field === 'kind' ? kindLabel(o.value) : o.value}</span>
            {o.current ? <Chip tone="ok">{t('obs.current')}</Chip> : null}
          </div>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px] text-muted">
            <SourceBadge source={o.source} confidence={o.confidence} />
            <time dateTime={o.seen_at}>{fmtDateTime(o.seen_at)}</time>
            {o.current ? null : <span>{t('obs.kept')}</span>}
          </div>
        </div>
      )} />
  )
}

function Services({ list, fragile }: { list: Service[]; fragile: boolean }) {
  const { t } = useTranslation('inventory')
  if (!list.length) return <EmptyState title={t('services.empty')}>{fragile ? t('services.emptyFragile') : t('services.emptyBody')}</EmptyState>
  const columns: ColumnDef<Service>[] = [
    { id: 'port', header: t('services.port'), accessorFn: (s) => s.port, cell: ({ row }) => <span className="whitespace-nowrap">{row.original.port}/{row.original.proto}</span> },
    { id: 'name', header: t('services.name'), accessorFn: (s) => s.name },
    { id: 'product', header: t('services.product'), accessorFn: (s) => [s.product, s.version].filter(Boolean).join(' '), cell: ({ getValue }) => (getValue() as string) || <span className="text-muted">–</span> },
    { id: 'detail', header: t('services.detail'), accessorFn: (s) => s.detail ?? '', cell: ({ getValue }) => <span className="text-[13px] [overflow-wrap:anywhere]">{(getValue() as string) || <span className="text-muted">–</span>}</span> },
    { id: 'source', header: t('obs.source'), accessorFn: (s) => s.confidence, cell: ({ row }) => <SourceBadge source={row.original.source} confidence={row.original.confidence} /> },
  ]
  return (
    <DataTable caption={t('services.caption')} data={list} columns={columns}
      mobileRow={(sv) => (
        <div className="grid gap-1">
          <span className="text-sm font-medium">{sv.port}/{sv.proto} {sv.name}</span>
          {sv.product || sv.version ? <span className="text-[13px] [overflow-wrap:anywhere]">{[sv.product, sv.version].filter(Boolean).join(' ')}</span> : null}
          {sv.detail ? <span className="text-[13px] text-muted [overflow-wrap:anywhere]">{sv.detail}</span> : null}
          <span className="text-[12px] text-muted"><SourceBadge source={sv.source} confidence={sv.confidence} /></span>
        </div>
      )} />
  )
}

const VERSION_RE = /^[A-Za-z0-9_.\-+() ]{1,40}$/ // the backend's versionRE: what "edit version" accepts
const sameProduct = (a: SoftwareView, b: SoftwareView) => a.vendor.toLowerCase() === b.vendor.toLowerCase() && a.product.toLowerCase() === b.product.toLowerCase()

/** D-471: a version a person typed (or left empty) that an agent or scan sees differently on the same device. */
function seenVersion(sw: SoftwareView, list: SoftwareView[]) {
  if (sw.source !== 'manual') return null
  const typed = (sw.version ?? '').trim().toLowerCase()
  return list.find((o) => o.source !== 'manual' && o.version && sameProduct(o, sw) && o.version.trim().toLowerCase() !== typed) ?? null
}

/** "Change the version" of software a person declared (D-471 edit version); empty removes it. */
function VersionDialog({ sw, assetId, onClose }: { sw: SoftwareView | null; assetId: string; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const act = useDeviceAction(assetId)
  const [value, setValue] = useState(sw?.version ?? '')
  const [error, setError] = useState<string | null>(null)
  if (!sw) return null
  const save = (e: FormEvent) => {
    e.preventDefault()
    const version = value.trim()
    act.setVersion.mutate({ sid: sw.id, version }, {
      onSuccess: () => { toast.success(version ? t('software.edited', { name: sw.display, version }) : t('software.editedNone', { name: sw.display })); onClose() },
      onError: (er) => setError(errMsg(er)),
    })
  }
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('software.editTitle', { name: sw.display })} description={t('software.editBody')}>
        <form onSubmit={save} className="grid gap-4" noValidate>
          <Field label={t('add.version')} htmlFor="sw-version" hint={t('add.versionHint')}>
            <Input id="sw-version" value={value} maxLength={40} placeholder={t('add.versionPlaceholder')} aria-describedby="sw-version-hint" onChange={(e) => { setValue(e.target.value); setError(null) }} />
          </Field>
          {error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-danger">{error}</p> : null}
          <DialogFooter>
            <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
            <Button type="submit" variant="primary" disabled={act.setVersion.isPending}>{t('software.editSave')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function SoftwareList({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const act = useDeviceAction(d.asset.id)
  const [editing, setEditing] = useState<SoftwareView | null>(null)
  const list = d.asset.software
  if (!list.length) return <EmptyState title={t('software.empty')}>{t('software.emptyBody')}</EmptyState>
  const needRole = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const version = (sw: SoftwareView) => {
    const seen = seenVersion(sw, list)
    const v = seen?.version ?? ''
    return (
      <div className="grid gap-1">
        <span>{sw.version || <span className="text-muted">{t('software.noVersion')}</span>}</span>
        {seen ? (
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px] text-warn">
            {t('software.seen', { version: v, source: t(`common:source.${seen.source}`) })}
            {VERSION_RE.test(v) ? (
              <Button size="sm" variant="secondary" disabled={!can || act.setVersion.isPending} title={needRole} aria-label={t('software.acceptLabel', { version: v, name: sw.display })}
                onClick={() => act.setVersion.mutate({ sid: sw.id, version: v }, { onSuccess: () => toast.success(t('software.edited', { name: sw.display, version: v })), onError: (e) => toast.error(errMsg(e)) })}>
                {t('software.accept', { version: v })}
              </Button>
            ) : null}
          </span>
        ) : null}
      </div>
    )
  }
  const actions = (sw: SoftwareView) => (sw.source === 'manual' ? (
    <div className="flex">
      <Button size="sm" variant="ghost" disabled={!can} aria-label={t('software.edit', { name: sw.display })} title={needRole ?? t('software.edit', { name: sw.display })} onClick={() => setEditing(sw)}><Pencil /></Button>
      <Button size="sm" variant="ghost" disabled={!can || act.removeSoftware.isPending} aria-label={t('software.remove', { name: sw.display })} title={t('software.remove', { name: sw.display })}
        onClick={() => act.removeSoftware.mutate(sw.id, { onSuccess: () => toast.success(t('software.removed', { name: sw.display })), onError: (e) => toast.error(errMsg(e)) })}><Trash2 /></Button>
    </div>
  ) : null)
  const columns: ColumnDef<SoftwareView>[] = [
    { id: 'name', header: t('software.name'), accessorFn: (s) => s.display, cell: ({ row }) => {
      const raw = rawProductLine(row.original.display, row.original.vendor, row.original.product)
      return <div className="grid"><span className="font-medium">{row.original.display}</span>{raw ? <span className="text-[12px] text-muted">{raw}</span> : null}</div>
    } },
    { id: 'version', header: t('software.version'), accessorFn: (s) => s.version ?? '', cell: ({ row }) => version(row.original) },
    { id: 'kev', header: t('software.kev'), accessorFn: (s) => s.kev_cves.length, cell: ({ row }) => row.original.kev_cves.length ? (
      <div className="flex flex-wrap gap-x-2">{row.original.kev_cves.map((c) => <Link key={c} to={`/cve/${c}`} className="whitespace-nowrap text-accent underline-offset-4 hover:underline">{c}</Link>)}</div>
    ) : <span className="text-[13px] text-muted">{t('software.noKev')}</span> },
    { id: 'source', header: t('obs.source'), accessorFn: (s) => s.confidence, cell: ({ row }) => (d.asset.is_box ? <span className="text-[12px] text-muted">{t('box.source')}</span> : <SourceBadge source={row.original.source} confidence={row.original.confidence} />) },
    { id: 'actions', header: () => <span className="sr-only">{t('software.actions')}</span>, enableSorting: false, cell: ({ row }) => actions(row.original) },
  ]
  return (
    <>
      <DataTable caption={t('software.caption')} data={list} columns={columns}
        mobileRow={(sw) => (
          <div className="flex items-start justify-between gap-3">
            <div className="grid min-w-0 gap-1">
              <span className="text-sm font-medium [overflow-wrap:anywhere]">{sw.display}</span>
              {rawProductLine(sw.display, sw.vendor, sw.product) ? <span className="text-[12px] text-muted">{rawProductLine(sw.display, sw.vendor, sw.product)}</span> : null}
              <div className="text-[13px]">{version(sw)}</div>
              <div className="flex flex-wrap gap-x-2 text-[13px]">
                {sw.kev_cves.length ? sw.kev_cves.map((c) => <Link key={c} to={`/cve/${c}`} className="whitespace-nowrap text-accent underline-offset-4 hover:underline">{c}</Link>) : <span className="text-muted">{t('software.noKev')}</span>}
              </div>
              <span className="text-[12px] text-muted">{d.asset.is_box ? t('box.source') : <SourceBadge source={sw.source} confidence={sw.confidence} />}</span>
            </div>
            {actions(sw)}
          </div>
        )} />
      <VersionDialog key={editing?.id ?? ''} sw={editing} assetId={d.asset.id} onClose={() => setEditing(null)} />
    </>
  )
}

function Notes({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const act = useDeviceAction(d.asset.id)
  const saved = d.asset.notes ?? ''
  const [text, setText] = useState(saved)
  return (
    <div className="grid max-w-2xl gap-2">
      <Label htmlFor="device-notes" className="sr-only">{t('notes.label')}</Label>
      <Textarea id="device-notes" value={text} maxLength={2000} disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })} placeholder={t('notes.placeholder')} onChange={(e) => setText(e.target.value)} />
      <div><Button disabled={!can || text === saved || act.patch.isPending} onClick={() => act.patch.mutate({ notes: text }, { onSuccess: () => toast.success(t('notes.saved')), onError: (e) => toast.error(errMsg(e)) })}>{t('notes.save')}</Button></div>
    </div>
  )
}

function Approval({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const act = useDeviceAction(d.asset.id)
  const navigate = useNavigate()
  const [del, setDel] = useState(false)
  const name = nameOf(d.asset, kindLabel(d.asset.kind))
  const fail = (e: unknown) => toast.error(errMsg(e))
  return (
    <div className="mb-8 grid gap-3 rounded-md border border-dashed border-warn bg-warn-soft/60 p-4 md:grid-cols-[1fr_auto] md:items-center">
      <div>
        <p className="font-medium">{d.suspicious ? t('approval.suspicious') : t('approval.pending')}</p>
        <p className="mt-1 max-w-2xl text-sm text-muted">{t('approval.body')}</p>
      </div>
      <div className="flex flex-wrap gap-2">
        <Button variant="primary" disabled={!can || act.approve.isPending} onClick={() => act.approve.mutate(undefined, { onSuccess: () => toast.success(t('pending.approved', { name }), { description: t('pending.findLater') }), onError: fail })}>{t('pending.approve')}</Button>
        <Button disabled={!can || act.suspicious.isPending} onClick={() => act.suspicious.mutate(!d.suspicious, { onSuccess: () => toast.success(d.suspicious ? t('pending.unmarked', { name }) : t('pending.marked', { name })), onError: fail })}>{d.suspicious ? t('pending.unmark') : t('pending.mark')}</Button>
        <Button disabled={!can} onClick={() => setDel(true)}>{t('pending.delete')}</Button>
      </div>
      <DeleteDialog open={del} onOpenChange={setDel} name={name} findings={d.findings_count} pending={act.remove.isPending}
        onConfirm={() => act.remove.mutate(undefined, { onSuccess: () => { toast.success(t('delete.done', { name })); void navigate('/devices') }, onError: fail })} />
    </div>
  )
}

/** D-53: the box is the first device; its findings are fixed by updating the operating system, not by a device vendor. */
function BoxNotice({ findings }: { findings: number }) {
  const { t } = useTranslation('inventory')
  const install = useInstallKind() // D-381; undefined while GET /modules loads: then neither claim about packages is made
  const packages = install === 'container' ? t('box.packagesContainer') : install === 'appliance' ? t('box.packagesAppliance') : ''
  return (
    <div className="mb-8 grid gap-1 rounded-md border border-accent/40 bg-accent-soft/50 p-4">
      <p className="font-medium">{t('box.title')}</p>
      <p className="max-w-3xl text-sm text-muted">{[t('box.lead'), packages, t('box.matched')].filter(Boolean).join(' ')}</p>
      <p className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
        <Link to="/settings/updates" className="font-medium text-accent underline-offset-4 hover:underline">{t('box.fix')}</Link>
        <span className="text-[13px] text-muted">{t('box.noDelete')}</span>
        {findings ? <Link to="/findings" className="text-accent underline-offset-4 hover:underline">{t('box.findings', { count: findings })}</Link> : null}
      </p>
    </div>
  )
}

function Body() {
  const { t } = useTranslation('inventory')
  const { id = '' } = useParams()
  const q = useDevice(id)
  const can = useCan('operator')
  const navigate = useNavigate()
  const act = useDeviceAction(id)
  const [adding, setAdding] = useState(false)
  const [del, setDel] = useState(false)
  const back = <Link to="/devices" className={cn(buttonVariants({ variant: 'link', size: 'sm' }), 'mb-3 inline-flex')}><ArrowLeft />{t('detail.back')}</Link>

  if (q.isPending) return <>{back}<Loading /></>
  if (q.error) {
    if (q.error instanceof ApiError && q.error.status === 404) return <>{back}<EmptyState title={t('detail.notFound')}>{q.error.message}</EmptyState></>
    return <>{back}<ErrorState error={q.error} onRetry={() => void q.refetch()} /></>
  }
  const d = q.data
  const a = d.asset
  const name = nameOf(a, kindLabel(a.kind))
  const needRole = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  return (
    <>
      {back}
      <PageHeader title={<span className="[overflow-wrap:anywhere]">{t('detail.title', { name, kind: kindLabel(a.kind), when: fmtRelative(a.last_seen) })}</span>} stories={['S-INV-1', 'S-INV-2']}
        meta={<span className="inline-flex flex-wrap items-center gap-2">{a.is_box ? <Chip tone="accent">{t('box.badge')}</Chip> : null}<SampleDataNote />{t('detail.meta')}</span>}
        actions={<Button disabled={!can || a.is_box} title={a.is_box ? t('box.noDelete') : needRole} onClick={() => setDel(true)}><Trash2 />{t('detail.delete')}</Button>} />
      {a.is_box ? <BoxNotice findings={d.findings_count} /> : null}
      {!a.approved ? <Approval d={d} /> : null}
      <Section id="overview" title={t('detail.overview')}><Panel className="p-4"><Overview d={d} /></Panel></Section>
      <Section id="obs" title={t('obs.title')} description={t('obs.description')}><Observations list={d.observations} /></Section>
      <Section id="services" title={t('services.title')} description={t('services.description')}><Services list={a.services} fragile={a.fragile} /></Section>
      <Section id="software" title={t('software.title')} description={t('software.description')}
        actions={<Button disabled={!can} title={needRole} onClick={() => setAdding(true)}><Plus />{t('software.add')}</Button>}>
        <SoftwareList d={d} />
      </Section>
      <Section id="notes" title={t('notes.title')}><Notes key={a.notes ?? ''} d={d} /></Section>
      <Slot name="device.panels" props={{ assetId: a.id }} />
      <AddDeviceDialog open={adding} onOpenChange={setAdding} deviceId={a.id} />
      <DeleteDialog open={del} onOpenChange={setDel} name={name} findings={d.findings_count} pending={act.remove.isPending}
        onConfirm={() => act.remove.mutate(undefined, { onSuccess: () => { toast.success(t('delete.done', { name })); void navigate('/devices') }, onError: (e) => toast.error(errMsg(e)) })} />
    </>
  )
}

export default function DevicePage() {
  const { t } = useTranslation('inventory')
  return (
    <RequireModule module="inventory" fallback={<><PageHeader title={t('off.title')} /><ModuleOff module="inventory">{t('off.body')}</ModuleOff></>}>
      <Body />
    </RequireModule>
  )
}
