import { useRef, useState, type RefObject } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Pencil, Plus, Trash2 } from 'lucide-react'
import { Breadcrumbs } from '@/components/common/Breadcrumbs'
import { Card } from '@/components/common/Card'
import { Notice, PageHeader, Section } from '@/components/common/PageHeader'
import { InfoTip } from '@/components/common/InfoTip'
import { KpiStrip, PageTabs } from '@/components/common/PageFrame'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, ErrorState, Loading, ModuleOff, RequireModule, SampleDataNote } from '@/components/common/States'
import { SourceBadge } from '@/components/common/SourceBadge'
import { Slot } from '@/components/common/Slot'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Input, Select, Textarea, Label } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { ApiError } from '@/lib/api'
import { fmtDateTime, fmtRelative, rawProductLine } from '@/lib/format'
import { useCan } from '@/lib/session'
import type { AssetKind, Service } from '@/lib/types'
import { categoryLabel, categoryOf, kindLabel, TYPES_BY_CATEGORY } from '@/lib/deviceTypes'
import { AddDeviceDialog } from './AddDeviceDialog'
import { useDevice, useDeviceAction } from './api'
import { useInstallKind, useModuleEnabled } from '@/lib/modules'
import { useFindings } from '@/features/findings/api'
import { isOpen } from '@/features/findings/basis'
import { DeleteDialog } from './DeleteDialog'
import { VersionDialog } from './VersionDialog'
import { errMsg } from './kinds'
import { badUserName, declaredSoftwareOnly, nameOf } from './nameOf'
import { DeviceSources } from './DeviceSources'
import { PossibleSameNotice } from './SameDevice'
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
    <div className="contents"><dt className="text-meta text-muted">{label}</dt><dd className="text-sm">{value}</dd></div>
  )
  return (
    <dl className="grid grid-cols-1 items-center gap-x-6 gap-y-3 sm:grid-cols-[minmax(160px,max-content)_1fr]">
      <dt className="text-meta text-muted"><Label htmlFor="device-kind" className="text-meta font-normal text-muted">{t('detail.kind')}</Label></dt>
      <dd>
        <span className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <Select id="device-kind" className="max-w-xs" value={a.kind} disabled={!can || act.patch.isPending} title={needRole}
            onChange={(e) => setKind(e.target.value as AssetKind)}>
            {TYPES_BY_CATEGORY.map(({ category, types }) => {
              const listed = types.filter((ty) => d.kinds.includes(ty.id))
              return listed.length ? <optgroup key={category.id} label={category.label}>{listed.map((ty) => <option key={ty.id} value={ty.id}>{ty.label}</option>)}</optgroup> : null
            })}
          </Select>
          {a.kind !== 'unknown' ? <span className="text-meta text-muted">{categoryLabel(categoryOf(a.kind))}</span> : null}
          {a.kind_source ? <span className="text-caption text-muted">{t('detail.kindFrom')} <SourceBadge source={a.kind_source} /></span> : null}
        </span>
        {guess ? (
          <div className="mt-2 grid max-w-2xl gap-1.5 rounded-md border border-border p-3" data-testid="kind-guess">
            <div className="flex items-center gap-1">
              <p className="text-sm">
                <span className="font-medium">{t('guess.title', { kind: kindLabel(guess.kind), category: categoryLabel(categoryOf(guess.kind)) })}</span>
                {guess.model ? <span className="text-muted"> {t('guess.model', { model: guess.model })}</span> : null}
              </p>
              <InfoTip topic={t('guess.topic')}><p>{t('guess.hint')}</p>{guess.alternatives?.length ? <p>{t('guess.alternativesInfo')}</p> : null}</InfoTip>
            </div>
            <p className="text-meta text-muted [overflow-wrap:anywhere]">{guess.evidence}</p>
            {guess.alternatives?.length ? <p className="text-caption text-muted">{t('guess.alternatives', { list: guess.alternatives.map(kindLabel).join(', ') })}</p> : null}
            <span className="flex flex-wrap gap-2">
              <Button size="sm" disabled={!can || act.patch.isPending} title={needRole} onClick={() => setKind(guess.kind)}>{t('guess.confirm', { kind: kindLabel(guess.kind) })}</Button>
              {(guess.alternatives ?? []).map((k) => <Button key={k} size="sm" variant="ghost" disabled={!can || act.patch.isPending} title={needRole} onClick={() => setKind(k)}>{t('guess.instead', { kind: kindLabel(k) })}</Button>)}
            </span>
          </div>
        ) : null}
      </dd>
      <dt className="flex items-center gap-1 text-meta text-muted"><Label htmlFor="device-fragile" className="text-meta font-normal text-muted">{t('detail.fragile')}</Label><InfoTip topic={t('detail.fragile')}>{t('detail.fragileInfo')}</InfoTip></dt>
      <dd className="flex flex-wrap items-center gap-3">
        <Switch id="device-fragile" checked={a.fragile} disabled={!can || act.patch.isPending} title={needRole}
          onCheckedChange={(v) => act.patch.mutate({ fragile: v }, { onSuccess: () => toast.success(v ? t('detail.fragileOn') : t('detail.fragileOff')), onError: fail })} />
        <span className="max-w-xl text-meta text-muted">{a.fragile ? t('detail.fragileOnHint') : t('detail.fragileOffHint')}</span>
      </dd>
      {a.fragile ? (
        <>
          <dt className="flex items-center gap-1 text-meta text-muted"><Label htmlFor="device-regular" className="text-meta font-normal text-muted">{t('detail.regularScan')}</Label><InfoTip topic={t('detail.regularScan')}>{t('detail.regularScanHint')}</InfoTip></dt>
          <dd className="flex flex-wrap items-center gap-3">
            <Select id="device-regular" className="max-w-xs" value={a.regular_scan} disabled={!can || act.patch.isPending} title={needRole}
              onChange={(e) => act.patch.mutate({ regular_scan: e.target.value as RegularScan }, { onSuccess: () => toast.success(t('detail.regularScanSaved')), onError: fail })}>
              {(['follow', 'allow', 'never'] as const).map((o) => <option key={o} value={o}>{t(`detail.regularScanOpt.${o}`)}</option>)}
            </Select>
          </dd>
          {row(t('detail.firstScan'), a.first_scan_at ? fmtDateTime(a.first_scan_at) : <span className="text-muted">{t('detail.firstScanNone')}</span>)}
        </>
      ) : null}
      {row(t('detail.hostname'), <HostName d={d} />)}
      {row(t('detail.ip'), a.ip)}
      {row(t('detail.mac'), a.mac ?? <span className="text-muted">{t('common:unknown')}</span>)}
      {row(t('detail.firstSeen'), fmtDateTime(a.first_seen))}
      {row(t('detail.lastSeen'), `${fmtDateTime(a.last_seen)} (${fmtRelative(a.last_seen)})`)}
      {row(t('detail.origin'), a.is_box ? t('box.origin') : a.origin === 'manual' ? t('detail.originManual') : t('detail.originDiscovered'))}
    </dl>
  )
}

/** G2: the host name the network reports (or typed when the device was added), with its source: read-only, apart from the name in
 *  Vedette that the title shows and Rename changes. */
function HostName({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const host = d.asset.hostname
  if (!host) return <span className="text-muted">{t('detail.hostnameNone')}</span>
  const obs = d.observations.find((o) => o.field === 'hostname' && o.current)
  return (
    <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1">
      <span className="[overflow-wrap:anywhere]" data-testid="device-hostname">{host}</span>
      {obs ? <SourceBadge source={obs.source} confidence={obs.confidence} /> : null}
    </span>
  )
}

/** G2 (kien): rename the device in Vedette where its name is, next to the page title. The name wins on every page (nameOf,
 *  inventory.DisplayName); empty goes back to the default name. Enter saves, Escape cancels. The host name the network reports is not
 *  changed. `editing` false: the Rename button; true: the field that takes the title's place. */
function RenameDevice({ d, editing, setEditing, button }: { d: DeviceDetail; editing: boolean; setEditing: (v: boolean) => void; button: RefObject<HTMLButtonElement | null> }) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const act = useDeviceAction(d.asset.id)
  const saved = d.asset.name ?? ''
  const [text, setText] = useState(saved) // the field mounts on Rename, so it starts from the saved name
  const fallback = nameOf({ ...d.asset, name: null }, kindLabel(d.asset.kind)) // the default name: what an empty name shows
  const next = text.trim()
  const bad = badUserName(next) // the characters the backend refuses (review r1 of #929)
  const [refused, setRefused] = useState('') // why the server refused the last save, next to the field (review r1 of #929)
  const field = useRef<HTMLInputElement>(null)
  const close = () => { setEditing(false); requestAnimationFrame(() => button.current?.focus()) } // focus back on Rename, which comes back
  const save = () => {
    if (bad || act.patch.isPending) return
    if (next === saved) { close(); return }
    act.patch.mutate({ name: next }, {
      onSuccess: () => { toast.success(next ? t('detail.renamed', { name: next }) : t('detail.renameReset', { name: fallback })); close() },
      // the field stays focused and says why next to it, for keyboard and screen-reader users
      onError: (e) => { setRefused(errMsg(e)); requestAnimationFrame(() => field.current?.focus()) },
    })
  }
  if (!editing) {
    return (
      <Button ref={button} size="sm" variant="ghost" className="ml-1" disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}
        onClick={() => setEditing(true)}><Pencil />{t('detail.rename')}</Button>
    )
  }
  return (
    <span className="flex flex-wrap items-center gap-2">
      {/* readOnly, not disabled, while saving: a disabled field would drop the keyboard focus to the page */}
      <Input ref={field} id="device-name" autoFocus className="w-80 max-w-full" value={text} maxLength={64} aria-label={t('detail.renameLabel')}
        aria-invalid={bad || !!refused || undefined} aria-describedby={refused || bad ? 'device-name-error device-name-hint' : 'device-name-hint'} placeholder={fallback}
        readOnly={act.patch.isPending} aria-busy={act.patch.isPending || undefined}
        onChange={(e) => { setText(e.target.value); setRefused('') }}
        onKeyDown={(e) => {
          if (e.key === 'Enter') { e.preventDefault(); save() }
          if (e.key === 'Escape') { e.preventDefault(); close() }
        }} />
      <Button size="sm" variant="primary" disabled={bad || act.patch.isPending} onClick={save}>{t('detail.renameSave')}</Button>
      <Button size="sm" variant="ghost" disabled={act.patch.isPending} onClick={close}>{t('detail.renameCancel')}</Button>
      {bad || refused ? <span id="device-name-error" role="alert" className="w-full text-caption text-danger">{bad ? t('detail.renameBad') : refused}</span> : null}
    </span>
  )
}

function Observations({ list }: { list: Observation[] }) {
  const { t } = useTranslation('inventory')
  const columns: ColumnDef<Observation>[] = [
    { id: 'field', header: t('obs.field'), accessorFn: (o) => t(`obs.fields.${o.field}`), cell: ({ getValue }) => <span className="whitespace-nowrap font-medium">{getValue() as string}</span> },
    { id: 'value', header: t('obs.value'), accessorFn: (o) => (o.field === 'kind' ? kindLabel(o.value) : o.value) },
    { id: 'source', header: t('obs.source'), accessorFn: (o) => o.confidence, cell: ({ row }) => <SourceBadge source={row.original.source} confidence={row.original.confidence} /> },
    { id: 'at', header: t('obs.at'), accessorFn: (o) => new Date(o.seen_at).getTime(), cell: ({ row }) => <time dateTime={row.original.seen_at} className="whitespace-nowrap text-meta text-muted">{fmtDateTime(row.original.seen_at)}</time> },
    { id: 'current', header: t('obs.state'), enableSorting: false, accessorFn: (o) => Number(o.current), cell: ({ row }) => (row.original.current ? <Chip tone="ok">{t('obs.current')}</Chip> : <span className="text-meta text-muted">{t('obs.kept')}</span>) },
  ]
  return (
    <DataTable caption={t('obs.caption')} data={list} columns={columns} pageSize={100}
      mobileRow={(o) => (
        <div className="grid gap-1">
          <div className="flex items-start justify-between gap-3">
            <span className="min-w-0 text-sm [overflow-wrap:anywhere]"><span className="font-medium">{t(`obs.fields.${o.field}`)}:</span> {o.field === 'kind' ? kindLabel(o.value) : o.value}</span>
            {o.current ? <Chip tone="ok">{t('obs.current')}</Chip> : null}
          </div>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-caption text-muted">
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
  if (!list.length) return <EmptyState title={t('services.empty')} info={fragile ? t('services.emptyFragileInfo') : t('services.emptyBodyInfo')}>{fragile ? t('services.emptyFragile') : t('services.emptyBody')}</EmptyState>
  const columns: ColumnDef<Service>[] = [
    { id: 'port', header: t('services.port'), accessorFn: (s) => s.port, cell: ({ row }) => <span className="whitespace-nowrap">{row.original.port}/{row.original.proto}</span> },
    { id: 'name', header: t('services.name'), accessorFn: (s) => s.name },
    { id: 'product', header: t('services.product'), accessorFn: (s) => s.product ?? '', cell: ({ getValue }) => (getValue() as string) || <span className="text-muted">–</span> },
    { id: 'version', header: t('services.version'), accessorFn: (s) => s.version ?? '', cell: ({ getValue }) => (getValue() as string) || <span className="text-muted">–</span> },
    { id: 'detail', header: t('services.detail'), accessorFn: (s) => s.detail ?? '', cell: ({ getValue }) => <span className="text-meta [overflow-wrap:anywhere]">{(getValue() as string) || <span className="text-muted">–</span>}</span> },
    { id: 'source', header: t('obs.source'), accessorFn: (s) => s.confidence, cell: ({ row }) => <SourceBadge source={row.original.source} confidence={row.original.confidence} /> },
  ]
  return (
    <DataTable caption={t('services.caption')} data={list} columns={columns}
      mobileRow={(sv) => (
        <div className="grid gap-1">
          <span className="text-sm font-medium">{sv.port}/{sv.proto} {sv.name}</span>
          {sv.product || sv.version ? <span className="text-meta [overflow-wrap:anywhere]">{[sv.product, sv.version].filter(Boolean).join(' ')}</span> : null}
          {sv.detail ? <span className="text-meta text-muted [overflow-wrap:anywhere]">{sv.detail}</span> : null}
          <span className="text-caption text-muted"><SourceBadge source={sv.source} confidence={sv.confidence} /></span>
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

/**
 * W11-1: the exploited CVEs of a software row are the device's OPEN findings (findings' isOpen) whose CVE is one of
 * that product's KEV CVEs. kev_cves alone is every CVE ever exploited in the product, versions not checked (Bash 5.3
 * "has" Shellshock); like Tenable and Qualys, the device shows only what detection found. Findings off → it says so.
 */
function OpenCves({ sw, open }: { sw: SoftwareView; open: Map<string, string> | 'off' | 'pending' | 'error' }) {
  const { t } = useTranslation('inventory')
  if (open === 'off') return <span className="text-meta text-muted">{t('software.kevOff')}</span>
  if (open === 'pending') return <span className="text-meta text-muted">{t('software.kevPending')}</span>
  if (open === 'error') return <span className="text-meta text-muted">{t('software.kevError')}</span>
  const cves = sw.kev_cves.filter((c) => open.has(c))
  if (!cves.length) return <span className="text-meta text-muted">{t('software.noKev')}</span>
  return <div className="flex flex-wrap gap-x-2">{cves.map((c) => <Link key={c} to={`/findings/${encodeURIComponent(open.get(c)!)}`} className="whitespace-nowrap text-accent underline-offset-4 hover:underline">{c}</Link>)}</div>
}

/** CVE → id of the device's open finding for it; the states the column shows instead while there is no list. */
function useOpenFindings(assetId: string): Map<string, string> | 'off' | 'pending' | 'error' {
  const on = useModuleEnabled('findings')
  const q = useFindings(assetId)
  if (on === false) return 'off'
  if (q.isError) return 'error'
  if (on === undefined || q.isPending) return 'pending'
  return new Map(q.data.items.filter((f) => isOpen(f.status)).map((f) => [f.cve, f.id]))
}

function SoftwareList({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const act = useDeviceAction(d.asset.id)
  const [editing, setEditing] = useState<SoftwareView | null>(null)
  const open = useOpenFindings(d.asset.id)
  const list = d.asset.software
  if (!list.length) return <EmptyState title={t('software.empty')} info={t('software.emptyBodyInfo')}>{t('software.emptyBody')}</EmptyState>
  const openCount = (sw: SoftwareView) => (open instanceof Map ? sw.kev_cves.filter((c) => open.has(c)).length : 0)
  const needRole = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const version = (sw: SoftwareView) => {
    const seen = seenVersion(sw, list)
    const v = seen?.version ?? ''
    return (
      <div className="grid gap-1">
        <span>{sw.version || <span className="text-muted">{t('software.noVersion')}</span>}</span>
        {seen ? (
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-caption text-warn">
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
      return <div className="grid"><span className="font-medium">{row.original.display}</span>{raw ? <span className="text-caption text-muted">{raw}</span> : null}</div>
    } },
    { id: 'version', header: t('software.version'), accessorFn: (s) => s.version ?? '', cell: ({ row }) => version(row.original) },
    { id: 'kev', header: t('software.kev'), accessorFn: openCount, cell: ({ row }) => <OpenCves sw={row.original} open={open} /> },
    { id: 'source', header: t('obs.source'), accessorFn: (s) => s.confidence, cell: ({ row }) => (d.asset.is_box ? <span className="text-caption text-muted">{t('box.source')}</span> : <SourceBadge source={row.original.source} confidence={row.original.confidence} />) },
    { id: 'actions', header: () => <span className="sr-only">{t('software.actions')}</span>, enableSorting: false, cell: ({ row }) => actions(row.original) },
  ]
  return (
    <>
      <DataTable caption={t('software.caption')} data={list} columns={columns}
        mobileRow={(sw) => (
          <div className="flex items-start justify-between gap-3">
            <div className="grid min-w-0 gap-1">
              <span className="text-sm font-medium [overflow-wrap:anywhere]">{sw.display}</span>
              {rawProductLine(sw.display, sw.vendor, sw.product) ? <span className="text-caption text-muted">{rawProductLine(sw.display, sw.vendor, sw.product)}</span> : null}
              <div className="text-meta">{version(sw)}</div>
              <div className="text-meta"><OpenCves sw={sw} open={open} /></div>
              <span className="text-caption text-muted">{d.asset.is_box ? t('box.source') : <SourceBadge source={sw.source} confidence={sw.confidence} />}</span>
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
    <Notice tone="warn" title={d.suspicious ? t('approval.suspicious') : t('approval.pending')} info={t('approval.bodyInfo')} actions={<>
        <Button variant="primary" disabled={!can || act.approve.isPending} onClick={() => act.approve.mutate(undefined, { onSuccess: () => toast.success(t('pending.approved', { name }), { description: t('pending.findLater') }), onError: fail })}>{t('pending.approve')}</Button>
        <Button disabled={!can || act.suspicious.isPending} onClick={() => act.suspicious.mutate(!d.suspicious, { onSuccess: () => toast.success(d.suspicious ? t('pending.unmarked', { name }) : t('pending.marked', { name })), onError: fail })}>{d.suspicious ? t('pending.unmark') : t('pending.mark')}</Button>
        <Button disabled={!can} onClick={() => setDel(true)}>{t('pending.delete')}</Button>
      </>}>
      {t('approval.body')}
      <DeleteDialog open={del} onOpenChange={setDel} name={name} findings={d.findings_count} pending={act.remove.isPending}
        onConfirm={() => act.remove.mutate(undefined, { onSuccess: () => { toast.success(t('delete.done', { name })); void navigate('/devices') }, onError: fail })} />
    </Notice>
  )
}

/** D-53: the box is the first device; its findings are fixed by updating the operating system, not by a device vendor. */
function BoxNotice({ findings }: { findings: number }) {
  const { t } = useTranslation('inventory')
  const install = useInstallKind() // D-381; undefined while GET /modules loads: then neither claim about packages is made
  const packages = install === 'container' ? t('box.packagesContainer') : install === 'appliance' ? t('box.packagesAppliance') : ''
  return (
    <Notice tone="accent" title={t('box.title')} info={[t('box.lead'), packages].filter(Boolean).join(' ')}>
      <p>{t('box.matched')}</p>
      <p className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-ink">
        <Link to="/settings/updates" className="font-medium text-accent underline-offset-4 hover:underline">{t('box.fix')}</Link>
        <span className="text-meta text-muted">{t('box.noDelete')}</span>
        {findings ? <Link to="/findings" className="text-accent underline-offset-4 hover:underline">{t('box.findings', { count: findings })}</Link> : null}
      </p>
    </Notice>
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
  const [renaming, setRenaming] = useState(false)
  const renameButton = useRef<HTMLButtonElement>(null)
  // UI.md §3: breadcrumbs (parents only) above the title; also while the device loads or is missing, so the way back is always there.
  const crumbs = [{ label: t('nav.devices'), to: '/devices' }]
  const back = <Breadcrumbs items={crumbs} />

  if (q.isPending) return <>{back}<Loading /></>
  if (q.error) {
    if (q.error instanceof ApiError && q.error.status === 404) return <>{back}<EmptyState title={t('detail.notFound')}>{q.error.message}</EmptyState></>
    return <>{back}<ErrorState error={q.error} onRetry={() => void q.refetch()} /></>
  }
  const d = q.data
  const a = d.asset
  const name = nameOf(a, kindLabel(a.kind))
  const needRole = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  // Khung D-464 / D-543: tiêu đề → thông báo (máy là hộp, chưa duyệt) → dải số → tab ở ?tab=. Các khối module khác cắm vào (slot device.panels) nằm ở tab Overview.
  return (
    <>
      <PageHeader breadcrumbs={crumbs} title={<span className="[overflow-wrap:anywhere]">{name}</span>} stories={['S-INV-1', 'S-INV-2', 'S-INV-3']}
        meta={renaming
          ? <span id="device-name-hint" className="max-w-xl">{t('detail.renameHint', { name: nameOf({ ...a, name: null }, kindLabel(a.kind)) })}</span>
          : <span className="inline-flex flex-wrap items-center gap-2">{a.is_box ? <Chip tone="accent">{t('box.badge')}</Chip> : null}<span>{t('detail.metaLine', { kind: kindLabel(a.kind), when: fmtRelative(a.last_seen) })}</span><SampleDataNote /></span>}
        titleAction={<RenameDevice key="rename" d={d} editing={false} setEditing={setRenaming} button={renameButton} />}
        editing={renaming ? <RenameDevice key="edit" d={d} editing setEditing={setRenaming} button={renameButton} /> : undefined}
        actions={<>
          {/* #850: "Check this device now" plugs in here (slot device.actions, props { assetId, asset }: the facts that say whether
              it can be checked, from this page's own read, #877 r1 L6). */}
          <Slot name="device.actions" props={{ assetId: a.id, asset: a }} />
          <Button disabled={!can || a.is_box} title={a.is_box ? t('box.noDelete') : needRole} onClick={() => setDel(true)}><Trash2 />{t('detail.delete')}</Button>
        </>} />
      {a.is_box ? <BoxNotice findings={d.findings_count} /> : null}
      {/* D-599 (#829): before the approval, since merging a new row into the known device answers its approval too */}
      <PossibleSameNotice me={{ id: a.id, name, approved: a.approved }} list={d.possible_same ?? []} />
      {!a.approved ? <Approval d={d} /> : null}
      {declaredSoftwareOnly(a) ? <Notice tone="accent" title={t('declared.title')}>{t('declared.body')}</Notice> : null}
      <DeviceKpis d={d} />
      <PageTabs label={t('detail.tabs.label')} tabs={[
        { id: 'overview', label: t('detail.tabs.overview'), panel: (
          <>
            <Section id="overview" title={t('detail.overview')}><Card><Overview d={d} /></Card></Section>
            {a.is_box || declaredSoftwareOnly(a) ? null : <DeviceSources d={d} />}
            <Slot name="device.panels" props={{ assetId: a.id }} />
            <Section id="notes" title={t('notes.title')}><Notes key={a.notes ?? ''} d={d} /></Section>
          </>
        ) },
        { id: 'software', label: t('detail.tabs.software'), panel: (
          <Section id="software" title={t('software.title')} description={t('software.description')} info={t('software.descriptionInfo')}
            actions={<Button disabled={!can} title={needRole} onClick={() => setAdding(true)}><Plus />{t('software.add')}</Button>}>
            <SoftwareList d={d} />
          </Section>
        ) },
        { id: 'services', label: t('detail.tabs.services'), panel: (
          <Section id="services" title={t('services.title')} description={t('services.description')} info={<><p>{t('services.descriptionInfo')}</p><p>{t('services.descriptionInfo2')}</p></>}><Services list={a.services} fragile={a.fragile} /></Section>
        ) },
        { id: 'observations', label: t('detail.tabs.observations'), panel: (
          <Section id="obs" title={t('obs.title')} description={t('obs.description')} info={<><p>{t('obs.descriptionInfo')}</p><p>{t('detail.meta')}</p></>}>
            <Observations list={d.observations} />
          </Section>
        ) },
      ]} />
      <AddDeviceDialog open={adding} onOpenChange={setAdding} deviceId={a.id} />
      <DeleteDialog open={del} onOpenChange={setDel} name={name} findings={d.findings_count} pending={act.remove.isPending}
        onConfirm={() => act.remove.mutate(undefined, { onSuccess: () => { toast.success(t('delete.done', { name })); void navigate('/devices') }, onError: (e) => toast.error(errMsg(e)) })} />
    </>
  )
}

/** Ba con số trả lời "máy này có sao không": phát hiện (khi module findings bật), phần mềm, dịch vụ mở; mỗi số dẫn tới chỗ xem. */
function DeviceKpis({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const findingsOn = useModuleEnabled('findings')
  const id = encodeURIComponent(d.asset.id)
  return (
    <KpiStrip label={t('detail.kpi.label')} items={[
      ...(findingsOn ? [{ value: d.findings_count, label: t('detail.kpi.findings'), to: `/findings?device=${id}` }] : []),
      { value: d.asset.software.length, label: t('detail.kpi.software'), to: '?tab=software' },
      { value: d.asset.services.length, label: t('detail.kpi.services'), to: '?tab=services' },
    ]} />
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
