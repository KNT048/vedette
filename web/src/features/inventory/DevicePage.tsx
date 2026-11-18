import { useRef, useState, type RefObject } from 'react'
import { useNavigate, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { EyeOff, Pencil, Plus, Trash2 } from 'lucide-react'
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
import { fmtDate, fmtDateTime, fmtRelative, rawProductLine } from '@/lib/format'
import { useCan } from '@/lib/session'
import type { AssetKind, Service } from '@/lib/types'
import { categoryLabel, categoryOf, kindLabel, TYPES_BY_CATEGORY } from '@/lib/deviceTypes'
import { AddDeviceDialog } from './AddDeviceDialog'
import { useDevice, useDeviceAction } from './api'
import { DetectedNotice } from './DetectedNotice'
import { useScanning } from '@/features/scanning/api'
import { scanRefusal } from '@/features/scanning/canScan'
import type { Scanning } from '@/features/scanning/types'
import { useModuleEnabled } from '@/lib/modules'
import { OsNeeds, SoftwareNeeds, useSoftwareNeeds } from '@/features/findings/SoftwareNeeds'
import { useDeviceFindingCounts } from '@/features/findings/notRelevant'
import { DeleteDialog } from './DeleteDialog'
import { VersionDialog } from './VersionDialog'
import { NotInstalledDialog } from './NotInstalledDialog'
import { errMsg } from './kinds'
import { badUserName, declaredSoftwareOnly, hasSourcesCard, nameOf, neverSeen } from './nameOf'
import { DeviceSources } from './DeviceSources'
import { DeviceSnmpCard } from './SnmpCard'
import { PossibleSameNotice } from './SameDevice'
import { BoxNotice } from './BoxNotice'
import { IgnoreDialog, IgnoredNotice } from './IgnoreDevice'
import type { DeviceDetail, Observation, RegularScan, SoftwareView } from './types'
import { RiskMarker } from './RiskMarker'

/** #944: the fragile line promises a scan only when Vedette may scan the device now, by the one rule
 *  "Check this device now" uses (scanning/canScan.ts: the device, the ranges and exclusions, the ranges confirmed, discovery on);
 *  otherwise it says why. A device added by hand with its network scan off gets what fragile means instead: why it is not scanned
 *  is said once, on its Sources card. */
function scanHint(a: DeviceDetail['asset'], scanning: Scanning | undefined, t: (k: string) => string): string {
  const r = scanRefusal(a, scanning)
  if (r === 'manual') return t('detail.fragileInfo')
  if (r) return t(`scanning:selection.device.${r}`)
  return a.fragile ? t('detail.fragileOnHint') : t('detail.fragileOffHint')
}

function Overview({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const act = useDeviceAction(d.asset.id)
  const needRole = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const a = d.asset
  const fail = (e: unknown) => toast.error(errMsg(e))
  const scanning = useScanning().data
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
        <DetectedNotice d={d} field="kind" />
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
              <Button size="sm" disabled={!can || act.patch.isPending} busy={act.patch.isPending && act.patch.variables?.kind === guess.kind} busyLabel={t('common:busy.saving')} title={needRole} onClick={() => setKind(guess.kind)}>{t('guess.confirm', { kind: kindLabel(guess.kind) })}</Button>
              {(guess.alternatives ?? []).map((k) => <Button key={k} size="sm" variant="ghost" disabled={!can || act.patch.isPending} busy={act.patch.isPending && act.patch.variables?.kind === k} busyLabel={t('common:busy.saving')} title={needRole} onClick={() => setKind(k)}>{t('guess.instead', { kind: kindLabel(k) })}</Button>)}
            </span>
          </div>
        ) : null}
      </dd>
      <dt className="flex items-center gap-1 text-meta text-muted"><Label htmlFor="device-fragile" className="text-meta font-normal text-muted">{t('detail.fragile')}</Label>{scanRefusal(a, scanning) === 'manual' ? null : <InfoTip topic={t('detail.fragile')}>{t('detail.fragileInfo')}</InfoTip>}</dt>
      <dd className="flex flex-wrap items-center gap-3">
        <Switch id="device-fragile" checked={a.fragile} disabled={!can || act.patch.isPending} title={needRole}
          onCheckedChange={(v) => act.patch.mutate({ fragile: v }, { onSuccess: () => toast.success(v ? t('detail.fragileOn') : t('detail.fragileOff')), onError: fail })} />
        <span className="max-w-xl text-meta text-muted">{scanHint(a, scanning, t)}</span>
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
      {row(t('detail.maker'), <><Identity v={a.vendor} /><DetectedNotice d={d} field="vendor" /></>)}
      {row(t('detail.model'), <><Identity v={a.model} /><DetectedNotice d={d} field="model" /></>)}
      {row(t('detail.os'), <><Identity v={a.os} /><DetectedNotice d={d} field="os" /></>)}
      {row(hostnameObs(d)?.source === 'manual' ? t('detail.hostnameManual') : t('detail.hostname'), <><HostName d={d} /><DetectedNotice d={d} field="hostname" /></>)}
      {row(t('detail.ip'), a.ip)}
      {row(t('detail.mac'), a.mac ?? <span className="text-muted">{t('common:unknown')}</span>)}
      {/* a hand-added device's first_seen is when a person added it, not a sighting; last_seen is one only once a report moved it */}
      {row(a.origin === 'manual' ? t('detail.addedByHand') : t('detail.firstSeen'), fmtDateTime(a.first_seen))}
      {row(t('detail.lastSeen'), neverSeen(a) ? <span className="text-muted">{t('detail.neverSeen')}</span> : `${fmtDateTime(a.last_seen)} (${fmtRelative(a.last_seen)})`)}
      {row(t('detail.origin'), a.is_box ? t('box.origin') : a.origin === 'manual' ? t('detail.originManual') : t('detail.originDiscovered'))}
    </dl>
  )
}

/** Maker, model or OS as Vedette uses it everywhere (title, list, Software, matching: one ranking), with where it came from and how
 *  sure: a network scan's OS fingerprint reads as a guess, an OS the device announces over LLDP says so. */
function Identity({ v }: { v: DeviceDetail['asset']['os'] }) {
  const { t } = useTranslation('inventory')
  if (!v) return <span className="text-muted">{t('detail.notKnown')}</span>
  return (
    <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1">
      <span className="[overflow-wrap:anywhere]">{v.value}</span>
      <SourceBadge source={v.source} confidence={v.confidence} basis={v.basis} />
    </span>
  )
}

/** The observation the host name in use comes from; its source names the row ("entered by hand" for a person's, else "seen on the network"). */
const hostnameObs = (d: DeviceDetail) => d.observations.find((o) => o.field === 'hostname' && o.current)

/** The host name the network reports (or typed when the device was added), with its source: read-only, apart from the name in
 *  Vedette that the title shows and Rename changes. */
function HostName({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const host = d.asset.hostname
  if (!host) return <span className="text-muted">{t('detail.hostnameNone')}</span>
  const obs = hostnameObs(d)
  return (
    <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1">
      <span className="[overflow-wrap:anywhere]" data-testid="device-hostname">{host}</span>
      {obs ? <SourceBadge source={obs.source} confidence={obs.confidence} /> : null}
    </span>
  )
}

/** Rename the device in Vedette where its name is, next to the page title. The name wins on every page (nameOf,
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
  const bad = badUserName(next) // the characters the backend refuses (#929)
  const [refused, setRefused] = useState('') // why the server refused the last save, next to the field (#929)
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
      <Button size="sm" variant="primary" disabled={bad} busy={act.patch.isPending} busyLabel={t('common:busy.saving')} onClick={save}>{t('detail.renameSave')}</Button>
      <Button size="sm" variant="ghost" disabled={act.patch.isPending} onClick={close}>{t('common:cancel')}</Button>
      {bad || refused ? <span id="device-name-error" role="alert" className="w-full text-caption text-danger">{bad ? t('detail.renameBad') : refused}</span> : null}
    </span>
  )
}

function Observations({ list }: { list: Observation[] }) {
  const { t } = useTranslation('inventory')
  const columns: ColumnDef<Observation>[] = [
    { id: 'field', header: t('obs.field'), accessorFn: (o) => t(`obs.fields.${o.field}`), cell: ({ getValue }) => <span className="whitespace-nowrap font-medium">{getValue() as string}</span> },
    { id: 'value', header: t('obs.value'), accessorFn: (o) => (o.field === 'kind' ? kindLabel(o.value) : o.value) },
    { id: 'source', header: t('obs.source'), accessorFn: (o) => o.confidence, cell: ({ row }) => <SourceBadge source={row.original.source} confidence={row.original.confidence} basis={row.original.basis} /> },
    { id: 'at', header: t('obs.at'), accessorFn: (o) => new Date(o.seen_at).getTime(), cell: ({ row }) => <time dateTime={row.original.seen_at} className="whitespace-nowrap text-meta text-muted">{fmtDateTime(row.original.seen_at)}</time> },
    { id: 'current', header: t('obs.state'), enableSorting: false, accessorFn: (o) => Number(o.current), cell: ({ row }) => (row.original.current ? <Chip tone="ok">{t('obs.current')}</Chip> : <span className="text-meta text-muted">{t(row.original.contradicts_type ? 'obs.notUsedType' : 'obs.kept')}</span>) },
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
            <SourceBadge source={o.source} confidence={o.confidence} basis={o.basis} />
            <time dateTime={o.seen_at}>{fmtDateTime(o.seen_at)}</time>
            {o.current ? null : <span>{t(o.contradicts_type ? 'obs.notUsedType' : 'obs.kept')}</span>}
          </div>
        </div>
      )} />
  )
}

/** Who lists a device's open ports, for the empty state: the box lists its own, an agent lists its machine's, the active
 *  sensor scans the rest. */
type PortsBy = 'box' | 'boxContainer' | 'agent' | 'fragile' | 'scan'

function Services({ list, by, asset }: { list: Service[]; by: PortsBy; asset: DeviceDetail['asset'] }) {
  const { t } = useTranslation('inventory')
  const scanning = useScanning().data
  // On the box its own ports (source agent, host INV-9b) are read by the box itself, as its software is: "This box", not "Agent".
  const source = (sv: Service) => (by === 'box' && sv.source === 'agent' ? <span className="text-caption text-muted">{t('box.source')}</span> : <SourceBadge source={sv.source} confidence={sv.confidence} />)
  if (!list.length) {
    const [body, info] = {
      box: [t('services.emptyBox'), t('services.emptyBoxInfo')],
      boxContainer: [t('services.emptyBoxContainer'), t('services.emptyBoxContainerInfo')],
      agent: [t('services.emptyAgent'), t('services.emptyAgentInfo')],
      fragile: [t('services.emptyFragile'), t('services.emptyFragileInfo')],
      // "Check this device now" is named only when this page shows it (the button's rule, scanning/canScan.ts); otherwise why not
      scan: [t('services.emptyBody'), ((r) => r === 'manual' ? t('scanning:selection.device.manualServices') : r ? t(`scanning:selection.device.${r}`) : t('services.emptyBodyInfo'))(scanRefusal(asset, scanning))],
    }[by]
    return <EmptyState title={t('services.empty')} info={info}>{body}</EmptyState>
  }
  const columns: ColumnDef<Service>[] = [
    { id: 'port', header: t('services.port'), accessorFn: (s) => s.port, cell: ({ row }) => <span className="whitespace-nowrap">{row.original.port}/{row.original.proto}</span> },
    { id: 'name', header: t('services.name'), accessorFn: (s) => s.name },
    { id: 'product', header: t('services.product'), accessorFn: (s) => s.product ?? '', cell: ({ getValue }) => (getValue() as string) || <span className="text-muted">–</span> },
    { id: 'version', header: t('services.version'), accessorFn: (s) => s.version ?? '', cell: ({ getValue }) => (getValue() as string) || <span className="text-muted">–</span> },
    { id: 'detail', header: t('services.detail'), accessorFn: (s) => s.detail ?? '', cell: ({ getValue }) => <span className="text-meta [overflow-wrap:anywhere]">{(getValue() as string) || <span className="text-muted">–</span>}</span> },
    { id: 'source', header: t('obs.source'), accessorFn: (s) => s.confidence, cell: ({ row }) => source(row.original) },
  ]
  return (
    <DataTable caption={t('services.caption')} data={list} columns={columns}
      mobileRow={(sv) => (
        <div className="grid gap-1">
          <span className="text-sm font-medium">{sv.port}/{sv.proto} {sv.name}</span>
          {sv.product || sv.version ? <span className="text-meta [overflow-wrap:anywhere]">{[sv.product, sv.version].filter(Boolean).join(' ')}</span> : null}
          {sv.detail ? <span className="text-meta text-muted [overflow-wrap:anywhere]">{sv.detail}</span> : null}
          <span className="text-caption text-muted">{source(sv)}</span>
        </div>
      )} />
  )
}

const VERSION_RE = /^[A-Za-z0-9_.\-+() ]{1,40}$/ // the backend's versionRE: what "edit version" accepts
const sameProduct = (a: SoftwareView, b: SoftwareView) => a.vendor.toLowerCase() === b.vendor.toLowerCase() && a.product.toLowerCase() === b.product.toLowerCase()

/** A version a person typed (or left empty) that an agent or scan sees differently on the same device. */
function seenVersion(sw: SoftwareView, list: SoftwareView[]) {
  if (sw.source !== 'manual') return null
  const typed = (sw.version ?? '').trim().toLowerCase()
  return list.find((o) => o.source !== 'manual' && o.version && sameProduct(o, sw) && o.version.trim().toLowerCase() !== typed) ?? null
}

function SoftwareList({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const act = useDeviceAction(d.asset.id)
  const [editing, setEditing] = useState<SoftwareView | null>(null)
  const [gone, setGone] = useState<SoftwareView | null>(null)
  // What each software row needs, from the same answer as Findings › To fix
  const needs = useSoftwareNeeds(d.asset.id)
  // INV-41 (6): a reported row a person said is not installed is shown once, as that "not installed" row (with Clear)
  const notInstalledIn = (sw: SoftwareView) => !!sw.correction?.not_installed
  const list = d.asset.software.filter((sw) => !(sw.corrected_by && d.asset.software.some((c) => c.id === sw.corrected_by && notInstalledIn(c) && c.correction?.active)))
  // The OS the device uses has a line of its own when no row shows it (an OS from the agent, SNMP or the device's LLDP statement);
  // a network scan's OS guess, or the OS row a person declared, is its own row, never also a line. The box's own OS is its package list.
  const os = d.asset.os
  const osBox = os && os.basis !== 'guess' && !os.software_id && !d.asset.is_box && !list.some((sw) => sw.display === os.value) ? (
    <div className="mb-3 grid gap-1 rounded-md border border-rule bg-surface px-4 py-3 text-sm" data-testid="software-os">
      <span className="font-medium">{t('software.os')}</span>
      <span className="flex flex-wrap items-center gap-x-2 gap-y-1"><span className="[overflow-wrap:anywhere]">{os.value}</span><SourceBadge source={os.source} confidence={os.confidence} basis={os.basis} /></span>
      <SoftwareNeeds assetId={d.asset.id} softwareId={`os:${d.asset.id}`} needs={needs} />
    </div>
  ) : null
  if (!list.length) return <>{osBox}<EmptyState title={t('software.empty')} info={t('software.emptyBodyInfo')}>{t('software.emptyBody')}</EmptyState></>
  const needCount = (sw: SoftwareView) => (needs instanceof Map ? (needs.get(sw.id)?.exploited.reduce((n, a) => n + a.cves.length, 0) ?? 0) : 0)
  const needRole = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const version = (sw: SoftwareView) => {
    const c = sw.correction
    if (c?.not_installed) {
      const date = fmtDate(c.set_at)
      const now = c.detected ? [c.detected.display, c.detected.version].filter(Boolean).join(' ') : ''
      return (
        <div className="grid gap-1">
          <span className="text-muted line-through">{sw.version || t('software.noVersion')}</span>
          {c.active ? <span className="text-caption font-medium">{t('software.notInstalled', { date })}</span>
            : <span className="text-caption text-warn">{c.detected ? t('software.notInstalledStale', { date, now, source: t(`common:source.${c.detected.source}`) }) : t('software.notInstalledGone', { date })}</span>}
        </div>
      )
    }
    const seen = seenVersion(sw, list)
    const v = seen?.version ?? ''
    return (
      <div className="grid gap-1">
        <span>{sw.version || <span className="text-muted">{t(sw.basis === 'guess' ? 'software.guessNoVersion' : 'software.noVersion')}</span>}</span>
        {seen ? (
          <span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-caption text-warn">
            {t('software.seen', { version: v, source: t(`common:source.${seen.source}`) })}
            {VERSION_RE.test(v) ? (
              <Button size="sm" variant="secondary" disabled={!can || act.setVersion.isPending} busy={act.setVersion.isPending && act.setVersion.variables?.sid === sw.id} busyLabel={t('common:busy.saving')} title={needRole} aria-label={t('software.acceptLabel', { version: v, name: sw.display })}
                onClick={() => act.setVersion.mutate({ sid: sw.id, version: v }, { onSuccess: () => toast.success(t('software.edited', { name: sw.display, version: v })), onError: (e) => toast.error(errMsg(e)) })}>
                {t('software.accept', { version: v })}
              </Button>
            ) : null}
          </span>
        ) : null}
      </div>
    )
  }
  const actions = (sw: SoftwareView) => (sw.correction?.not_installed ? (
    <Button size="sm" variant="secondary" disabled={!can || act.removeSoftware.isPending} busy={act.removeSoftware.isPending && act.removeSoftware.variables === sw.id} busyLabel={t('common:busy.saving')}
      title={needRole} aria-label={t('software.clearLabel', { name: sw.display })}
      onClick={() => act.removeSoftware.mutate(sw.id, { onSuccess: () => toast.success(t('software.cleared', { name: sw.display })), onError: (e) => toast.error(errMsg(e)) })}>{t('software.clear')}</Button>
  ) : sw.source !== 'manual' && !d.asset.is_box ? (
    <Button size="sm" variant="secondary" disabled={!can} title={needRole} aria-label={t('software.notInstalledActionLabel', { name: sw.display })} onClick={() => setGone(sw)}>{t('software.notInstalledAction')}</Button>
  ) : sw.source === 'manual' ? (
    <div className="flex">
      <Button size="sm" variant="ghost" disabled={!can} aria-label={t('software.edit', { name: sw.display })} title={needRole ?? t('software.edit', { name: sw.display })} onClick={() => setEditing(sw)}><Pencil /></Button>
      <Button size="sm" variant="ghost" disabled={!can || act.removeSoftware.isPending} busy={act.removeSoftware.isPending && act.removeSoftware.variables === sw.id} aria-label={t('software.remove', { name: sw.display })} title={t('software.remove', { name: sw.display })}
        onClick={() => act.removeSoftware.mutate(sw.id, { onSuccess: () => toast.success(t('software.removed', { name: sw.display })), onError: (e) => toast.error(errMsg(e)) })}><Trash2 /></Button>
    </div>
  ) : null)
  const columns: ColumnDef<SoftwareView>[] = [
    { id: 'name', header: t('software.name'), accessorFn: (s) => s.display, cell: ({ row }) => {
      const raw = rawProductLine(row.original.display, row.original.vendor, row.original.product)
      return <div className="grid"><span className="font-medium">{row.original.display}</span>{raw ? <span className="text-caption text-muted">{raw}</span> : null}</div>
    } },
    { id: 'version', header: t('software.version'), accessorFn: (s) => s.version ?? '', cell: ({ row }) => version(row.original) },
    { id: 'kev', header: t('findings:needs.column'), accessorFn: needCount, cell: ({ row }) => <SoftwareNeeds assetId={d.asset.id} softwareId={row.original.id} needs={needs} /> },
    { id: 'source', header: t('obs.source'), accessorFn: (s) => s.confidence, cell: ({ row }) => (d.asset.is_box ? <span className="text-caption text-muted">{t('box.source')}</span> : <SourceBadge source={row.original.source} confidence={row.original.confidence} basis={row.original.basis} />) },
    { id: 'actions', header: () => <span className="sr-only">{t('software.actions')}</span>, enableSorting: false, cell: ({ row }) => actions(row.original) },
  ]
  return (
    <>
      {osBox ?? <OsNeeds assetId={d.asset.id} needs={needs} />}
      <DataTable caption={t('software.caption')} data={list} columns={columns}
        mobileRow={(sw) => (
          <div className="flex items-start justify-between gap-3">
            <div className="grid min-w-0 gap-1">
              <span className="text-sm font-medium [overflow-wrap:anywhere]">{sw.display}</span>
              {rawProductLine(sw.display, sw.vendor, sw.product) ? <span className="text-caption text-muted">{rawProductLine(sw.display, sw.vendor, sw.product)}</span> : null}
              <div className="text-meta">{version(sw)}</div>
              <SoftwareNeeds assetId={d.asset.id} softwareId={sw.id} needs={needs} />
              <span className="text-caption text-muted">{d.asset.is_box ? t('box.source') : <SourceBadge source={sw.source} confidence={sw.confidence} basis={sw.basis} />}</span>
            </div>
            {actions(sw)}
          </div>
        )} />
      <VersionDialog key={editing?.id ?? ''} sw={editing} assetId={d.asset.id} onClose={() => setEditing(null)} />
      <NotInstalledDialog sw={gone} assetId={d.asset.id} device={nameOf(d.asset, kindLabel(d.asset.kind))} onClose={() => setGone(null)} />
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
      <div><Button disabled={!can || text === saved || act.patch.isPending} busy={act.patch.isPending && act.patch.variables?.notes !== undefined} busyLabel={t('common:busy.saving')} onClick={() => act.patch.mutate({ notes: text }, { onSuccess: () => toast.success(t('notes.saved')), onError: (e) => toast.error(errMsg(e)) })}>{t('notes.save')}</Button></div>
    </div>
  )
}

function Approval({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const can = useCan('operator')
  const act = useDeviceAction(d.asset.id)
  const navigate = useNavigate()
  const [del, setDel] = useState(false)
  const [ign, setIgn] = useState(false)
  const name = nameOf(d.asset, kindLabel(d.asset.kind))
  const fail = (e: unknown) => toast.error(errMsg(e))
  return (
    <Notice tone="warn" title={d.suspicious ? t('approval.suspicious') : t('approval.pending')} info={t('approval.bodyInfo')} actions={<>
        <Button variant="primary" disabled={!can} busy={act.approve.isPending} busyLabel={t('common:busy.approving')} onClick={() => act.approve.mutate(undefined, { onSuccess: () => toast.success(t('pending.approved', { name }), { description: t('pending.findLater') }), onError: fail })}>{t('pending.approve')}</Button>
        <Button disabled={!can} busy={act.suspicious.isPending} busyLabel={t('common:busy.saving')} onClick={() => act.suspicious.mutate(!d.suspicious, { onSuccess: () => toast.success(d.suspicious ? t('pending.unmarked', { name }) : t('pending.marked', { name })), onError: fail })}>{d.suspicious ? t('pending.unmark') : t('pending.mark')}</Button>
        <Button disabled={!can} busy={act.ignore.isPending} busyLabel={t('common:busy.saving')} onClick={() => setIgn(true)}>{t('pending.ignore')}</Button>
        <Button disabled={!can} onClick={() => setDel(true)}>{t('pending.delete')}</Button>
      </>}>
      {t('approval.body')}
      <IgnoreDialog open={ign} onOpenChange={setIgn} name={name} mac={d.asset.mac} findings={d.findings_count} pending={act.ignore.isPending}
        onConfirm={() => act.ignore.mutate(true, { onSuccess: () => { setIgn(false); toast.success(t('pending.ignored', { name }), { description: t('pending.ignoredLater') }) }, onError: fail })} />
      <DeleteDialog open={del} onOpenChange={setDel} name={name} findings={d.findings_count} pending={act.remove.isPending}
        onConfirm={() => act.remove.mutate(undefined, { onSuccess: () => { toast.success(t('delete.done', { name })); void navigate('/devices') }, onError: fail })} />
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
  const [ign, setIgn] = useState(false)
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
  // Khung trang: tiêu đề → thông báo (máy là hộp, chưa duyệt) → dải số → tab ở ?tab=. Các khối module khác cắm vào (slot device.panels) nằm ở tab Overview.
  return (
    <>
      <PageHeader breadcrumbs={crumbs} title={<span className="[overflow-wrap:anywhere]">{name}</span>} stories={['S-INV-1', 'S-INV-2', 'S-INV-3']}
        meta={renaming
          ? <span id="device-name-hint" className="max-w-xl">{t('detail.renameHint', { name: nameOf({ ...a, name: null }, kindLabel(a.kind)) })}</span>
          : <span className="inline-flex flex-wrap items-center gap-2">{a.is_box ? <Chip tone="accent">{t('box.badge')}</Chip> : null}<RiskMarker id={a.id} risk={d.risk} />{d.risk_unavailable ? <span>{t('risk.unavailableOne')}</span> : null}<span>{neverSeen(a) ? t('detail.metaLineNeverSeen', { kind: kindLabel(a.kind), when: fmtRelative(a.first_seen) }) : t('detail.metaLine', { kind: kindLabel(a.kind), when: fmtRelative(a.last_seen) })}</span><SampleDataNote /></span>}
        titleAction={<RenameDevice key="rename" d={d} editing={false} setEditing={setRenaming} button={renameButton} />}
        editing={renaming ? <RenameDevice key="edit" d={d} editing setEditing={setRenaming} button={renameButton} /> : undefined}
        actions={<>
          {/* #850: "Check this device now" plugs in here (slot device.actions, props { assetId, asset }: the facts that say whether
              it can be checked, from this page's own read, #877 r1 L6). */}
          <Slot name="device.actions" props={{ assetId: a.id, asset: a }} />
          {/* An approved device can be ignored here; a waiting one in its notice below, an ignored one is stopped there */}
          {a.approved && !a.ignored_at && !a.is_box ? <Button disabled={!can} busy={act.ignore.isPending} busyLabel={t('common:busy.saving')} title={needRole} onClick={() => setIgn(true)}><EyeOff />{t('pending.ignore')}</Button> : null}
          <Button disabled={!can || a.is_box} title={a.is_box ? t('box.noDelete') : needRole} onClick={() => setDel(true)}><Trash2 />{t('detail.delete')}</Button>
        </>} />
      {a.is_box ? <BoxNotice assetId={a.id} /> : null}
      {/* #829: before the approval, since merging a new row into the known device answers its approval too */}
      <PossibleSameNotice me={{ id: a.id, name, approved: a.approved, ignored: a.ignored_at != null }} list={d.possible_same ?? []} />
      {a.ignored_at ? <IgnoredNotice d={d} /> : !a.approved ? <Approval d={d} /> : null}
      {declaredSoftwareOnly(a) ? <Notice tone="accent" title={t('declared.title')}>{t('declared.body')}</Notice> : null}
      <DeviceKpis d={d} />
      <PageTabs label={t('detail.tabs.label')} tabs={[
        { id: 'overview', label: t('detail.tabs.overview'), panel: (
          <>
            <Section id="overview" title={t('detail.overview')}><Card><Overview d={d} /></Card></Section>
            {hasSourcesCard(a) ? <><DeviceSources d={d} /><DeviceSnmpCard d={d} /></> : null}
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
          <Section id="services" title={t('services.title')} description={t('services.description')} info={<><p>{t('services.descriptionInfo')}</p><p>{t('services.descriptionInfo2')}</p></>}><Services asset={a} list={a.services} by={a.is_box ? (/container-only/.test(a.model?.value ?? '') ? 'boxContainer' : 'box') : [...d.observations, ...a.software].some((x) => x.source === 'agent') ? 'agent' : a.fragile ? 'fragile' : 'scan'} /></Section>
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
      <IgnoreDialog open={ign} onOpenChange={setIgn} name={name} mac={a.mac} findings={d.findings_count} pending={act.ignore.isPending}
        onConfirm={() => act.ignore.mutate(true, { onSuccess: () => { setIgn(false); toast.success(t('pending.ignored', { name }), { description: t('pending.ignoredLater') }) }, onError: (e) => toast.error(errMsg(e)) })} />
    </>
  )
}

/** Ba con số trả lời "máy này có sao không": phát hiện (khi module findings bật), phần mềm, dịch vụ mở; mỗi số dẫn tới chỗ xem. */
function DeviceKpis({ d }: { d: DeviceDetail }) {
  const { t } = useTranslation('inventory')
  const findingsOn = useModuleEnabled('findings')
  const counts = useDeviceFindingCounts(d.asset.id) // The open findings the link opens, as the findings list counts them
  const id = encodeURIComponent(d.asset.id)
  return (
    <KpiStrip label={t('detail.kpi.label')} items={[
      ...(findingsOn ? [{ value: counts ? counts.open : '–', label: t('detail.kpi.findings'), to: `/findings?tab=open&device=${id}` }] : []),
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
