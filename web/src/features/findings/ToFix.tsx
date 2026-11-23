// S-MIT-1: "when the user opens Findings, they know which devices need patching or an action, and what the action is".
// To fix lists the devices, the most urgent first (GET /findings/to-fix orders them), each with its few actions as plain sentences;
// every action opens to its CVEs, and each CVE to its finding (CVSS, basis, status: one click deeper). By fix turns it around for an
// admin patching one app everywhere. As Defender's security recommendations ("Update Mozilla Firefox": exposed devices) and
// Tenable's remediation view group by the fix, never one row per CVE.
import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { X } from 'lucide-react'
import { CveList, SeverityBadge, type Band } from '@/components/common/status'
import { EmptyState, QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Segmented } from '@/components/ui/segmented'
import { useDevice, useDevices } from '@/features/inventory/api'
import { deviceName } from './basis'
import { kbNote, noCvesKey } from './fix'
import type { ToFix, ToFixAction, ToFixDevice } from './types'
import type { SoftwareLine } from '@/features/inventory/types'
import { isOsSoftware, IUpdated, TypedVersionDialog, type UpdatedSoftware } from './Updated'
import { RiskMarker } from '@/features/inventory/RiskMarker'
import { NotAdded, NotAddedChip, notAdded } from './NotAdded'
import { RowActions } from './Handle'

/** An action that updates the operating system itself (its new build shows only after a restart): Windows' cumulative update, or a
 *  row that is the OS or the kernel (its "vendor|product"). */
const osAction = (a: ToFixAction) => a.windows || a.kind === 'windows' || a.kind === 'esu' || a.kind === 'feature_update' || isOsSoftware(a.product.split('|')[0] ?? '', a.product.split('|')[1] ?? '')

const SEV: readonly Band[] = ['info', 'low', 'medium', 'high', 'critical']
const rank = (s: string) => SEV.indexOf(s.toLowerCase() as Band)

/** An exploited action without a named update and without proof is the person's to check (Needs your input), not to fix. */
export const proved = (a: ToFixAction) => a.confirmed + a.detected > 0
/** What To fix lists of a device: its updates for exploited findings, and the proved findings no update is named for. */
export const actionable = (d: ToFixDevice) => [...d.exploited, ...d.no_update.filter(proved)]
/** Findings no update is named for and the box could not prove: Needs your input. */
export const unproved = (d: ToFixDevice) => d.no_update.filter((a) => !proved(a))
/** A device To fix lists: something to fix, or a recommended update. */
export const listed = (d: ToFixDevice) => actionable(d).length + d.planned.length > 0

/** One severity: the worst of the action's CVEs, in words (never a second CVSS label next to it). */
export function Worst({ worst }: { worst: string }) {
  const band = SEV.find((b) => b === worst.toLowerCase())
  return band ? <SeverityBadge severity={band} /> : null
}

/** The box's own OS packages are installed from Settings › Updates: the action's button. */
function ActionButton({ a, box }: { a: ToFixAction; box: boolean }) {
  const { t } = useTranslation('findings')
  if (!box || a.kind !== 'distro') return null
  return <Link to="/settings/updates#os" className="w-fit text-meta font-medium text-accent underline underline-offset-4">{t('toFix.openOsUpdates')}</Link>
}

/** The typed version being entered on To fix: the tab holds its dialog (TypedVersionDialog), so the dialog, and what the re-match
 *  closed, stay when the update closes the row, or the whole device, that opened it. */
type Typed = { asset: ToFixDevice['asset']; software: UpdatedSoftware }
const TypedHost = createContext<((x: Typed) => void) | undefined>(undefined)

/** "I updated <software>" of a typed software under a To fix row: the tab's dialog when there is one, else its own. */
function TypedUpdated({ asset, software }: Typed) {
  const host = useContext(TypedHost)
  return <IUpdated asset={asset} software={software} size="sm" progress={false} onTyped={host ? () => host({ asset, software }) : undefined} />
}

/** One action: the sentence and what it fixes; it opens to its CVEs, each linking to its finding. */
function Action({ a, planned, box, asset, typed }: { a: ToFixAction; planned: boolean; box: boolean; asset: ToFixDevice['asset']; typed?: UpdatedSoftware }) {
  const { t } = useTranslation('findings')
  const what = planned
    ? t(a.distro_data === 'no_fix' ? 'toFix.plannedNoFix' : a.distro_data === 'none' ? 'toFix.plannedNoData' : a.nvd_lag ? 'toFix.plannedFixesAtLeast' : 'toFix.plannedFixes', { count: a.cves.length })
    : a.kind === 'none' ? t('toFix.noUpdateCount', { count: a.cves.length }) : t('toFix.fixes', { count: a.cves.length })
  if (planned && a.cves.length === 0) { // Microsoft's newest Windows update, none of its CVEs analysed by NVD yet: nothing to open
    return (
      <li className="grid gap-1 py-2">
        <p className="text-sm"><span className="font-medium">{a.action}</span><span className="text-muted">{': '}{t(noCvesKey(a.nvd_lag))}</span></p>
        {typed ? <TypedUpdated asset={asset} software={typed} /> : null}
      </li>
    )
  }
  return (
    <li className="grid gap-1 py-2">
      <details className="group">
        <summary className="cursor-pointer list-none text-sm marker:hidden [&::-webkit-details-marker]:hidden">
          <span className="font-medium">{a.action}</span>
          <span className="text-muted">{': '}{what}</span>
          {a.ransomware ? <span className="text-danger">{', '}{t('toFix.ransomware', { count: a.ransomware })}</span> : null}
          {/* review r1 of #943: an update named for versions only read from the network, or not compared, says so */}
          {!planned && a.reported + a.suspected > 0 ? <span className="text-warn">{', '}{t(proved(a) ? 'toFix.someUnverified' : 'toFix.unverified', { count: a.reported + a.suspected })}</span> : null}
          {planned && a.likely ? <span className="text-warn">{', '}{t('toFix.likely', { count: a.likely })}</span> : null}
          {planned && a.nvd_lag ? <span className="text-muted">{t('plan.nvdLag')}</span> : null}
          {' '}<Worst worst={a.worst} />
          <span className="ml-2 text-meta text-accent underline-offset-4 group-open:hidden">{t('toFix.showCves', { count: a.cves.length })}</span>
          <span className="ml-2 hidden text-meta text-accent underline-offset-4 group-open:inline">{t('toFix.hideCves')}</span>
        </summary>
        {/* a finding to fix: one line each, with Mark as handled right there; a planned CVE (no finding) only links to its page */}
        <CveList all rows={!planned} className="mt-1 pl-4" label={t('toFix.cvesOf', { action: a.action })}
          items={a.cves.map((cve, i) => ({ cve, id: a.finding_ids[i], to: a.finding_ids[i] ? `/findings/${encodeURIComponent(a.finding_ids[i]!)}` : undefined }))}
          action={planned ? undefined : (c) => (c.id ? <RowActions f={{ id: c.id, cve: c.cve, asset }} /> : null)} />
      </details>
      <ActionButton a={a} box={box} />
      {/* The same "I updated it" as the finding page: a typed version once per software, under its last row (typedSoftware); an
          agent or a check reads the whole device (DeviceUpdated, once per device) */}
      {typed ? <TypedUpdated asset={asset} software={typed} /> : null}
    </li>
  )
}

const updatedOf = (a: ToFixAction): UpdatedSoftware => ({ id: a.software_id, display: a.software, version: a.version || null, source: a.source as SoftwareLine['source'], kev_cves: a.cves })

/** The typed (hand-entered) software a device's rows name, once each by its software row: "I updated <software>" saves one version,
 *  however many rows name it (an exploited update and a recommended one of the same product), so it is one button, with the CVEs of
 *  all its rows. `last`: the row it shows under, the last of that software in the card's order (to fix, then recommended). */
export function typedSoftware(d: ToFixDevice): Map<string, { software: UpdatedSoftware; last: ToFixAction }> {
  const m = new Map<string, { software: UpdatedSoftware; last: ToFixAction }>()
  for (const a of [...actionable(d), ...d.planned]) {
    if (!a.software_id || a.source !== 'manual') continue
    const had = m.get(a.software_id)?.software
    m.set(a.software_id, { software: had ? { ...had, kev_cves: [...new Set([...had.kev_cves, ...a.cves])] } : updatedOf(a), last: a })
  }
  return m
}

/** "I updated it" for what reads the whole device (n83: once per device, not under every row): its agent ("ask the agent now", or how
 *  the new version arrives), and the network check for rows a scan read. An OS update among the agent's rows words it for the restart. */
function DeviceUpdated({ d, box }: { d: ToFixDevice; box: boolean }) {
  const rows = [...actionable(d), ...d.planned].filter((a) => a.software_id)
  const agent = rows.filter((a) => a.source === 'agent')
  const scan = rows.find((a) => a.source !== 'agent' && a.source !== 'manual')
  if (!agent.length && !scan) return null
  return (
    <div className="mt-1 grid gap-1">
      {agent.length ? <IUpdated asset={d.asset} software={updatedOf(agent[0]!)} size="sm" progress={false} os={agent.some(osAction)} box={box} /> : null}
      {scan ? <IUpdated asset={d.asset} software={updatedOf(scan)} size="sm" progress={false} /> : null}
    </div>
  )
}

/** One device: its name, how bad it is, and its actions (to fix first, then recommended). `typed`: the card shows "I updated
 *  <software>" for typed software itself (To fix); the device page shows it below the card, where it outlives a row the update closes. */
export function DeviceCard({ d, box, showName = true, typed = true }: { d: ToFixDevice; box: boolean; showName?: boolean; typed?: boolean }) {
  const { t } = useTranslation('findings')
  const acts = actionable(d)
  const once = typed ? typedSoftware(d) : undefined
  const typedOf = (a: ToFixAction) => { const x = once?.get(a.software_id); return x?.last === a ? x.software : undefined }
  const worst = acts.reduce((w, a) => (rank(a.worst) > rank(w) ? a.worst : w), '')
  const check = unproved(d).reduce((n, a) => n + a.cves.length, 0)
  const name = deviceName(d.asset, t('removedDevice'))
  return (
    <li className="rounded-md border border-rule bg-surface px-4 py-3" aria-label={name}>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        {showName ? <><Link to={`/devices/${encodeURIComponent(d.asset.id)}`} className="text-base font-semibold text-accent underline-offset-4 hover:underline">{name}</Link><NotAddedChip asset={d.asset} /><RiskMarker id={d.asset.id} risk={d.risk} /></> : null}
        {d.asset.ip && d.asset.ip !== '—' ? <span className="text-meta text-muted">{d.asset.ip}</span> : null}
        {acts.length ? <><Worst worst={worst} /><span className="text-meta text-muted">{t('toFix.deviceCount', { count: acts.reduce((n, a) => n + a.cves.length, 0) })}</span></> : null}
      </div>
      {/* a device nobody approved yet: Add device or Ignore right here (the device page has its own) */}
      {showName && notAdded(d.asset) ? <div className="mt-1"><NotAdded asset={d.asset} findings={acts.reduce((n, a) => n + a.cves.length, 0) + check} /></div> : null}
      {acts.length ? <ul aria-label={t('toFix.actionsOf', { device: name })} className="divide-y divide-rule">{acts.map((a) => <Action key={`${a.kind}:${a.group}`} a={a} planned={false} box={box} asset={d.asset} typed={typedOf(a)} />)}</ul> : null}
      {d.planned.length ? (
        <>
          <p className="mt-2 text-meta font-medium text-muted">{t('toFix.recommended')}</p>
          <ul aria-label={t('toFix.recommendedOf', { device: name })} className="divide-y divide-rule">{d.planned.map((a) => <Action key={`plan:${a.group}`} a={a} planned box={box} asset={d.asset} typed={typedOf(a)} />)}</ul>
        </>
      ) : null}
      <DeviceUpdated d={d} box={box} />
      {check ? <Link to={`/findings?tab=input&device=${encodeURIComponent(d.asset.id)}`} className="mt-1 inline-block text-meta text-accent underline underline-offset-4">{t('toFix.toCheck', { count: check })}</Link> : null}
    </li>
  )
}

type FixRow = { key: string; sample: ToFixAction; planned: boolean; devices: { d: ToFixDevice; a: ToFixAction }[] }

/** By fix: one row per update (the product's identity, the kind and the release), with the devices that need it; the worst first. */
function ByFix({ devices }: { devices: ToFixDevice[] }) {
  const { t } = useTranslation('findings')
  const rows = useMemo(() => {
    const m = new Map<string, FixRow>()
    for (const d of devices) {
      for (const [a, planned] of [...actionable(d).map((x) => [x, false] as const), ...d.planned.map((x) => [x, true] as const)]) {
        // review r1 of #943: the product's identity (vendor|product), not the name each device gives it; a distro's own updates apart
        const key = [a.kind, a.product || a.software.toLowerCase(), a.distro, a.fixed, planned].join('|')
        const r = m.get(key) ?? { key, sample: a, planned, devices: [] }
        // review r2 of #943: two rows of the same product on one device (7-Zip and 7-Zip (x64)) are one device, their CVEs together
        const same = r.devices.find((x) => x.d.asset.id === d.asset.id)
        if (same) same.a = { ...same.a, cves: [...same.a.cves, ...a.cves], worst: rank(a.worst) > rank(same.a.worst) ? a.worst : same.a.worst }
        else r.devices.push({ d, a })
        m.set(key, r)
      }
    }
    const worst = (r: FixRow) => Math.max(...r.devices.map((x) => rank(x.a.worst)))
    return [...m.values()].sort((x, y) => Number(x.planned) - Number(y.planned) || worst(y) - worst(x) || y.devices.length - x.devices.length || x.sample.software.localeCompare(y.sample.software))
  }, [devices])
  const label = (a: ToFixAction) => {
    const v = { software: a.software || t('toFix.theSoftware'), fixed: a.windows ? a.fixed.replace(/^10\.0\./, '') : a.fixed, kb: kbNote(a.kb) }
    // review r1 of #943: a Windows row's feature update and ESU before the monthly cumulative update
    switch (a.kind) {
      case 'none': return t('toFix.byFix.none', v)
      case 'feature_update': return t('toFix.byFix.featureUpdate', v)
      case 'esu': return t('toFix.byFix.esu', v)
      case 'distro': return a.fixed ? t('toFix.byFix.distroFixed', v) : t('toFix.byFix.distro', v)
      case 'windows': return t('toFix.byFix.windows', v)
    }
    return a.windows ? t('toFix.byFix.windows', v) : t('toFix.byFix.fixed', v)
  }
  return (
    <ul aria-label={t('toFix.byFix.label')} className="grid gap-2">
      {rows.map((r) => {
        const cves = r.devices.reduce((n, x) => n + x.a.cves.length, 0)
        const worst = r.devices.reduce((w, x) => (rank(x.a.worst) > rank(w) ? x.a.worst : w), '')
        const lag = r.planned && r.devices.some((x) => x.a.nvd_lag) // Microsoft's newest update: the CVEs NVD has analysed so far
        // no CVE analysed yet on any device: the update is named, its count is not known
        const on = r.planned && cves === 0 ? `${t('toFix.byFix.devices', { count: r.devices.length })}; ${t(noCvesKey(r.devices.some((x) => x.a.nvd_lag)))}`
          : `${t('toFix.byFix.devices', { count: r.devices.length })}, ${t(lag ? 'toFix.byFix.cvesPlannedAtLeast' : r.planned ? 'toFix.byFix.cvesPlanned' : 'toFix.byFix.cves', { count: cves })}`
        return (
          <li key={r.key} className="rounded-md border border-rule bg-surface px-4 py-3">
            <details>
              <summary className="cursor-pointer text-sm">
                <span className="font-medium">{label(r.sample)}</span>
                <span className="text-muted">{': '}{r.planned ? t('toFix.byFix.recommendedOn', { on }) : on}{lag && cves > 0 ? t('plan.nvdLag') : null}</span>
                {' '}<Worst worst={worst} />
              </summary>
              <ul className="mt-1 grid gap-1 pl-4 text-meta">
                {r.devices.map(({ d, a }) => (
                  <li key={d.asset.id}>
                    <Link to={`/devices/${encodeURIComponent(d.asset.id)}`} className="font-medium text-accent underline-offset-4 hover:underline">{deviceName(d.asset, t('removedDevice'))}</Link>
                    {' '}<NotAddedChip asset={d.asset} />{' '}<RiskMarker id={d.asset.id} risk={d.risk} className="align-middle" />
                    <span className="text-muted">{': '}{a.action}, {a.cves.length === 0 ? t(noCvesKey(a.nvd_lag)) : <>{t(a.nvd_lag ? 'toFix.cveCountAtLeast' : 'toFix.cveCount', { count: a.cves.length })}{a.nvd_lag ? t('plan.nvdLag') : null}</>}</span>
                    {/* as the By device cards: a device nobody approved yet offers Add device and Ignore on its line */}
                    {notAdded(d.asset) ? <div className="mt-1"><NotAdded asset={d.asset} findings={a.cves.length} /></div> : null}
                  </li>
                ))}
              </ul>
            </details>
          </li>
        )
      })}
    </ul>
  )
}

/** A device's name, read only for a `?device=` To fix does not list (review r2 of #943): the chip and the empty state name it. */
function WithDeviceName({ id, children }: { id: string; children: (name: string | undefined) => ReactNode }) {
  const a = useDevice(id).data?.asset
  return <>{children(a ? (a.name || a.hostname || (a.ip && a.ip !== '—' ? a.ip : undefined)) ?? undefined : undefined)}</>
}

/** The box's device id, read only when an action may need it (a distribution's update): its OS updates have their own page. */
export function WithBox({ children }: { children: (boxId: string | undefined) => ReactNode }) {
  const boxId = useDevices().data?.items.find((x) => x.is_box)?.id
  return <>{children(boxId)}</>
}

/** The To fix tab: by device (default) or by fix (`?by=fix`, shareable); `?device=` keeps one device, shown as a chip to clear. */
export function ToFixTab({ q }: { q: { data: ToFix | undefined; error: unknown; isPending: boolean; refetch: () => unknown } }) {
  const [params] = useSearchParams()
  const device = params.get('device') ?? ''
  // review r2 of #943: a device with nothing in to-fix is still named (its device read, only then)
  const inList = !device || !q.data || q.data.devices.some((x) => x.asset.id === device)
  // The typed version's dialog lives here, beside the list: the update it saves closes rows and devices of the list
  const [typed, setTyped] = useState<(Typed & { open: boolean }) | null>(null)
  const openTyped = useCallback((x: Typed) => setTyped({ ...x, open: true }), [])
  return (
    <TypedHost.Provider value={openTyped}>
      {!inList ? <WithDeviceName id={device}>{(name) => <ToFixBody q={q} otherName={name} />}</WithDeviceName> : <ToFixBody q={q} otherName={undefined} />}
      {typed ? <TypedVersionDialog key={`${typed.asset.id}/${typed.software.id}`} asset={typed.asset} software={typed.software} open={typed.open}
        onOpenChange={(open) => setTyped((x) => x && { ...x, open })} /> : null}
    </TypedHost.Provider>
  )
}

function ToFixBody({ q, otherName }: { q: { data: ToFix | undefined; error: unknown; isPending: boolean; refetch: () => unknown }; otherName: string | undefined }) {
  const { t } = useTranslation('findings')
  const [params, setParams] = useSearchParams()
  const by = params.get('by') === 'fix' ? 'fix' : 'device'
  const device = params.get('device') ?? ''
  const hasDistro = !!q.data?.devices.some((d) => actionable(d).some((a) => a.kind === 'distro'))
  const set = (k: string, v: string) => { const p = new URLSearchParams(params); if (v) p.set(k, v); else p.delete(k); setParams(p, { replace: true }) }
  return (
    <QueryState query={q}>
      {(d) => {
        const devices = d.devices.filter(listed).filter((x) => !device || x.asset.id === device)
        const named = device ? d.devices.find((x) => x.asset.id === device) : undefined
        const deviceLabel = named ? deviceName(named.asset, t('removedDevice')) : otherName ?? t('toFix.thisDevice')
        const planNote = d.plan_off ? t('toFix.planOff') : !d.plan_ran ? t('toFix.planNotRun') : ''
        return (
          <div className="grid gap-3">
            <div className="flex flex-wrap items-center gap-3">
              <Segmented<'device' | 'fix'> label={t('toFix.view')} value={by} onChange={(v) => set('by', v === 'fix' ? 'fix' : '')} options={[{ value: 'device', label: t('toFix.byDevice') }, { value: 'fix', label: t('toFix.byFixLabel') }]} />
              {/* review r1 of #943: a device filter is visible and clears in one click */}
              {device ? <Button size="sm" onClick={() => set('device', '')}><X />{t('toFix.clearDevice', { device: deviceLabel })}</Button> : null}
              {d.truncated ? <span className="text-meta text-muted">{t('toFix.truncated')}</span> : null}
            </div>
            {planNote ? <p className="text-meta text-muted">{planNote}</p> : null}
            {devices.length === 0 ? (
              <EmptyState art="no-findings" title={device ? t('toFix.emptyDevice', { device: deviceLabel }) : t('toFix.empty')}>
                {device && named && unproved(named).length
                  ? <Link to={`/findings?tab=input&device=${encodeURIComponent(device)}`} className="text-accent underline underline-offset-4">{t('toFix.emptyDeviceCheck')}</Link>
                  : d.plan_off || !d.plan_ran ? t('toFix.emptyBodyNoPlan') : t('toFix.emptyBody')}
              </EmptyState>
            ) : by === 'fix' ? <ByFix devices={devices} /> : (() => {
              const list = (boxId: string | undefined) => <ul aria-label={t('toFix.label')} className="grid gap-3">{devices.map((x) => <DeviceCard key={x.asset.id} d={x} box={x.asset.id === boxId} />)}</ul>
              return hasDistro ? <WithBox>{list}</WithBox> : list(undefined)
            })()}
          </div>
        )
      }}
    </QueryState>
  )
}
