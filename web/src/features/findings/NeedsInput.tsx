// kien G15 (J3, S-MIT-1): Needs your input, one block per device, the most urgent first (To fix's own order), collapsed until opened.
// Each item says in plain words what the person can do and offers it right there (docs/UI.md §0, "do it where you are"): type the
// version of software they added by hand, remove what is not installed, mark unproved findings not affected, check the device now
// (the same "Check this device now" as the device page), or open the software on the device. When nothing a person does would help,
// it says so and when Vedette checks again (the next version scan or SNMP read from GET /scanning, the next NVD refresh from the
// feed's last fetch and interval). As Defender's "Software inventory" and Tenable's asset view group a device's open questions under
// the device, never one flat list per kind. D-604 (BN340, kien G16): a CVE only the platform or the package release can settle asks its
// question here, with every answer the box offers (one click for an OS, fields for what the person types), each an inventory correction.
import { useEffect, useId, useState, type FormEvent, type ReactNode } from 'react'
import { Link, useLocation } from 'react-router'
import { Trans, useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ChevronDown } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input, Label } from '@/components/ui/input'
import { useFeedSources } from '@/features/feeds/api'
import { RiskMarker } from '@/features/inventory/RiskMarker'
import { useDeviceAction } from '@/features/inventory/api'
import type { DeviceRisk } from '@/features/inventory/types'
import { useScanning } from '@/features/scanning/api'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useBulkStatus } from './api'
import { deviceName, hasIp } from './basis'
import { MAX_BULK } from './contract'
import { errMsg } from './errors'
import { notInstalledText, useNotInstalled } from './notInstalled'
import { useDeviceSoftware } from './rematch'
import { Worst, unproved } from './ToFix'
import { nameWithVersion, UNCHECKED_ANCHOR, UncheckedLine } from './UncheckedList'
import { CheckNow } from './Updated'
import type { FindingAsset, ToFixAction, ToFixDevice, UncheckedItem, VersionNeeded } from './types'
import type { z } from 'zod'
import type { UncheckedAnswer } from './contract'

type Answer = z.infer<typeof UncheckedAnswer>

const SEV = ['info', 'low', 'medium', 'high', 'critical']
const rank = (s: string) => SEV.indexOf(s.toLowerCase())
/** The backend's versionRE (inventory manual.go): what PATCH …/software/{sid} accepts. */
const VERSION_RE = /^[A-Za-z0-9_.\-+() ]{1,40}$/

/** One device's block: what only a person can settle (a version, an unproved match), then what could not be checked. */
export type InputGroup = { id: string; asset: FindingAsset | null; versions: VersionNeeded[]; unproved: ToFixAction[]; unchecked: UncheckedItem[] }

const uncheckedCves = (items: UncheckedItem[]) => new Set(items.flatMap((i) => i.cves.map((c) => c.cve))).size

/** Groups the items by device. Order: To fix's own urgency (`order`, the devices of GET /findings/to-fix as the server ranks them),
 *  then a device with something to settle, its worst unproved severity, how many things to settle, how many CVEs could not be
 *  checked, and its name. */
export function groupByDevice(need: VersionNeeded[], unc: UncheckedItem[], devices: ToFixDevice[], order: string[], removed: string): InputGroup[] {
  const m = new Map<string, InputGroup>()
  const at = (id: string, asset: FindingAsset | null) => {
    const g = m.get(id) ?? { id, asset, versions: [], unproved: [], unchecked: [] }
    g.asset ??= asset
    m.set(id, g)
    return g
  }
  for (const v of need) at(v.asset_id, v.asset).versions.push(v)
  for (const d of devices) for (const a of unproved(d)) at(d.asset.id, d.asset).unproved.push(a)
  for (const u of unc) at(u.asset_id, u.asset).unchecked.push(u)
  const pos = new Map(order.map((id, i) => [id, i]))
  const settle = (g: InputGroup) => g.versions.length + g.unproved.length
  const worst = (g: InputGroup) => Math.max(-1, ...g.unproved.map((a) => rank(a.worst)))
  const name = (g: InputGroup) => deviceName(g.asset, removed)
  return [...m.values()].sort((x, y) => (pos.get(x.id) ?? Infinity) - (pos.get(y.id) ?? Infinity) || Number(settle(y) > 0) - Number(settle(x) > 0)
    || worst(y) - worst(x) || settle(y) - settle(x) || uncheckedCves(y.unchecked) - uncheckedCves(x.unchecked) || name(x).localeCompare(name(y)))
}

/** Needs your input: the device blocks. `device` (the `?device=` filter, a link from To fix or the Software tab) opens its block. */
export function NeedsInput({ need, unc, devices, order, risks, device }: { need: VersionNeeded[]; unc: UncheckedItem[]; devices: ToFixDevice[]; order: string[]; risks: Record<string, DeviceRisk | null>; device: string }) {
  const { t } = useTranslation('findings')
  const { hash } = useLocation()
  const groups = groupByDevice(need, unc, devices, order, t('removedDevice'))
  const [open, setOpen] = useState<ReadonlySet<string>>(() => new Set(device ? [device] : []))
  const toggle = (id: string) => setOpen((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n })
  useEffect(() => {
    if (hash === `#${UNCHECKED_ANCHOR}`) document.getElementById(UNCHECKED_ANCHOR)?.scrollIntoView?.({ block: 'start' })
  }, [hash])
  if (!groups.length) return null
  return (
    <section id={UNCHECKED_ANCHOR} aria-labelledby="needs-input-title" className="grid scroll-mt-4 gap-2">
      <h2 id="needs-input-title" className="text-base font-semibold">{t('needsInput.title', { count: groups.length })}</h2>
      <p className="text-meta text-muted">{t('needsInput.intro')}</p>
      <ul aria-label={t('needsInput.label')} className="grid gap-2">
        {groups.map((g) => <DeviceBlock key={g.id} g={g} open={open.has(g.id)} onToggle={() => toggle(g.id)} risk={risks[g.id] ?? null} />)}
      </ul>
    </section>
  )
}

function DeviceBlock({ g, open, onToggle, risk }: { g: InputGroup; open: boolean; onToggle: () => void; risk: DeviceRisk | null }) {
  const { t } = useTranslation('findings')
  const name = deviceName(g.asset, t('removedDevice'))
  const settle = g.versions.length + g.unproved.length
  const cves = uncheckedCves(g.unchecked)
  const panel = `needs-input-${g.id}`
  // the block's counts, in its toggle's name; each only when it is not 0 (kien G5)
  const settleText = settle ? t('needsInput.toSettle', { count: settle }) : ''
  const cvesText = cves ? t('needsInput.uncheckedCount', { count: cves }) : ''
  return (
    <li aria-label={name} className="rounded-md border border-rule bg-surface">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 px-2 py-2">
        <Button variant="ghost" size="sm" aria-expanded={open} aria-controls={panel} onClick={onToggle} className="h-auto min-h-9 flex-wrap justify-start gap-x-2 gap-y-0.5 whitespace-normal py-1.5 text-left">
          <ChevronDown className={open ? 'rotate-180' : ''} aria-hidden />
          <span className="text-sm font-semibold [overflow-wrap:anywhere]">{name}</span>
          {settleText ? <span className="whitespace-nowrap font-normal text-warn"><span className="sr-only">,</span> {settleText}</span> : null}
          {cvesText ? <span className="whitespace-nowrap font-normal text-muted"><span className="sr-only">,</span> {cvesText}</span> : null}
        </Button>
        {g.asset ? <RiskMarker id={g.id} risk={risk} /> : null}
        {hasIp(g.asset) ? <span className="text-meta text-muted">{g.asset?.ip}</span> : null}
      </div>
      {open ? (
        <div id={panel} className="grid gap-3 border-t border-rule px-4 py-3">
          {settle ? (
            <ul aria-label={t('needsInput.settleOf', { device: name })} className="divide-y divide-rule">
              {g.versions.map((v) => <VersionItem key={`v:${v.software_id}`} v={v} />)}
              {g.unproved.map((a) => <UnprovedItem key={`u:${a.group}`} a={a} asset={g.asset} />)}
            </ul>
          ) : null}
          {cves ? (
            <div className="grid gap-1">
              <h3 className="text-sm font-semibold">{t('needsInput.uncheckedTitle', { count: cves })}</h3>
              <p className="text-meta text-muted">{t('unchecked.help')}</p>
              <ul aria-label={t('needsInput.uncheckedOf', { device: name })} className="divide-y divide-rule">
                {g.unchecked.map((u) => (
                  <li key={`${u.software_id ?? u.software}/${u.reason}`} className="grid gap-2 py-3">
                    <UncheckedLine item={u} />
                    {u.action === 'answer_platform' && u.question ? <><PlatformQuestion u={u} question={u.question} /><PlatformNotInstalled u={u} /></> : (
                      <NextStep assetId={u.asset_id} asset={u.asset} softwareId={u.software_id ?? ''} software={u.software} need={u.action === 'add_version' ? 'version' : 'nvd'}
                        waiting={u.cves.some((c) => c.nvd_pending)} />
                    )}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}
    </li>
  )
}

/** D-500: a software without a usable version: the version decides its exploited CVEs. */
function VersionItem({ v }: { v: VersionNeeded }) {
  const { t } = useTranslation('findings')
  return (
    <li className="grid gap-2 py-3">
      <p className="text-sm">
        <Trans t={t} i18nKey={v.version === null ? 'versionNeeded.missing' : 'versionNeeded.unreadable'} count={v.cves}
          values={{ software: v.software, version: v.version ?? '' }} components={{ sw: <span className="font-medium" /> }} />
      </p>
      <NextStep assetId={v.asset_id} asset={v.asset} softwareId={v.software_id} software={v.software} need="version" />
    </li>
  )
}

/** Findings no update is named for that the box could not prove (kien G8): their CVEs, and how a person settles them. */
function UnprovedItem({ a, asset }: { a: ToFixAction; asset: FindingAsset | null }) {
  const { t } = useTranslation('findings')
  return (
    <li className="grid gap-2 py-3">
      <div className="text-sm">
        <p>
          <span className="font-medium">{nameWithVersion(a.software || t('toFix.theSoftware'), a.version)}</span>
          <span className="text-muted">{', '}{t('toFix.unproved.count', { count: a.cves.length })}</span>{' '}<Worst worst={a.worst} />
        </p>
        <details>
          <summary className="w-fit cursor-pointer text-meta text-accent underline-offset-4 hover:underline">{t('toFix.showCves', { count: a.cves.length })}</summary>
          <ul className="mt-1 flex flex-wrap gap-x-3 gap-y-1 pl-4 text-meta">
            {a.cves.map((c, i) => <li key={c}><Link to={`/findings/${encodeURIComponent(a.finding_ids[i] ?? '')}`} className="text-accent underline-offset-4 hover:underline">{c}</Link></li>)}
          </ul>
        </details>
      </div>
      <NextStep assetId={asset?.id ?? ''} asset={asset} softwareId={a.software_id} software={a.software || t('toFix.theSoftware')} need="proof" sourceHint={a.source} findingIds={a.finding_ids} />
    </li>
  )
}

/** What decides an item: its version (version), NVD's data only (nvd), or a person's check of unproved findings (proof). */
type Need = 'version' | 'nvd' | 'proof'
const SCAN_READ = new Set(['nmap', 'scan', 'passive'])

/**
 * The item's next step, from who reported its software row (the device's own read): a row a person added is theirs to type or
 * remove; on a row a scan, SNMP or an agent reads, the version typed here is a person's correction (INV-41, PATCH on that row) that
 * matching uses until it is cleared on the device page, or the next read changes it. Every branch names something to do here, or says
 * that nothing a person does helps and when Vedette checks again. Never a control that can only be refused.
 */
function NextStep({ assetId, asset, softwareId, software, need, sourceHint = '', findingIds = [], waiting = false }: {
  assetId: string; asset: FindingAsset | null; softwareId: string; software: string; need: Need; sourceHint?: string; findingIds?: string[]; waiting?: boolean
}) {
  const { t } = useTranslation('findings')
  const q = useDeviceSoftware(assetId || undefined)
  if (assetId && q.isPending) return <p className="text-meta text-muted">{t('needsInput.reading')}</p>
  const d = q.data?.asset
  const row = d?.software.find((s) => s.id === softwareId)
  // a person's correction of a reported row (INV-41) is still that row: its source is the one that reads it, and Not installed marks it
  const source = row?.correction ? (row.correction.detected?.source ?? sourceHint) : row?.source ?? sourceHint
  const device = deviceName(asset, t('removedDevice'))
  // a product added by hand as its own device ("Microsoft SQL Server (no device)"): not installed removes the device
  const wholeDevice = !!d && d.origin === 'manual' && d.software.length === 1 && row?.source === 'manual'
  const open = asset && softwareId ? <Link to={`/devices/${encodeURIComponent(asset.id)}?tab=software`} className="text-meta text-accent underline underline-offset-4">{t('needsInput.openRow', { software, device })}</Link> : null
  const notAffected = need === 'proof' ? <NotAffected ids={findingIds} /> : null

  // INV-41 (6): on a row a scan, SNMP or an agent reads, Not installed is the person's word, kept while the source reads that row. Never
  // on the box: it reads its own package list.
  const notInstalled = row && asset && !d?.is_box ? <NotInstalled assetId={assetId} software={row.display} softwareId={row.id} cves={row.kev_cves} device={device} wholeDevice={false} reported /> : null

  if (row?.source === 'manual' && !row.correction) {
    return (
      <Step text={need === 'nvd' ? <>{t('needsInput.next.manualNvd')} <NvdWhen waiting={waiting} /></> : t('needsInput.next.manual')}>
        {need !== 'nvd' ? <VersionForm assetId={assetId} sw={row} /> : null}
        <div className="flex flex-wrap items-center gap-2">
          <NotInstalled assetId={assetId} software={row.display} softwareId={row.id} device={device} wholeDevice={wholeDevice} />
          {notAffected}
        </div>
      </Step>
    )
  }
  if (need === 'nvd') {
    // not_named, no NVD data or versions, or a version the box read that NVD's ranges cannot order: only NVD's data decides
    return <Step text={<>{t('needsInput.next.nothing')} <NvdWhen waiting={waiting} /></>}>{notInstalled}{open}</Step>
  }
  const proof = need === 'proof' ? ` ${t('needsInput.next.proof')}` : ''
  if (SCAN_READ.has(source) || source === 'snmp') {
    return (
      <Step text={<>{t(`needsInput.next.${source === 'snmp' ? 'snmp' : source === 'passive' ? 'passive' : 'scan'}`)}{row ? ` ${t('needsInput.next.correct')}` : ''} <ScanWhen engine={source === 'snmp' ? 'snmp' : 'nmap-versions'} />{proof}</>}>
        {row ? <VersionForm assetId={assetId} sw={row} /> : null}
        <div className="flex flex-wrap items-start gap-x-3 gap-y-2">
          {asset ? <CheckNow asset={asset} size="sm" progress={false} /> : null}
          {notInstalled}
          {notAffected}
        </div>
        {open}
      </Step>
    )
  }
  return (
    <Step text={`${t(source === 'agent' ? 'needsInput.next.agent' : 'needsInput.next.device')}${row ? ` ${t('needsInput.next.correct')}` : ''}${proof}`}>
      {row ? <VersionForm assetId={assetId} sw={row} /> : null}
      {notInstalled || notAffected ? <div className="flex flex-wrap items-center gap-2">{notInstalled}{notAffected}</div> : null}
      {open}
    </Step>
  )
}

function Step({ text, children }: { text: ReactNode; children?: ReactNode }) {
  return (
    <div className="grid gap-2 pl-4">
      <p className="text-meta">{text}</p>
      {children}
    </div>
  )
}

/** When the version scan (Service versions) or the SNMP round reads the device again, from GET /scanning. */
function ScanWhen({ engine }: { engine: 'nmap-versions' | 'snmp' }) {
  const { t } = useTranslation('findings')
  const e = useScanning().data?.engines.find((x) => x.id === engine)
  const k = engine === 'snmp' ? 'snmp' : 'scan'
  if (e && !e.enabled) {
    return <>{t(`needsInput.when.${k}Off`)} <Link to={`/settings/scanning?tab=engines#engine-${engine}`} className="text-accent underline underline-offset-4">{t('needsInput.when.scanOffLink')}</Link></>
  }
  if (e?.next_run_at && Date.parse(e.next_run_at) > Date.now()) return <>{t(`needsInput.when.${k}At`, { when: fmtDateTime(e.next_run_at) })}</>
  return <>{t(`needsInput.when.${k}Next`)}</>
}

/** When Vedette reads NVD's affected versions again (the nvd-kev feed: its last fetch plus its interval), or that the feed is off. */
function NvdWhen({ waiting }: { waiting: boolean }) {
  const { t } = useTranslation('findings')
  const f = useFeedSources().data?.items.find((x) => x.id === 'nvd-kev')
  const pre = waiting ? `${t('needsInput.when.nvdWaiting')} ` : ''
  if (f && !f.enabled) return <>{pre}{t('needsInput.when.nvdOff')} <Link to="/settings/feeds" className="text-accent underline underline-offset-4">{t('needsInput.when.nvdOffLink')}</Link></>
  const next = f?.last_fetch ? Date.parse(f.last_fetch) + f.interval_hours * 3_600_000 : NaN
  if (Number.isFinite(next) && next > Date.now()) return <>{pre}{t('needsInput.when.nvdAt', { when: fmtDateTime(new Date(next).toISOString()) })}</>
  return <>{pre}{t('needsInput.when.nvdNext')}</>
}

/** The version typed here (PATCH …/software/{sid}): in place on a row a person added, a correction of a row a sensor or agent reported
 *  (INV-41); the device is matched again at once, so the item leaves the list or changes (useDeviceAction refreshes findings, inventory
 *  and feeds). */
function VersionForm({ assetId, sw }: { assetId: string; sw: { id: string; display: string; version: string | null } }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const act = useDeviceAction(assetId)
  const id = useId()
  const [value, setValue] = useState('')
  const [error, setError] = useState<string | undefined>()
  function save(e: FormEvent) {
    e.preventDefault()
    const v = value.trim()
    if (!v) { setError(t('updated.required')); return }
    if (!VERSION_RE.test(v)) { setError(t('updated.bad_version', { version: v })); return }
    setError(undefined)
    // mutateAsync: the item leaves the list when the re-match lands, which unmounts this form before mutate's own callbacks would run
    act.setVersion.mutateAsync({ sid: sw.id, version: v })
      .then(() => toast.success(t('needsInput.saved', { software: sw.display, version: v })), (er: unknown) => setError(errMsg(er)))
  }
  return (
    <form onSubmit={save} noValidate className="flex flex-wrap items-end gap-2">
      <div className="grid gap-1">
        <Label htmlFor={id} className="text-meta">{t('needsInput.versionLabel', { software: sw.display })}</Label>
        <Input id={id} value={value} maxLength={40} className="h-9 w-48" placeholder={t('needsInput.versionPlaceholder')} disabled={!can}
          aria-invalid={!!error} aria-describedby={error ? `${id}-error` : undefined} onChange={(e) => { setValue(e.target.value); setError(undefined) }} />
      </div>
      <Button type="submit" size="sm" variant="primary" disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}
        busy={act.setVersion.isPending} busyLabel={t('common:busy.saving')}>{t('needsInput.saveVersion')}</Button>
      {error ? <p id={`${id}-error`} role="alert" className="basis-full text-meta text-danger">{error}</p> : null}
    </form>
  )
}

/** Not installed, after one confirmation here: software a person added (or the device added only for it) is removed; on a row a scan,
 *  SNMP or an agent reads (`reported`), deleting would last only until the next read, so it is the person's word kept as an inventory
 *  correction (INV-41 (6), PATCH not_installed): the row stops matching while the source reads it and its findings close (findings
 *  INV-6c); Clear on the device page undoes it. */
function NotInstalled({ assetId, software, softwareId, cves, device, wholeDevice, reported = false }: { assetId: string; software: string; softwareId: string; cves?: string[]; device: string; wholeDevice: boolean; reported?: boolean }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const act = useDeviceAction(assetId)
  const mark = useNotInstalled(assetId)
  const [asking, setAsking] = useState(false)
  const pending = act.remove.isPending || act.removeSoftware.isPending || mark.isPending
  // async: the item leaves the list once removed, which unmounts this control before mutate's own callbacks would run
  const remove = () => (reported
    ? mark.mark({ id: softwareId, kev_cves: cves }).then((o) => toast.success(notInstalledText(t, software, device, o)))
    : (wholeDevice ? act.remove.mutateAsync() : act.removeSoftware.mutateAsync(softwareId))
      .then(() => toast.success(wholeDevice ? t('needsInput.removedDevice', { device }) : t('needsInput.removed', { software, device }))))
    .catch((e: unknown) => toast.error(errMsg(e)))
  if (!asking) {
    return <Button size="sm" disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })} onClick={() => setAsking(true)}>{t('needsInput.notInstalled')}</Button>
  }
  return (
    <div role="group" aria-label={t('needsInput.notInstalled')} className="flex flex-wrap items-center gap-2 rounded-md border border-rule bg-sunken px-3 py-2 text-meta">
      <span>{reported ? t('needsInput.notInstalledAsk', { software, device }) : wholeDevice ? t('needsInput.removeDeviceAsk', { device, software }) : t('needsInput.removeAsk', { software, device })}</span>
      <Button size="sm" variant={reported ? 'primary' : 'danger'} busy={pending} busyLabel={t(reported ? 'common:busy.saving' : 'common:busy.removing')} onClick={remove}>{t(reported ? 'needsInput.notInstalledConfirm' : 'needsInput.remove')}</Button>
      <Button size="sm" disabled={pending} onClick={() => setAsking(false)}>{t('common:cancel')}</Button>
    </div>
  )
}

/** Not affected: the unproved findings of this software close as false positives with the person's reason (one note for all, as the
 *  bulk status of the list); a person's status stays when the box matches again. */
function NotAffected({ ids }: { ids: string[] }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const bulk = useBulkStatus()
  const id = useId()
  const [asking, setAsking] = useState(false)
  const [note, setNote] = useState('')
  const [error, setError] = useState<string | undefined>()
  if (!ids.length) return null
  const tooMany = ids.length > MAX_BULK
  function submit(e: FormEvent) {
    e.preventDefault()
    if (note.trim().length < 3) { setError(t('status.noteRequired')); return }
    setError(undefined)
    bulk.mutateAsync({ ids, action: 'false_positive', note: note.trim() })
      .then((r) => toast.success(t('bulk.done', { count: r.updated })), (er: unknown) => setError(errMsg(er)))
  }
  if (!asking) {
    return (
      <Button size="sm" disabled={!can || tooMany} title={!can ? t('common:needRole', { role: t('common:role.operator') }) : tooMany ? t('bulk.tooMany', { max: MAX_BULK }) : undefined}
        onClick={() => setAsking(true)}>{t('needsInput.notAffected')}</Button>
    )
  }
  return (
    <form onSubmit={submit} noValidate className="grid basis-full gap-2 rounded-md border border-rule bg-sunken px-3 py-2">
      <div className="grid gap-1">
        <Label htmlFor={id} className="text-meta">{t('needsInput.notAffectedNote')}</Label>
        <Input id={id} value={note} maxLength={500} placeholder={t('needsInput.notAffectedHint')} aria-invalid={!!error} aria-describedby={error ? `${id}-error` : undefined}
          onChange={(e) => { setNote(e.target.value); setError(undefined) }} />
        {error ? <p id={`${id}-error`} role="alert" className="text-meta text-danger">{error}</p> : null}
      </div>
      <div className="flex flex-wrap gap-2">
        <Button type="submit" size="sm" variant="primary" busy={bulk.isPending} busyLabel={t('common:busy.saving')}>{t('needsInput.notAffectedSubmit', { count: ids.length })}</Button>
        <Button size="sm" disabled={bulk.isPending} onClick={() => setAsking(false)}>{t('common:cancel')}</Button>
      </div>
    </form>
  )
}

/**
 * D-604 (BN340): the one question left for a CVE that affects only some platforms or package builds. Its text, the command that prints
 * the answer on the device, and every answer the box offers: an OS is one click (PATCH /inventory/devices/{id} {os}); an answer that
 * asks shows its fields (os → the device's OS, pkg_version → the row's package release, PATCH …/software/{sid} {pkg_version}; the bare
 * release or the line the command prints). Each is an inventory correction (INV-41); the device is matched again, so the item leaves
 * (or comes back with the next question, or with `question.error` when the release could not be read).
 */
/** INV-41 (6): an item that asks about the platform or the package release of a row a scan, SNMP or an agent reported also offers
 *  Not installed (never on the box, never on a row a person added: that one is removed instead). */
function PlatformNotInstalled({ u }: { u: UncheckedItem }) {
  const { t } = useTranslation('findings')
  const d = useDeviceSoftware(u.asset_id || undefined).data?.asset
  const row = d?.software.find((s) => s.id === u.software_id)
  if (!row || !u.asset || d?.is_box || (row.source === 'manual' && !row.correction)) return null
  return (
    <div className="pl-4">
      <NotInstalled assetId={u.asset_id} software={row.display} softwareId={row.id} cves={row.kev_cves} device={deviceName(u.asset, t('removedDevice'))} wholeDevice={false} reported />
    </div>
  )
}

function PlatformQuestion({ u, question: q }: { u: UncheckedItem; question: NonNullable<UncheckedItem['question']> }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const act = useDeviceAction(u.asset_id)
  const needRole = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const asks = q.answers.filter((a) => a.ask?.length && (u.software_id || !a.ask.includes('pkg_version')))
  // one answer to type (the package release), or the last release could not be read: its fields are open at once
  const first = asks.length === 1 && q.answers.length === 1 ? asks[0]! : q.error ? asks.find((a) => a.ask?.includes('pkg_version')) ?? null : null
  const [asking, setAsking] = useState<Answer | null>(first)
  const setOs = (os: string) => act.patch.mutateAsync({ os })
    .then(() => toast.success(t('needsInput.question.osSaved', { os })), (e: unknown) => toast.error(errMsg(e)))
  return (
    <div className="grid gap-2 pl-4">
      <p className="text-meta">{q.text}</p>
      {q.command ? <p className="text-meta text-muted">{t('needsInput.question.command')} <code className="font-mono text-meta">{q.command}</code></p> : null}
      <div className="flex flex-wrap items-center gap-2">
        {q.answers.map((a) => a.os ? (
          <Button key={a.label} size="sm" disabled={!can || act.patch.isPending} title={needRole} busy={act.patch.isPending && act.patch.variables?.os === a.os}
            busyLabel={t('common:busy.saving')} onClick={() => setOs(a.os!)}>{a.label}</Button>
        ) : asks.includes(a) && !(asking === a && a === first) ? (
          <Button key={a.label} size="sm" variant={asking === a ? 'secondary' : 'ghost'} aria-pressed={asking === a} disabled={!can} title={needRole} onClick={() => setAsking(asking === a ? null : a)}>{a.label}</Button>
        ) : null)}
      </div>
      {asking ? <AnswerForm key={asking.label} u={u} q={q} answer={asking} /> : null}
    </div>
  )
}

/** The fields of one answer: the device's OS and/or the row's package release; errors at their field (`question.error`, 400 bad_os,
 *  bad_pkg_version). */
function AnswerForm({ u, q, answer }: { u: UncheckedItem; q: NonNullable<UncheckedItem['question']>; answer: Answer }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const act = useDeviceAction(u.asset_id)
  const id = useId()
  const wantOs = !!answer.ask?.includes('os')
  const wantPkg = !!answer.ask?.includes('pkg_version') && !!u.software_id
  const [os, setOs] = useState('')
  const [pkg, setPkg] = useState('')
  const [osError, setOsError] = useState<string | undefined>()
  const [pkgError, setPkgError] = useState<string | undefined>(q.error)
  const busy = act.patch.isPending || act.correct.isPending
  async function send() {
    try {
      if (wantOs) await act.patch.mutateAsync({ os: os.trim() })
    } catch (e) { setOsError(errMsg(e)); return }
    try {
      if (wantPkg) await act.correct.mutateAsync({ sid: u.software_id!, pkg_version: pkg.trim() })
    } catch (e) { setPkgError(errMsg(e)); return }
    toast.success(t('needsInput.question.saved', { software: u.software }))
  }
  function submit(e: FormEvent) {
    e.preventDefault()
    const noOs = wantOs && !os.trim()
    const noPkg = wantPkg && !pkg.trim()
    setOsError(noOs ? t('needsInput.question.osRequired') : undefined)
    setPkgError(noPkg ? t('needsInput.question.pkgRequired') : undefined)
    if (noOs || noPkg) return
    void send()
  }
  const field = (k: 'os' | 'pkg', label: string, value: string, set: (v: string) => void, error: string | undefined, hint?: string, placeholder?: string) => (
    <div className="grid gap-1">
      <Label htmlFor={`${id}-${k}`} className="text-meta">{label}</Label>
      <Input id={`${id}-${k}`} value={value} maxLength={k === 'os' ? 200 : 100} className="h-9 w-full sm:w-72" placeholder={placeholder} disabled={!can}
        aria-invalid={!!error} aria-describedby={error ? `${id}-${k}-error` : hint ? `${id}-${k}-hint` : undefined}
        onChange={(e) => { set(e.target.value); if (k === 'os') setOsError(undefined); else setPkgError(undefined) }} />
      {error ? <p id={`${id}-${k}-error`} role="alert" className="text-meta text-danger [overflow-wrap:anywhere]">{error}</p>
        : hint ? <p id={`${id}-${k}-hint`} className="text-meta text-muted [overflow-wrap:anywhere]">{hint}</p> : null}
    </div>
  )
  return (
    <form onSubmit={submit} noValidate aria-label={answer.label} className="grid gap-2 rounded-md border border-rule bg-sunken px-3 py-2">
      {wantOs ? field('os', t('needsInput.question.osLabel'), os, setOs, osError, undefined, t('needsInput.question.osPlaceholder')) : null}
      {wantPkg ? field('pkg', t('needsInput.question.pkgLabel', { software: u.software }), pkg, setPkg, pkgError,
        // the question's command prints the package release only when the release is the question (package_unknown); for the platform
        // question it prints the distribution's release, which is not what this field takes
        u.reason === 'package_unknown' && q.command ? t('needsInput.question.pkgHint', { command: q.command }) : t('needsInput.question.pkgHintNone'), t('needsInput.question.pkgPlaceholder')) : null}
      <div>
        <Button type="submit" size="sm" variant="primary" disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}
          busy={busy} busyLabel={t('common:busy.saving')}>{t('needsInput.saveVersion')}</Button>
      </div>
    </form>
  )
}
