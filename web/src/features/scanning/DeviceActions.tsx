import { useId, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { InfoTip } from '@/components/common/InfoTip'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/input'
import type { DeviceRow } from '@/features/inventory/types'
import { deviceRefusal, useDeviceButtons, type ScanFacts, type VulnButton } from './canScan'
import { useTargets } from '@/features/scan/api'
import { VulnChecksButton } from '@/features/scan/VulnChecksButton'
import { useModuleEnabled } from '@/lib/modules'
import { useScanning } from './api'
import { useFindings } from '@/features/findings/api'
import { ScanNowButton } from './ScanNow'

// The rule moved to canScan.ts, shared with the finding page, To fix and the device page's fragile line
type Facts = ScanFacts
const nmapRefusal = deviceRefusal

/** "Not in Scan selected: the Vedette box, 2 added by hand." (#877): what a button left out of the selection, and why. */
function useLeftOut() {
  const { t } = useTranslation('scanning')
  return (why: string[], kind: 'nmap' | 'vuln') => {
    if (!why.length) return null
    const n = new Map<string, number>()
    for (const w of why) n.set(w, (n.get(w) ?? 0) + 1)
    return t(`selection.${kind}.leftOut`, { list: [...n].map(([w, c]) => t(`selection.${kind}.${w}`, { count: c })).join(', ') })
  }
}

/** #850 H3, slot `devices.actions` of the Devices list: "Scan selected (N)" with a selection, "Scan the LAN now" always, and while
 *  the vulnerability checks are on "Run vulnerability checks on selected (N)" (#877). Select all ticks every row, the box and
 *  devices added by hand included, while the server refuses a whole run for one of them: each button sends only the devices it may
 *  check and says how many it left out and why (#877). */
export function DevicesActions({ selectedIds, selected, clearSelection }: { selectedIds: string[]; selected: DeviceRow[]; clearSelection: () => void }) {
  const { t } = useTranslation('scanning')
  const safety = useScanning().data?.safety
  const leftOut = useLeftOut()
  void clearSelection // the selection stays: the person sees what was sent while it runs
  const rows = new Map(selected.map((d) => [d.id, d]))
  const ok: string[] = []
  const why: string[] = []
  for (const id of selectedIds) {
    const d = rows.get(id)
    const r = d ? nmapRefusal(d, safety) : null // a row not read yet: the server decides
    if (r) why.push(r)
    else ok.push(id)
  }
  const note = leftOut(why, 'nmap')
  return (
    <div className="grid gap-2">
      <div className="flex flex-wrap items-start gap-3">
        {ok.length ? <ScanNowButton targets={ok} size="sm" label={t('scanNow.selected', { count: ok.length })} /> : null}
        <ScanNowButton targets="lan" size="sm" variant="secondary" />
        {selectedIds.length ? <SelectedVulnChecks selectedIds={selectedIds} /> : null}
      </div>
      {note ? <p className="text-meta text-muted" role="status">{note}</p> : null}
    </div>
  )
}

/**
 * #877: the hand pick for several devices (a KEV rescan's "N devices need a hand pick on Devices"): POST /scans/runs
 * with the selection. Devices checked only on a person's own pick (fragile, unclassified, added by hand, the box) are never sent
 * because a box was ticked by Select all: each one is ticked here, by name (scan contract: "not with Select all"). Devices the
 * scan refuses (never scan, no IP, outside the scope) are left out with the reason.
 */
function SelectedVulnChecks({ selectedIds }: { selectedIds: string[] }) {
  const { t } = useTranslation('scanning')
  const on = useModuleEnabled('scan') === true
  const targets = useTargets(on)
  const leftOut = useLeftOut()
  const id = useId()
  const [picked, setPicked] = useState<Set<string>>(new Set())
  if (!on || !targets.data) return null
  const byId = new Map(targets.data.items.map((x) => [x.id, x]))
  const ok: string[] = []
  const pick: { id: string; label: string }[] = []
  const why: string[] = []
  for (const sid of selectedIds) {
    const x = byId.get(sid)
    if (!x || !x.selectable) why.push(x?.reason ?? 'out_of_scope')
    else if (x.pick_only || x.box) pick.push({ id: sid, label: x.label })
    else ok.push(sid)
  }
  const send = [...ok, ...pick.filter((p) => picked.has(p.id)).map((p) => p.id)]
  const note = leftOut(why, 'vuln')
  return (
    <div className="grid gap-2">
      {send.length ? <VulnChecksButton targets={send} label={t('selection.vuln.button', { count: send.length })} /> : null}
      {pick.length ? (
        <fieldset className="grid gap-1.5">
          <legend className="text-meta text-muted">{t('selection.vuln.handPick', { count: pick.length })}</legend>
          {pick.map((p) => (
            <span key={p.id} className="inline-flex items-center gap-2">
              <Checkbox id={`${id}-${p.id}`} checked={picked.has(p.id)} onCheckedChange={(v) => setPicked((s) => { const n = new Set(s); if (v === true) n.add(p.id); else n.delete(p.id); return n })} />
              <Label htmlFor={`${id}-${p.id}`} className="font-normal">{p.label}</Label>
            </span>
          ))}
        </fieldset>
      ) : null}
      {note ? <p className="text-meta text-muted" role="status">{note}</p> : null}
    </div>
  )
}

/** #850 H3, slot `device.actions` of the device page: "Check this device now" (nmap identification), and "Run vulnerability
 *  checks now" while the vulnerability checks (Preview) are on. A device the nmap check always refuses (the box, added
 *  by hand, never scan, no IP, outside the scope) gets the reason instead of a button that can only fail (#877).
 *  He could not tell the two apart. Each button has one line under it: what it does, what it does not, how long. They
 *  stay two buttons: the vulnerability check sends exploit checks to the device and is a person's own pick, the device
 *  check only identifies it; one merged button would hide that difference. */
export function DeviceActions({ assetId, asset: d }: { assetId: string; /** The device page's own read (no second read of it here). */ asset?: Facts & { ignored_at?: string | null } }) {
  const { t } = useTranslation('scanning')
  const hint = useId()
  const { identify: r, vuln } = useDeviceButtons(assetId, d)
  // one cause is said once: a device that can be neither identified nor checked for the same reason (no address) gets one note
  if (r && r !== 'manual' && r === vuln) return <p className="text-meta text-muted">{t(`selection.device.both.${r}`, { defaultValue: t(`selection.device.${r}`) })}</p>
  return (
    <div className="flex flex-wrap items-start gap-3">
      {r === 'manual' ? <p className="text-meta text-muted"><ScanOffSeeSources link={!d?.ignored_at} /></p>
        : r ? <p className="text-meta text-muted">{t(`selection.device.${r}`)}</p> : (
        // what the button does sits behind its info icon (and is the button's description for screen readers)
        <span className="inline-flex items-start gap-1">
          <ScanNowButton targets={[assetId]} size="sm" describedBy={hint} />
          <InfoTip topic={t('scanNow.device')} className="sm:mt-1">{t('hint.identify')}</InfoTip>
          <span id={hint} hidden>{t('hint.identify')}</span>
        </span>
      )}
      {/* a device added by hand with its network scan off: the scan list's reason is that same switch, already pointed at */}
      {r === 'manual' && vuln === 'regular_scan_never' ? null : <DeviceVulnChecks assetId={assetId} vuln={vuln} />}
    </div>
  )
}

/** "Run vulnerability checks now" on one device: a person's own pick (the box too); a device the scan refuses (never
 *  scan, no IP, outside the scope) gets the reason instead (#877). */
function DeviceVulnChecks({ assetId, vuln }: { assetId: string; vuln: VulnButton }) {
  const { t } = useTranslation('scanning')
  const hint = useId()
  const c = useVulnCheckable(assetId)
  if (vuln === 'off') return null
  if (vuln) return <p className="text-meta text-muted">{t(`scan:reason.${vuln}`)}</p>
  if (c.pending) return null // the count decides whether a run is offered: wait for it
  // nothing a run could confirm or rule out: no button that runs for nothing; why is behind the info icon of its Last checks row
  if (c.none) return null
  const what = [t('hint.vuln'), c.counted && c.suspected > 0 ? t('hint.vulnCount', { checkable: c.checkable, count: c.suspected }) : '', c.again > 0 ? t('hint.vulnAgain', { count: c.again }) : ''].filter(Boolean).join(' ')
  return (
    <span className="inline-flex items-start gap-1">
      <VulnChecksButton targets={[assetId]} describedBy={hint} />
      <InfoTip topic={t('scan:checks.button')} className="sm:mt-1">{what}</InfoTip>
      <span id={hint} hidden>{what}</span>
    </span>
  )
}

/** What a vulnerability check of the device can do: `checkable` of its `suspected` findings have a safe check (the finding's
 *  has_template: the scan's own template pack) it can confirm or rule out, and `again` of its confirmed or mitigated ones a check
 *  it can run again to see whether a fix or a mitigation holds. `none`: neither, so the device page offers no run (nothing
 *  suspected, or no check exists). Not counted (findings off, no device yet, or its read failed): the run is offered as before,
 *  without a count. The device page's button and its Last checks row read this one rule. Without an id it reads nothing (never
 *  the whole /findings list). */
export function useVulnCheckable(assetId: string) {
  const findingsOn = useModuleEnabled('findings') === true && assetId !== ''
  const list = useFindings(assetId, findingsOn)
  const counted = findingsOn && list.isSuccess
  const items = counted ? list.data.items : []
  const suspected = items.filter((f) => f.status === 'suspected')
  const checkable = suspected.filter((f) => f.kev?.has_template).length
  // the scan also checks confirmed and mitigated findings again (scan run.go `dismissed`): whether a fix or a mitigation holds
  const again = items.filter((f) => (f.status === 'confirmed' || f.status === 'mitigated') && f.kev?.has_template).length
  return { pending: findingsOn && list.isPending, counted, suspected: suspected.length, checkable, again, none: counted && checkable + again === 0 }
}

/** A device added by hand whose network scan is off: the full note is on its Sources card, next to the switch that turns the scan
 *  on; every other place on the device page (the check buttons, Last checks) only points there. No link where the page shows no
 *  Sources card (an ignored device). */
export function ScanOffSeeSources({ link = true }: { link?: boolean }) {
  const { t } = useTranslation('scanning')
  if (!link) return <>{t('selection.device.manualOff')}</>
  return <>{t('selection.device.manualSee')} <Link to="?tab=overview#sources" className="text-accent underline-offset-4 hover:underline">{t('selection.device.manualSeeLink')}</Link></>
}
