import { useId, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/input'
import type { DeviceRow } from '@/features/inventory/types'
import { inRanges } from '@/features/inventory/AddToScopeDialog'
import { useTargets } from '@/features/scan/api'
import { VulnChecksButton } from '@/features/scan/VulnChecksButton'
import { useModuleEnabled } from '@/lib/modules'
import { useScanning } from './api'
import { ScanNowButton } from './ScanNow'
import type { Safety } from './types'

/** What a device needs for "Check this device now" (nmap), as POST /scanning/engines/nmap-discovery/run refuses it (sensor-active
 *  runnow.go: the box and outside the scope are out_of_scope; never scan, added by hand, no address are not_scannable). */
type Facts = { is_box: boolean; ip: string; origin: 'discovered' | 'manual'; regular_scan: 'follow' | 'allow' | 'never' }
type NmapRefusal = 'box' | 'no_ip' | 'manual' | 'never' | 'out_of_scope'
function nmapRefusal(d: Facts, safety?: Safety): NmapRefusal | null {
  if (d.is_box) return 'box'
  if (!d.ip || d.ip === '—') return 'no_ip'
  if (d.origin === 'manual') return 'manual'
  if (d.regular_scan === 'never') return 'never'
  // the scope check runs only once there are ranges: with none, the button already says the ranges are not confirmed
  if (safety && safety.scope.lan_ranges.length && (!inRanges(d.ip, safety.scope.lan_ranges) || inRanges(d.ip, safety.exclusions))) return 'out_of_scope'
  return null
}

/** "Not in Scan selected: the Vedette box, 2 added by hand." (#877 r1 M2): what a button left out of the selection, and why. */
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
 *  the vulnerability checks are on "Run vulnerability checks on selected (N)" (#877 r1 M5). Select all ticks every row, the box and
 *  devices added by hand included, while the server refuses a whole run for one of them: each button sends only the devices it may
 *  check and says how many it left out and why (#877 r1 M2). */
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
 * #877 r1 M5: the D-126 hand pick for several devices (a KEV rescan's "N devices need a hand pick on Devices"): POST /scans/runs
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
 *  checks now" while the vulnerability checks (Preview) are on (review r2 N4). A device the nmap check always refuses (the box, added
 *  by hand, never scan, no IP, outside the scope) gets the reason instead of a button that can only fail (#877 r1 L6). */
export function DeviceActions({ assetId, asset: d }: { assetId: string; /** The device page's own read (no second read of it here). */ asset?: Facts }) {
  const { t } = useTranslation('scanning')
  const safety = useScanning().data?.safety
  const r = d ? nmapRefusal(d, safety) : null
  return (
    <div className="flex flex-wrap items-start gap-3">
      {r ? <p className="text-meta text-muted">{t(`selection.device.${r}`)}</p> : <ScanNowButton targets={[assetId]} size="sm" />}
      <DeviceVulnChecks assetId={assetId} />
    </div>
  )
}

/** "Run vulnerability checks now" on one device: a person's own pick (D-126, the box too, D-470); a device the scan refuses (never
 *  scan, no IP, outside the scope) gets the reason instead (#877 r1 L6). */
function DeviceVulnChecks({ assetId }: { assetId: string }) {
  const { t } = useTranslation('scanning')
  const on = useModuleEnabled('scan') === true
  const x = useTargets(on).data?.items.find((i) => i.id === assetId)
  if (!on) return null
  if (x && !x.selectable) return <p className="text-meta text-muted">{t(`scan:reason.${x.reason ?? 'out_of_scope'}`)}</p>
  return <VulnChecksButton targets={[assetId]} />
}
