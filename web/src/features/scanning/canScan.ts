// One rule for "can Vedette scan this device now": the device page's "Check this device now", the
// Devices list's "Scan selected", the finding page's "I updated it" for scan-read software, and the device page's fragile
// line all read it, so none offers or promises a scan the box refuses. It follows what POST /scanning/engines/nmap-discovery/run
// refuses (sensor-active runnow.go: the box and outside the scope are out_of_scope; never scan, added by hand, no address are
// not_scannable) and what the run needs of the box (the ranges confirmed, network discovery on).
import { inRanges } from '@/features/inventory/AddToScopeDialog'
import { useTargets } from '@/features/scan/api'
import type { ScanTarget } from '@/features/scan/types'
import { useModuleEnabled } from '@/lib/modules'
import { useScanning } from './api'
import type { Safety, Scanning } from './types'

/** What a device brings to the rule: the device page's read or a Devices list row (inventory DeviceRow). */
export type ScanFacts = { is_box: boolean; ip: string; origin: 'discovered' | 'manual'; regular_scan: 'follow' | 'allow' | 'never'; scan_source: 'on' | 'off' }
export type DeviceRefusal = 'box' | 'no_ip' | 'manual' | 'never' | 'out_of_scope'
export type ScanRefusal = DeviceRefusal | 'scope' | 'discovery_off'

/** Why the network check refuses this device whatever the box's state; null: the device may be checked. */
export function deviceRefusal(d: ScanFacts, safety?: Safety): DeviceRefusal | null {
  if (d.is_box) return 'box'
  if (!d.ip || d.ip === '—') return 'no_ip'
  // The device's network scan, on or off on its Sources card (a device added by hand starts off; off is "never" to the server)
  if (d.scan_source === 'off') return d.origin === 'manual' ? 'manual' : 'never'
  if (d.regular_scan === 'never') return 'never'
  // the scope check runs only once there are ranges: with none, the scope itself is not confirmed (scanRefusal says so)
  if (safety && safety.scope.lan_ranges.length && (!inRanges(d.ip, safety.scope.lan_ranges) || inRanges(d.ip, safety.exclusions))) return 'out_of_scope'
  return null
}

/** Why Vedette cannot scan this device now, the device first, then the box: the ranges not confirmed, network discovery off; null:
 *  it may. `s` undefined (GET /scanning not answered yet): only the device's own reasons. */
export function scanRefusal(d: ScanFacts, s?: Scanning): ScanRefusal | null {
  const r = deviceRefusal(d, s?.safety)
  if (r || !s) return r
  if (!s.safety.scope.confirmed_at) return 'scope'
  const disc = s.engines.find((e) => e.id === 'nmap-discovery')
  if (!disc?.enabled) return 'discovery_off'
  return null
}

/** Which of this page's two check buttons the device gets, the one rule DeviceActions shows them by: identify is why "Check this
 *  device now" gives way to a reason (null: the button is shown); vuln is 'off' (the vulnerability checks are off: neither button
 *  nor reason), the scan list's reason shown instead of "Run vulnerability checks now", or null (the button is shown). Last checks
 *  reads the same answer, so its hints name only a button that is on the page. pending: the scan list has not answered yet. */
export function useDeviceButtons(assetId: string, d?: ScanFacts) {
  const safety = useScanning().data?.safety
  const on = useModuleEnabled('scan')
  const targets = useTargets(on === true)
  const x = targets.data?.items.find((i) => i.id === assetId)
  const vuln: VulnButton = on !== true ? 'off' : x && !x.selectable ? (x.reason ?? 'out_of_scope') : null
  return { identify: d ? deviceRefusal(d, safety) : null, vuln, pending: on === true && targets.isPending }
}
export type VulnButton = 'off' | NonNullable<ScanTarget['reason']> | null
