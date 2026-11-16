import { VulnChecksButton } from '@/features/scan/VulnChecksButton'
import { ScanNowButton } from './ScanNow'

/** #850 H3, slot `devices.actions` of the Devices list: "Scan selected (N)" with a selection, "Scan the LAN now" always. */
export function DevicesActions({ selectedIds, clearSelection }: { selectedIds: string[]; clearSelection: () => void }) {
  void clearSelection // the selection stays: the person sees what was sent while it runs
  return (
    <div className="flex flex-wrap items-start gap-3">
      {selectedIds.length ? <ScanNowButton targets={selectedIds} size="sm" /> : null}
      <ScanNowButton targets="lan" size="sm" variant="secondary" />
    </div>
  )
}

/** #850 H3, slot `device.actions` of the device page: "Check this device now" (nmap identification), and "Run vulnerability
 *  checks now" while the vulnerability checks (Preview) are on (review r2 N4). */
export function DeviceActions({ assetId }: { assetId: string }) {
  return (
    <div className="flex flex-wrap items-start gap-3">
      <ScanNowButton targets={[assetId]} size="sm" />
      <VulnChecksButton targets={[assetId]} />
    </div>
  )
}
