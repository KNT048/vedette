import type { RunningJob } from './types'

/** Where a run is seen with its progress (and Stop, where it has one): the device, the public target, the LAN scan history. */
export function runPlace(j: RunningJob): string {
  if (j.engine === 'zap' || j.engine === 'openvas') return j.target_id ? `/exposure/${encodeURIComponent(j.target_id)}` : '/exposure'
  if (j.engine === 'nuclei') return `/settings/scanning?tab=history&run=${encodeURIComponent(j.id)}`
  return j.target_id ? `/devices/${encodeURIComponent(j.target_id)}` : '/settings/scanning?tab=engines#engine-nmap-discovery'
}

/** Where a LAN run of a device opens: History of that device's runs, with that run on top. */
export const historyRowHref = (asset: string, job: string) => `/settings/scanning?tab=history&asset=${encodeURIComponent(asset)}&job=${encodeURIComponent(job)}`
