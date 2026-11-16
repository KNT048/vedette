import { Navigate, useLocation } from 'react-router'
import { CREDENTIALED_IN_UI } from '@/lib/credentialed'

/** #850: the old tabs of Vulnerability scans → the tabs of Settings › Scanning. */
const OLD_TAB: Record<string, string> = { runs: 'history', safety: 'safety', auto: 'history', probes: 'probes', credentialed: CREDENTIALED_IN_UI ? 'credentialed' : 'engines' }

/** #850: the Vulnerability scans page is gone from the menu; its old links land on their new place. `?run=` wins over `?target=`
 *  (review r1 L5); an external target (`ext:<id>`) lands on its External exposure page; a device on its page, which has "Check this
 *  device now" and, while the vulnerability checks are on, "Run vulnerability checks now" (slot device.actions, review r2 H3). */
export default function ScansMoved() {
  const { search } = useLocation()
  const p = new URLSearchParams(search)
  const run = p.get('run')
  const target = p.get('target')
  if (run) return <Navigate to={`/settings/scanning?tab=history&run=${encodeURIComponent(run)}`} replace />
  if (target?.startsWith('ext:')) return <Navigate to={`/exposure/${encodeURIComponent(target.slice(4))}`} replace />
  if (target) return <Navigate to={`/devices/${encodeURIComponent(target)}`} replace />
  return <Navigate to={`/settings/scanning?tab=${OLD_TAB[p.get('tab') ?? ''] ?? 'engines'}`} replace />
}
