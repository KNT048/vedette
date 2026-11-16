import { Navigate, useLocation } from 'react-router'
import { CREDENTIALED_IN_UI } from '@/lib/credentialed'

/** #850: the old tabs of Vulnerability scans → the tabs of Settings › Scanning. */
const OLD_TAB: Record<string, string> = { runs: 'history', safety: 'safety', auto: 'history', probes: 'probes', credentialed: CREDENTIALED_IN_UI ? 'credentialed' : 'engines' }

/** #850: the Vulnerability scans page is gone from the menu; its old links land on Settings › Scanning, or on the device a
 *  "?target=" was for (its page has "Check this device now"). ?run= keeps opening that run. */
export default function ScansMoved() {
  const { search } = useLocation()
  const p = new URLSearchParams(search)
  const target = p.get('target')
  if (target) return <Navigate to={`/devices/${encodeURIComponent(target)}`} replace />
  const q = new URLSearchParams()
  const run = p.get('run')
  q.set('tab', run ? 'history' : OLD_TAB[p.get('tab') ?? ''] ?? 'engines')
  if (run) q.set('run', run)
  return <Navigate to={`/settings/scanning?${q}`} replace />
}

