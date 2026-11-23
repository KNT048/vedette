// How an agent reads a device now: the one check behind every sentence that says an agent reports a version (the "I updated it"
// line, the finding's title and steps).
import { useAgentReport } from '@/features/inventory/api'
import type { AgentReport } from '@/features/inventory/types'
import { useModuleEnabled } from '@/lib/modules'
import { useDeviceSoftware } from './rematch'
import type { FindingDetail } from './types'

/** box: the Vedette box reads its own packages; none: no agent of this box reads the device (agent-intake off, no agent bound, or its
 *  state cannot be read); stale: its osquery node has not called for a while; wazuh, osquery: an agent reads it now. */
export type AgentNow = 'box' | 'none' | 'stale' | 'wazuh' | 'osquery'

/** The state from agent-intake's answer; undefined while it is not known yet. */
export function agentNow(on: boolean | undefined, q: { isPending: boolean; data?: AgentReport }, box: boolean): AgentNow | undefined {
  if (box || q.data?.agent === 'box') return 'box'
  if (on === undefined || (on && q.isPending)) return undefined
  const r = q.data
  if (!on || !r || r.agent === 'none') return 'none'
  if (r.agent === 'wazuh') return 'wazuh'
  return r.stale ? 'stale' : 'osquery'
}

/** No agent reports the device now: the version an agent gave is the last list it sent. */
export const lastReportOnly = (n: AgentNow | undefined) => n === 'none' || n === 'stale'

/** Whether the version an agent reported for this finding's device is only its last list (agentNow), asked only when the finding rests
 *  on an agent's reading; false while unknown. */
export function useFindingAgentGone(f: FindingDetail): boolean {
  const agent = !!f.asset && (((f.status === 'suspected' || f.status === 'confirmed') && !!f.evidence?.agent) || f.known_version?.source === 'agent')
  const dev = useDeviceSoftware(agent ? f.asset?.id : undefined)
  const on = useModuleEnabled('agent-intake')
  const q = useAgentReport(f.asset?.id ?? '', agent && on === true)
  if (!agent || dev.isPending) return false
  return lastReportOnly(agentNow(on, q, !!dev.data?.asset.is_box))
}
