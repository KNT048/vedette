// SAMPLE DATA of the trial build (D-58): what a connected firewall would answer to a read tool, and the containment the AI would draft from it.
// Vendor names (FortiGate, FortiOS paths) are allowed here and nowhere in the response core. On a real box the AI reads these through the
// customer's own connection (D-39) and drafts the change from the action template library; nothing in this file ships as logic.
import { connectorsStore, type Connector } from '@/mocks/connectors'
import { assetsStore } from '@/mocks/stores'
import type { Asset, Finding } from '@/lib/types'
import type { Change, PlanStep, StoredProposal } from '../types'

export type StoredStep = Omit<PlanStep, 'proposal'> & { proposal: StoredProposal | null }

/** Mock answer of the read tool get_virtual_ips on the sample firewall connection. */
const VIPS = [
  { name: 'NAS-PHOTO-443', extip: '203.0.113.10', extport: 443, mappedip: '192.168.10.21', mappedport: 443, status: 'enable' },
  { name: 'WEB-HTTPS', extip: '203.0.113.11', extport: 443, mappedip: '192.168.10.12', mappedport: 443, status: 'enable' },
]
/** The enabled sample connection that offers the virtual IP read tool, if any. */
const readable = (): Connector | undefined => connectorsStore.get().find((c) => c.enabled && c.tools.some((t) => t.name === 'get_virtual_ips' && t.access === 'read' && t.enabled))
/** The virtual IP that publishes this device to the Internet (undefined without a readable firewall connection). */
export const exposingVip = (ip: string): { name: string } | undefined => (readable() ? VIPS.find((v) => v.mappedip === ip && v.status === 'enable') : undefined)

/** Containment step of the sample plan: turn off the virtual IP that exposes the device, or do it by hand. */
export function sampleContainment(f: Finding, asset: Asset, name: string): { reads: { connection: string; tool: string; summary: string }[]; path: string; contain: StoredStep } {
  const conn = readable()
  const vips = conn ? VIPS.filter((v) => v.mappedip === asset.ip && v.status === 'enable') : []
  const vip = vips[0]
  const write = conn?.tools.find((t) => t.name === 'disable_virtual_ip' && t.access === 'write')
  const reads = conn ? [{ connection: conn.name, tool: 'get_virtual_ips', summary: `${VIPS.length} virtual IPs, ${vips.length} point${vips.length === 1 ? 's' : ''} to ${name} (${asset.ip})` }] : []
  const path = !conn ? `Vedette has no read access to a firewall, so it could not check how ${name} is exposed. Connect your firewall in Settings, AI assistant to get a plan that fits your network.`
    : vip ? `${name} is reachable from the Internet through FortiGate virtual IP ${vip.name} (${vip.extip}:${vip.extport} to ${vip.mappedip}:${vip.mappedport}).`
    : `No virtual IP on ${conn.name} points to ${name}, so it is not forwarded from the Internet. It is reachable from the internal network only.`
  if (vip && conn && write) {
    const fw = assetsStore.get().find((a) => a.id === conn.asset_id)?.hostname ?? conn.name
    const url = `${conn.target}/api/v2/cmdb/firewall/vip/${encodeURIComponent(vip.name)}`
    const change: Change = {
      before: `Virtual IP ${vip.name}: ${vip.extip}:${vip.extport} to ${vip.mappedip}:${vip.mappedport}, status enable`,
      after: `Virtual IP ${vip.name}: status disable. Internet traffic to ${vip.extip}:${vip.extport} is no longer forwarded to ${name}.`,
      cli: `config firewall vip\n    edit "${vip.name}"\n        set status disable\n    next\nend`,
      rest: { method: 'PUT', url, body: '{"status":"disable"}' },
      rollback: { title: `Turn virtual IP ${vip.name} back on`, cli: `config firewall vip\n    edit "${vip.name}"\n        set status enable\n    next\nend`, rest: { method: 'PUT', url, body: '{"status":"enable"}' } },
      verify: `GET ${url}`,
    }
    return { reads, path, contain: { kind: 'contain', title: `Turn off virtual IP ${vip.name} on ${fw}`, detail: `Stops the Internet from reaching ${name} while you patch. Existing LAN access is not affected. Side effect: anyone using the published address ${vip.extip}:${vip.extport} loses access until you turn it back on.`,
      proposal: { id: `pr-${f.id}-${vip.name}`.toLowerCase(), title: `Turn off virtual IP ${vip.name} on ${fw}`, tool_key: `${conn.id}/${write.name}`, tool: write.name, connector_id: conn.id, connection: conn.name, asset_id: conn.asset_id ?? '', asset_name: fw, change } } }
  }
  return { reads, path, contain: { kind: 'contain', title: `Limit who can reach ${name}`, detail: vip ? 'No write tool is connected for this, so do it by hand on the firewall.' : 'Allow only the admin workstations to connect until the fix is installed.', proposal: null } }
}
