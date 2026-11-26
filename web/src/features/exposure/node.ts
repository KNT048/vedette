// What the screens say about a target node, worked out once from its fields: where it sits in the tree, whether its
// ownership holds, and whether something waits on a person.
import type { TargetNode } from './types'

/** How deep each node sits in the tree (0 at the top), from the parent links of the list. */
export function depths(items: Pick<TargetNode, 'id' | 'parent_id'>[]): Map<string, number> {
  const parent = new Map(items.map((n) => [n.id, n.parent_id]))
  const out = new Map<string, number>()
  for (const n of items) {
    let d = 0
    for (let p = n.parent_id; p && d < 50; p = parent.get(p) ?? null) d++
    out.set(n.id, d)
  }
  return out
}

/** The ownership proof holds, by the node's own proof or an ancestor's. */
export const proven = (n: Pick<TargetNode, 'proof'>) => n.proof.state === 'proven' || n.proof.state === 'covered'

/** The testing terms can be accepted while the proof holds: proven, covered, or the box's own IP it does not go out through now (its
 *  proof holds 90 days from the last sighting and it is scanned in that time). */
export const termsAcceptable = (n: Pick<TargetNode, 'proof'>) => proven(n) || n.proof.state === 'not_current'

/** A person has something to do on the Ownership tab: prove the node, or put its proof back. */
export const needsProof = (n: Pick<TargetNode, 'proof'>) => n.proof.state === 'missing' || n.proof.state === 'expired'

/** A public IP the box found as its own address (not typed in). */
export const boxIp = (n: Pick<TargetNode, 'kind' | 'origin'>) => n.kind === 'ip' && n.origin === 'box'

/** The run page of a scan (the shared runs: its steps, log and Stop). */
export const runHref = (runId: string) => `/runs/${encodeURIComponent(runId)}`
