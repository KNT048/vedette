// The device's Software tab says, on each software row, what it needs: its open findings (count, most urgent status, the fix that
// closes them) and what waits for a person (Needs your input), from the same answers as the device's Findings tab (GET
// /findings/devices?device=<id>, GET /findings/input?device=<id>); nothing on a clean row.
import { useTranslation } from 'react-i18next'
import { StatusBadge } from '@/components/common/status'
import { useModuleEnabled } from '@/lib/modules'
import { OPEN_FINDING_STATUSES } from '@/lib/statusCodes'
import { useDeviceCards, useInputList } from './api'
import { PAGE_MAX } from './contract'
import { useFixTitle } from './parts'
import type { FixBlock, OpenStatus } from './types'

const ONE = { offset: 0, limit: 1 }
const QUEUE = { offset: 0, limit: PAGE_MAX }

/** What one software line needs: its fix blocks (open findings) and the items of Needs your input about it. */
type Needs = { blocks: FixBlock[]; check: number }

const layer = (s: OpenStatus) => OPEN_FINDING_STATUSES.indexOf(s)
const worstOf = (blocks: FixBlock[]) => blocks.reduce<OpenStatus | null>((w, b) => (w === null || layer(b.status) < layer(w) ? b.status : w), null)
const findingsOf = (blocks: FixBlock[]) => blocks.reduce((s, b) => s + b.findings.length, 0)

/** The device's needs by software line id, or the state while there is none. */
export function useSoftwareNeeds(assetId: string): Map<string, Needs> | 'off' | 'pending' | 'error' {
  const on = useModuleEnabled('findings')
  const cards = useDeviceCards({ device: assetId }, ONE, on === true)
  const input = useInputList({ device: assetId }, QUEUE, on === true)
  if (on === false) return 'off'
  if (cards.isError || input.isError) return 'error'
  if (on === undefined || cards.isPending || input.isPending) return 'pending'
  const m = new Map<string, Needs>()
  const entry = (id: string) => {
    const e = m.get(id) ?? { blocks: [], check: 0 }
    m.set(id, e)
    return e
  }
  for (const card of cards.data.items) {
    if (card.device.id !== assetId) continue
    for (const b of card.blocks) if (b.software) entry(b.software.id).blocks.push(b)
  }
  for (const i of input.data.items) {
    if (i.kind === 'device_not_added' || !i.software) continue
    entry(i.software.id).check += i.kind === 'question' ? i.cves : 1
  }
  return m
}

/** The needs keyed by the row each software is shown as. A finding names the software line it is on, and that can be any row of
 *  the software: the device page shows one line per software (inventory's effective row) and lists the other rows under it
 *  (also_seen). `lineOf` maps every row id to the id of its line; the needs of all the rows of a line are merged. */
export function needsByLine(needs: ReturnType<typeof useSoftwareNeeds>, lineOf: ReadonlyMap<string, string>): ReturnType<typeof useSoftwareNeeds> {
  if (!(needs instanceof Map)) return needs
  const m = new Map<string, Needs>()
  for (const [id, n] of needs) {
    const line = lineOf.get(id) ?? id
    const e = m.get(line)
    m.set(line, e ? { blocks: [...e.blocks, ...n.blocks], check: e.check + n.check } : n)
  }
  return m
}

/** The order of a row by what it needs, for sorting the Software tab (higher first): the most urgent status of its open findings,
 *  then their number; a row with only items to check after every row with findings; 0 for a clean row and while the answer is not
 *  there. */
export function needsRank(needs: ReturnType<typeof useSoftwareNeeds>, softwareId: string): number {
  const n = needs instanceof Map ? needs.get(softwareId) : undefined
  if (!n) return 0
  const worst = worstOf(n.blocks)
  if (worst !== null) return (OPEN_FINDING_STATUSES.length - layer(worst)) * 1_000_000 + Math.min(findingsOf(n.blocks), 999_999)
  return Math.min(n.check, 999_999)
}

/** One software row's needs. */
export function SoftwareNeeds({ softwareId, needs }: { assetId: string; softwareId: string; needs: ReturnType<typeof useSoftwareNeeds> }) {
  const { t } = useTranslation('findings')
  const title = useFixTitle()
  if (needs === 'off') return <span className="text-meta text-muted">{t('needs.off')}</span>
  if (needs === 'pending') return <span className="text-meta text-muted">{t('needs.pending')}</span>
  if (needs === 'error') return <span className="text-meta text-muted">{t('needs.error')}</span>
  const n = needs.get(softwareId)
  if (!n) return null
  const worst = worstOf(n.blocks)
  const count = findingsOf(n.blocks)
  const fixes = [...new Set(n.blocks.filter((b) => b.fix.kind !== 'none_yet' && b.fix.kind !== 'unknown').map((b) => title(b.fix, b.software)))]
  // plain text: the device's Findings tab and Needs your input are one click away on this page, so the rows repeat no link
  return (
    <div className="grid gap-1 text-meta">
      {worst !== null ? (
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="font-medium">{t('needs.findings', { count })}</span>
          <StatusBadge code={worst} />
          {fixes.map((f) => <span key={f}>{f}</span>)}
        </span>
      ) : null}
      {n.check > 0 ? <span className="text-muted">{t('needs.toCheck', { count: n.check })}</span> : null}
    </div>
  )
}

/** The device's operating system has no row of its own on the Software tab when the OS comes from SNMP or what the device states
 *  (its findings are on "os:<device>"): one line above the table says what it needs; nothing when clean. */
export function OsNeeds({ assetId, needs }: { assetId: string; needs: ReturnType<typeof useSoftwareNeeds> }) {
  const { t } = useTranslation('findings')
  const id = `os:${assetId}`
  if (!(needs instanceof Map) || !needs.has(id)) return null
  return (
    <div className="mb-3 grid gap-1 rounded-md border border-rule bg-surface px-4 py-3 text-sm">
      <span className="font-medium">{t('needs.os')}</span>
      <SoftwareNeeds assetId={assetId} softwareId={id} needs={needs} />
    </div>
  )
}
