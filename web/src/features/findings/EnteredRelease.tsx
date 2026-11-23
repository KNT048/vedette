// What a version or package release a person entered did. The box saves it on the software row and closes the CVEs it proves
// the device is not affected by; this says so where the person is, from the device's findings (GET /findings?asset=: each finding names
// the software row the matcher matched it on and, when Vedette closed it by proof, the version it compared). A CVE counts as closed by
// the entry only when that version IS the entry: a closure by another rule (name only, age, an open platform question) or on another
// version says nothing about it. Used by Needs your input right after a save and by the device's Software tab, for good.
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { isOpen } from './basis'
import { useFindings } from './api'
import type { FindingRow } from './types'
import type { DeviceDetail, SoftwareLine } from '@/features/inventory/types'

/** Reads of the findings list after a save, and the pause between them: the box matches the device a moment after the save. */
export const ENTRY_POLLS = 6
export const ENTRY_POLL_MS = 2500
/** Past those, while the device is not matched again yet, the list is read again this often, this many times (about 5 minutes). */
export const ENTRY_SLOW_POLLS = 30
export const ENTRY_SLOW_MS = 10000

export type EnteredResult = { closed: FindingRow[]; open: FindingRow[]; otherProof: boolean; rows: FindingRow[]; unknown: boolean }

const same = (a: string | null, b: string) => !!a && a.trim().toLowerCase() === b.trim().toLowerCase()
const byProof = (f: FindingRow) => f.status === 'not_relevant' && f.resolution_reason === 'not_affected_version' && f.proved_version !== null

/** The findings of one software (the ids of its rows: softwareRowIds) against what a person
 *  entered (`entered`: the release and/or the version on the row). `unknown`: some finding of the device names no row yet (an older one
 *  no match has reached), so an empty answer is not an answer. */
export function enteredResult(items: FindingRow[], rowIds: readonly string[], entered: readonly string[]): EnteredResult {
  const rows = items.filter((f) => f.software_id !== '' && rowIds.includes(f.software_id))
  const closed = rows.filter((f) => byProof(f) && entered.some((e) => same(f.proved_version, e)))
  return {
    rows, closed, open: rows.filter((f) => isOpen(f.status)),
    otherProof: rows.some((f) => byProof(f) && !closed.includes(f)),
    unknown: items.some((f) => f.software_id === ''),
  }
}

/** One software line of the device as inventory gives it (the device's lines, DeviceDetail.asset.software): its id and the ids its
 *  other readings name. */
type LineIds = Pick<SoftwareLine, 'id' | 'vendor' | 'product'> & { also_seen: { id: string }[] }

/** The ids of every row of the software the entry was made on: the edited line and, from inventory's lines, every line of that
 *  software: its other readings and any other line of the same vendor and product (another release train). A finding of the software
 *  can be on any of them. */
export function softwareRowIds(rowIds: readonly string[], effective: readonly LineIds[] | undefined): string[] {
  const ids = new Set(rowIds)
  const rows = (e: LineIds) => [e.id, ...e.also_seen.map((o) => o.id)]
  const product = (e: LineIds) => `${e.vendor}|${e.product}`.trim().toLowerCase()
  const mine = new Set((effective ?? []).filter((e) => rows(e).some((id) => ids.has(id))).map(product))
  for (const e of effective ?? []) if (mine.has(product(e))) rows(e).forEach((id) => ids.add(id))
  return [...ids]
}

/** Whether the re-match after the save has run, as far as this software is concerned: one of its findings is new, gone or changed
 *  (status, last match, the version it was proved on, the row it is on), or a match of the device started after the save (`since`:
 *  when the save was done): every finding a match still makes gets that match's time, so a later last match than any before the save
 *  is that match. A change on another software of the device alone does not end the wait. */
export function rematched(before: FindingRow[], items: FindingRow[], ids: readonly string[], since: number): boolean {
  const mine = (l: FindingRow[]) => l.filter((f) => ids.includes(f.software_id))
  const was = mine(before), now = mine(items)
  const old = new Map(was.map((f) => [f.id, f]))
  if (was.length !== now.length || now.some((f) => {
    const b = old.get(f.id)
    return !b || b.status !== f.status || b.last_seen !== f.last_seen || b.proved_version !== f.proved_version || b.software_id !== f.software_id
  })) return true
  const last = (l: FindingRow[]) => l.reduce((m, f) => (f.last_seen > m ? f.last_seen : m), '')
  const after = last(items)
  return after !== '' && after > last(before) && Date.parse(after) >= since
}

function CveLinks({ items }: { items: FindingRow[] }) {
  return (
    <>
      {items.map((f, i) => (
        <span key={f.id}>{i ? ', ' : ' '}<Link to={`/findings/${encodeURIComponent(f.id)}`} className="text-accent underline underline-offset-4">{f.cve}</Link></span>
      ))}
    </>
  )
}

/**
 * The one-line result: what the entry closed (with links to those findings) and what is still affected, over every row of the
 * software (softwareRowIds: the finding may sit on the agent's row that describes the software, not on the row the person edited).
 * `before` (right after a save): the device's findings read before it. Nothing is said until the box has matched the device again
 * (rematched), read every few seconds for about 15 s; past that it says the device is not matched again yet and keeps reading, more
 * slowly, so the answer appears when the match lands: it never claims a result it does not have. Mount it with a key that changes with
 * every save so a second entry starts over. Without `before` (the Software tab) it only reads.
 * `always`: say so when nothing is closed or open too (a row that carries an entry).
 */
export function EnteredOutcome({ assetId, rowIds, entered, before, always = false }: { assetId: string; rowIds: readonly string[]; entered: readonly string[]; before?: FindingRow[] | null; always?: boolean }) {
  const { t } = useTranslation('findings')
  const q = useFindings(assetId)
  // its own copy of the device's lines: reading them again while waiting must not re-render the device page around it
  const eff = useQuery({
    queryKey: ['inventory', 'device', assetId, 'lines'],
    queryFn: () => api.get<DeviceDetail>(`/inventory/devices/${encodeURIComponent(assetId)}`).then((d) => d.asset.software),
    retry: false,
  })
  const qc = useQueryClient()
  const [since] = useState(() => Date.now())
  const waiting = before !== undefined
  const items = q.data?.items ?? []
  const ids = softwareRowIds(rowIds, eff.data)
  const r = enteredResult(items, ids, entered)
  const done = !waiting || (before ? rematched(before, items, ids, since) : false) || r.closed.length > 0
  const [tries, setTries] = useState(0)
  const late = !done && tries >= ENTRY_POLLS
  useEffect(() => {
    if (done || tries >= ENTRY_POLLS + ENTRY_SLOW_POLLS) return
    const timer = setTimeout(() => {
      setTries((n) => n + 1)
      void qc.invalidateQueries({ queryKey: ['findings', 'list', assetId] })
      void qc.invalidateQueries({ queryKey: ['inventory', 'device', assetId, 'lines'], exact: true })
    }, tries < ENTRY_POLLS ? ENTRY_POLL_MS : ENTRY_SLOW_MS)
    return () => clearTimeout(timer)
  }, [done, tries, qc, assetId])
  if (q.isError || eff.isError) return null // either list unreadable: nothing is claimed, as for a failed read of the findings
  if (q.isPending || eff.isPending) return waiting ? <p className="text-meta text-muted">{t('entered.checking')}</p> : null
  if (late) return <p className="text-meta text-muted">{t('entered.notYet')}</p>
  if (!done) return <p className="text-meta text-muted">{t('entered.checking')}</p>
  if (!r.closed.length && !r.open.length) {
    return (waiting || always) && !r.unknown && !r.otherProof ? <p className="text-meta">{t('entered.none')}</p> : null
  }
  return (
    <div className="grid gap-0.5 text-meta">
      {r.closed.length ? <p>{t('entered.closed', { count: r.closed.length })}<CveLinks items={r.closed} /></p> : null}
      {r.open.length ? <p className="text-warn">{t('entered.stillOpen', { count: r.open.length })}<CveLinks items={r.open} /></p> : null}
    </div>
  )
}
