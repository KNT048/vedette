// S-MIT-1: what a version or package release a person entered did. The box saves it on the software row and closes the CVEs it proves
// the device is not affected by; this says so where the person is, from the device's findings (GET /findings?asset=: each finding names
// the software row the matcher matched it on and, when Vedette closed it by proof, the version it compared). A CVE counts as closed by
// the entry only when that version IS the entry: a closure by another rule (name only, age, an open platform question) or on another
// version says nothing about it. Used by Needs your input right after a save and by the device's Software tab, for good.
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { isOpen } from './basis'
import { useFindings } from './api'
import type { FindingRow } from './types'

/** Reads of the findings list after a save, and the pause between them: the box matches the device a moment after the save. */
export const ENTRY_POLLS = 6
export const ENTRY_POLL_MS = 2500

export type EnteredResult = { closed: FindingRow[]; open: FindingRow[]; otherProof: boolean; rows: FindingRow[]; unknown: boolean }

const same = (a: string | null, b: string) => !!a && a.trim().toLowerCase() === b.trim().toLowerCase()
const byProof = (f: FindingRow) => f.status === 'not_relevant' && f.resolution_reason === 'not_affected_version' && f.proved_version !== null

/** The findings of one software row (the id of the row, and of the correction that replaces it for matching) against what a person
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

/** The device's findings now, before a save, to tell later what the re-match changed; null when they cannot be read. */
export const readDeviceFindings = (assetId: string) =>
  api.get<{ items: FindingRow[] }>(`/findings?asset=${encodeURIComponent(assetId)}`).then((d) => d.items, () => null)

/** Whether the re-match after the save has run: a finding of the row is new or changed (status, last match, the version it was proved on). */
export function rematched(before: FindingRow[], rows: FindingRow[]): boolean {
  const old = new Map(before.map((f) => [f.id, f]))
  return rows.some((f) => {
    const b = old.get(f.id)
    return !b || b.status !== f.status || b.last_seen !== f.last_seen || b.proved_version !== f.proved_version
  })
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
 * The one-line result: what the entry closed (with links to those findings) and what is still affected.
 * `before` (right after a save): the device's findings read before it. Nothing is said until the box has matched the device again
 * (a finding of the row changed), read every few seconds for about 15 s, then "still checking, reload later". Mount it with a key that
 * changes with every save so a second entry starts over. Without `before` (the Software tab) it only reads.
 * `always`: say so when nothing is closed or open too (a row that carries an entry).
 */
export function EnteredOutcome({ assetId, rowIds, entered, before, always = false }: { assetId: string; rowIds: readonly string[]; entered: readonly string[]; before?: FindingRow[] | null; always?: boolean }) {
  const { t } = useTranslation('findings')
  const q = useFindings(assetId)
  const qc = useQueryClient()
  const waiting = before !== undefined
  const r = enteredResult(q.data?.items ?? [], rowIds, entered)
  const done = !waiting || (before ? rematched(before, r.rows) : false) || r.closed.length > 0
  const [tries, setTries] = useState(0)
  useEffect(() => {
    if (done || tries >= ENTRY_POLLS) return
    const timer = setTimeout(() => { setTries((n) => n + 1); void qc.invalidateQueries({ queryKey: ['findings', 'list', assetId] }) }, ENTRY_POLL_MS)
    return () => clearTimeout(timer)
  }, [done, tries, qc, assetId])
  if (q.isError) return null
  if (q.isPending) return waiting ? <p className="text-meta text-muted">{t('entered.checking')}</p> : null
  if (!done) {
    if (tries < ENTRY_POLLS) return <p className="text-meta text-muted">{t('entered.checking')}</p>
    // out of time: with nothing on the row there is nothing to wait for; otherwise it has not been checked again yet
    return r.rows.length || r.unknown ? <p className="text-meta text-muted">{t('entered.stillChecking')}</p> : <p className="text-meta">{t('entered.none')}</p>
  }
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
