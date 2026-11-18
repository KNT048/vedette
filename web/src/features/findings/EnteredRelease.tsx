// S-MIT-1: what a version or package release a person entered did. The box saves it on the software row and closes the CVEs it proves
// the device is not affected by (reason not_affected_version); this says so where the person is, from the device's findings
// (GET /findings?asset=: each finding names its software row and why Vedette closed it). Used by Needs your input right after the
// save and by the device's Software tab, for good.
import { useEffect, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { isOpen } from './basis'
import { useFindings } from './api'
import { POLLS, POLL_MS } from './rematch'
import type { FindingRow } from './types'

export type EnteredResult = { closed: FindingRow[]; open: FindingRow[] }

/** The findings of one software row (the id of the row, and of the correction that replaces it for matching): the ones Vedette closed
 *  because the entered release is not affected, and the ones still open. */
export function enteredResult(items: FindingRow[], rowIds: readonly string[]): EnteredResult {
  const mine = items.filter((f) => f.software_id !== '' && rowIds.includes(f.software_id))
  return {
    closed: mine.filter((f) => f.status === 'not_relevant' && f.resolution_reason === 'not_affected_version'),
    open: mine.filter((f) => isOpen(f.status)),
  }
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

/** The one-line result: what the entry closed (with links to those findings) and what is still affected. `always`: say so when nothing is closed or open too (a row that carries an entry). `waiting`: the box matches
 *  the device again a moment after the save, so an empty result is "checking" until it has had time to answer. */
export function EnteredOutcome({ assetId, rowIds, waiting = false, always = false }: { assetId: string; rowIds: readonly string[]; waiting?: boolean; always?: boolean }) {
  const { t } = useTranslation('findings')
  const q = useFindings(assetId)
  const qc = useQueryClient()
  const r = enteredResult(q.data?.items ?? [], rowIds)
  const empty = !r.closed.length && !r.open.length
  const [tries, setTries] = useState(0)
  const checking = waiting && (q.isPending || (empty && tries < POLLS))
  useEffect(() => {
    if (!waiting || !empty || tries >= POLLS) return
    const timer = setTimeout(() => { setTries((n) => n + 1); void qc.invalidateQueries({ queryKey: ['findings', 'list', assetId] }) }, POLL_MS * 2)
    return () => clearTimeout(timer)
  }, [waiting, empty, tries, qc, assetId])
  if (q.isError) return null
  if (checking) return <p className="text-meta text-muted">{t('entered.checking')}</p>
  if (q.isPending) return null
  if (empty) return waiting || always ? <p className="text-meta">{t('entered.none')}</p> : null
  return (
    <div className="grid gap-0.5 text-meta">
      {r.closed.length ? <p>{t('entered.closed', { count: r.closed.length })}<CveLinks items={r.closed} /></p> : null}
      {r.open.length ? <p className="text-warn">{t('entered.stillOpen', { count: r.open.length })}<CveLinks items={r.open} /></p> : null}
    </div>
  )
}
