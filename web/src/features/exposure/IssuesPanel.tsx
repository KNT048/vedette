import { useRef, useState, type RefObject } from 'react'
import { useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { KeyValue } from '@/components/common/PageHeader'
import { EmptyState, QueryState } from '@/components/common/States'
import { CveList } from '@/components/common/status/CveList'
import { SeverityBadge } from '@/components/common/status/SeverityBadge'
import { StatusBadge, useStatusLabel } from '@/components/common/status/StatusBadge'
import { Button } from '@/components/ui/button'
import { Checkbox, RadioGroup, RadioItem } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Textarea } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { AcceptUntil } from '@/features/findings/AcceptRisk'
import { untilOk } from '@/features/findings/accept'
import { FINDING_RESOLUTIONS } from '@/lib/statusCodes'
import { fmtDate, fmtDateTime, fmtDayMonth } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useHandleIssues, useReopenIssues, useRows } from './api'
import { Seen } from './NodeParts'
import { serviceText } from './services'
import type { Issue, IssueState, Resolution, Service, TargetNode } from './types'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))
const VIEWS: IssueState[] = ['open', 'handled', 'gone']
/** A note is required for these: the next person must understand why the issue is not fixed. */
const NOTE_REQUIRED: readonly Resolution[] = ['accepted', 'not_relevant', 'false_positive']

/** Where an issue was found: "198.51.100.20:443 HTTPS", or the target as a whole. */
function useWhere(services: Service[] | undefined) {
  const { t } = useTranslation('exposure')
  const byId = new Map((services ?? []).map((s) => [s.id, s]))
  return (i: Issue) => {
    const s = i.service_id ? byId.get(i.service_id) : undefined
    return s ? `${s.ip}:${s.port} ${serviceText(s).name}` : i.service_id ? t('issues.onService') : t('issues.whole')
  }
}

/** Who handled an issue and how, from its stored fields: "Mitigated by ana@example.com (17 Nov): CSP set at the proxy". */
function HandledText({ i }: { i: Issue }) {
  const { t } = useTranslation()
  const label = useStatusLabel()
  if (i.state !== 'handled' || !i.resolution) return null
  const line = t('handled.line', { status: label(i.resolution, { until: i.accepted_until }), by: i.resolved_by ?? '?', date: fmtDayMonth(i.resolved_at) })
  return <span className="text-meta text-muted">{i.note ? t('handled.withNote', { line, note: i.note }) : line}</span>
}

/** The state of an issue that is not open: how it was handled, or since when the scans no longer report it. */
function IssueStatus({ i }: { i: Issue }) {
  const { t } = useTranslation('exposure')
  if (i.state === 'handled' && i.resolution) return <span className="grid gap-1"><StatusBadge code={i.resolution} until={i.accepted_until} /><HandledText i={i} /></span>
  if (i.state === 'gone') return <span className="text-meta text-muted">{t('issues.goneSince', { date: fmtDate(i.last_seen) })}</span>
  return null
}

/** The issues every engine reported on this target: open first, then handled and no longer seen, each a click from its details. */
export function IssuesPanel({ node }: { node: TargetNode }) {
  const q = useRows(node.id, 'issues')
  const services = useRows(node.id, 'services')
  return <QueryState query={q}>{(d) => <IssuesTable node={node} issues={d.items} services={services.data?.items} />}</QueryState>
}

function IssuesTable({ node, issues, services }: { node: TargetNode; issues: Issue[]; services: Service[] | undefined }) {
  const { t } = useTranslation('exposure')
  const operator = useCan('operator')
  const where = useWhere(services)
  const [params, setParams] = useSearchParams()
  const view: IssueState = VIEWS.find((v) => v === params.get('issues')) ?? 'open'
  // ?service=<id> (the issue count of a row on the Services tab) shows the issues of that one service
  const only = services?.find((s) => s.id === params.get('service')) ?? null
  const clearOnly = () => { const p = new URLSearchParams(params); p.delete('service'); setParams(p, { replace: true }); setSelected(new Set()) }
  const shown = only ? issues.filter((i) => i.service_id === only.id) : issues
  const setView = (v: IssueState) => { const p = new URLSearchParams(params); if (v === 'open') p.delete('issues'); else p.set('issues', v); setParams(p, { replace: true }); setSelected(new Set()) }
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set())
  const [handling, setHandling] = useState<string[] | null>(null)
  const [detail, setDetail] = useState<Issue | null>(null)
  const reopen = useReopenIssues()
  const opener = useRef<HTMLButtonElement | null>(null)
  const rows = shown.filter((i) => i.state === view)
  const count = (v: IssueState) => shown.filter((i) => i.state === v).length
  // Only rows of this view stay selected: a hidden row is never acted on.
  const picked = rows.filter((i) => selected.has(i.id)).map((i) => i.id)
  const toggle = (id: string, on: boolean) => setSelected((s) => { const n = new Set(s); if (on) n.add(id); else n.delete(id); return n })
  const selectable = operator && view !== 'gone' && rows.length > 0
  const doReopen = (ids: string[]) => reopen.mutate(ids, {
    onSuccess: (r) => { toast.success(t('issues.reopened', { count: r.reopened }) + (r.skipped ? ` ${t('issues.skippedReopen', { count: r.skipped })}` : '')); setSelected(new Set()); setDetail(null) },
    onError: (e) => toast.error(errMsg(e)),
  })
  const needOperator = operator ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const action = (i: Issue) => (i.state === 'open'
    ? <Button size="sm" disabled={!operator} title={needOperator} aria-label={t('issues.markOf', { title: i.title })} onClick={(e) => { e.stopPropagation(); opener.current = e.currentTarget; setHandling([i.id]) }}>{t('issues.mark')}</Button>
    : i.state === 'handled'
      ? <Button size="sm" disabled={!operator} title={needOperator} aria-label={t('issues.reopenOf', { title: i.title })} busy={reopen.isPending && reopen.variables?.length === 1 && reopen.variables[0] === i.id} busyLabel={t('issues.reopening')} onClick={(e) => { e.stopPropagation(); doReopen([i.id]) }}>{t('issues.reopen')}</Button>
      : null)
  const columns: ColumnDef<Issue>[] = [
    ...(selectable ? [{ id: 'select', enableSorting: false, header: () => (
      <Checkbox checked={rows.length > 0 && picked.length === rows.length ? true : picked.length > 0 ? 'indeterminate' : false}
        onCheckedChange={(v) => setSelected(v === true ? new Set(rows.map((r) => r.id)) : new Set())} aria-label={t('issues.selectAll', { count: rows.length })} />
    ), cell: ({ row }) => (
      <span onClick={(e) => e.stopPropagation()}><Checkbox checked={selected.has(row.original.id)} onCheckedChange={(v) => toggle(row.original.id, v === true)} aria-label={t('issues.select', { title: row.original.title })} /></span>
    ) } satisfies ColumnDef<Issue>] : []),
    { id: 'severity', header: t('issues.col.severity'), accessorFn: (i) => SEVERITY_RANK[i.severity], cell: ({ row }) => <SeverityBadge severity={row.original.severity} compact /> },
    { id: 'title', header: t('issues.col.issue'), accessorFn: (i) => i.title, cell: ({ row }) => (
      <span className="grid gap-0.5">
        <button type="button" className="w-fit text-left font-medium text-accent underline-offset-4 hover:underline" onClick={(e) => { e.stopPropagation(); setDetail(row.original) }}>{row.original.title}</button>
        <span className="text-caption text-muted">{t(`engine.${row.original.engine}`)} · {where(row.original)}</span>
      </span>
    ) },
    // The CVEs column only when an issue of this view names one
    ...(rows.some((i) => i.cves.length) ? [{ id: 'cves', header: t('issues.col.cves'), enableSorting: false, cell: ({ row }) => (row.original.cves.length
      ? <CveList items={row.original.cves.map((c) => ({ cve: c.cve, severity: c.severity }))} label={t('issues.cvesOf', { title: row.original.title })} />
      : <span className="text-muted">—</span>) } satisfies ColumnDef<Issue>] : []),
    { id: 'seen', header: t('issues.col.seen'), accessorFn: (i) => i.last_seen, cell: ({ row }) => <Seen i={row.original} /> },
    ...(view !== 'open' ? [{ id: 'state', header: t('issues.col.state'), enableSorting: false, cell: ({ row }) => <IssueStatus i={row.original} /> } satisfies ColumnDef<Issue>] : []),
    ...(view !== 'gone' ? [{ id: 'action', header: t('issues.col.action'), enableSorting: false, cell: ({ row }) => action(row.original) } satisfies ColumnDef<Issue>] : []),
  ]
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Segmented<IssueState> label={t('issues.view')} value={view} onChange={setView} options={VIEWS.map((v) => ({ value: v, label: t(`issues.views.${v}`, { count: count(v) }) }))} />
        {picked.length ? (
          <div role="region" aria-label={t('issues.selection')} className="flex flex-wrap items-center gap-2">
            <span className="text-meta font-medium">{t('issues.selected', { count: picked.length })}</span>
            {/* empty-guard: the bar shows only with a selection */}
            {view === 'open' ? <Button size="sm" variant="primary" onClick={(e) => { opener.current = e.currentTarget; setHandling(picked) }}>{t('issues.markSelected', { count: picked.length })}</Button>
              : <Button size="sm" variant="primary" busy={reopen.isPending} busyLabel={t('issues.reopening')} onClick={() => doReopen(picked)}>{t('issues.reopenSelected', { count: picked.length })}</Button>}
            <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>{t('issues.clearSelection')}</Button>
          </div>
        ) : null}
      </div>
      {only ? (
        <p className="flex flex-wrap items-center gap-2 text-meta">
          <span>{t('issues.onlyService', { where: `${only.ip}:${only.port}/${only.proto}` })}</span>
          <Button size="sm" variant="ghost" onClick={clearOnly}>{t('issues.allServices')}</Button>
        </p>
      ) : null}
      <DataTable urlKey="exposure-issues" resetPageOn={`${view}:${only?.id ?? ''}`} caption={t('issues.caption', { value: node.value })} data={rows} columns={columns} pageSize={25}
        initialSort={[{ id: 'severity', desc: false }]} onRowClick={setDetail}
        mobileRow={(i) => (
          <div className="grid gap-1.5">
            <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={i.severity} compact /><button type="button" className="text-left font-medium text-accent underline-offset-4 hover:underline" onClick={(e) => { e.stopPropagation(); setDetail(i) }}>{i.title}</button></div>
            <p className="text-meta text-muted">{t(`engine.${i.engine}`)} · {where(i)}</p>
            <Seen i={i} />
            <IssueStatus i={i} />
            <span>{action(i)}</span>
          </div>
        )}
        empty={<EmptyState title={t(`issues.empty.${view}`)}>{view === 'open' && !node.last_scan ? t('issues.emptyNever') : null}</EmptyState>} />
      {handling ? <HandleDialog ids={handling} subject={handling.length === 1 ? issues.find((i) => i.id === handling[0])?.title : undefined} onClose={() => { setHandling(null); setSelected(new Set()); setDetail(null) }} opener={opener} /> : null}
      <IssueDialog issue={detail} where={detail ? where(detail) : ''} onClose={() => setDetail(null)}
        onHandle={(i) => { setDetail(null); setHandling([i.id]) }} onReopen={(i) => doReopen([i.id])} reopening={reopen.isPending} />
    </div>
  )
}

const SEVERITY_RANK: Record<Issue['severity'], number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

/** One issue in full: what it is, how to fix it, where it was seen and its CVEs, with its one action. */
function IssueDialog({ issue: i, where, onClose, onHandle, onReopen, reopening }: { issue: Issue | null; where: string; onClose: () => void; onHandle: (i: Issue) => void; onReopen: (i: Issue) => void; reopening: boolean }) {
  const { t } = useTranslation('exposure')
  const operator = useCan('operator')
  const needOperator = operator ? undefined : t('common:needRole', { role: t('common:role.operator') })
  return (
    <Dialog open={i !== null} onOpenChange={(o) => { if (!o) onClose() }}>
      {i ? (
        <DialogContent wide title={i.title} description={<span className="flex flex-wrap items-center gap-2"><SeverityBadge severity={i.severity} compact />{t(`engine.${i.engine}`)} · {where}</span>}>
          <div className="grid gap-4 text-sm">
            {i.state !== 'open' ? <IssueStatus i={i} /> : null}
            {i.detail.description ? <p>{i.detail.description}</p> : null}
            {i.detail.solution ? <div className="grid gap-1"><p className="font-medium">{t('issues.solution')}</p><p>{i.detail.solution}</p></div> : null}
            {i.cves.length ? <CveList rows items={i.cves.map((c) => ({ cve: c.cve, severity: c.severity }))} label={t('issues.cvesOf', { title: i.title })} /> : null}
            <KeyValue items={[
              { label: t('issues.firstSeen'), value: fmtDateTime(i.first_seen) },
              { label: t('issues.lastSeen'), value: fmtDateTime(i.last_seen) },
              { label: t('issues.key'), value: <span className="font-mono text-meta [overflow-wrap:anywhere]">{i.key}</span> },
            ]} />
            {i.detail.evidence.length ? (
              <div className="grid gap-1">
                <p className="font-medium">{t('issues.evidence')}</p>
                {/* what the engine saw, as text: an address on the scanned host is not a link the page vouches for */}
                <ul className="grid gap-0.5">{i.detail.evidence.map((e) => <li key={e} className="font-mono text-meta [overflow-wrap:anywhere]">{e}</li>)}</ul>
              </div>
            ) : null}
          </div>
          <DialogFooter>
            {i.state === 'open' ? <Button variant="primary" disabled={!operator} title={needOperator} onClick={() => onHandle(i)}>{t('issues.mark')}</Button> : null}
            {i.state === 'handled' ? <Button variant="primary" disabled={!operator} title={needOperator} busy={reopening} busyLabel={t('issues.reopening')} onClick={() => onReopen(i)}>{t('issues.reopen')}</Button> : null}
          </DialogFooter>
        </DialogContent>
      ) : null}
    </Dialog>
  )
}

/** Mark one or more open issues as handled: patched, mitigated, accepted until a day, not relevant or a false positive, with a note. */
function HandleDialog({ ids, subject, onClose, opener }: { ids: string[]; subject?: string; onClose: () => void; opener: RefObject<HTMLButtonElement | null> }) {
  const { t } = useTranslation('exposure')
  const label = useStatusLabel()
  const handle = useHandleIssues()
  const [resolution, setResolution] = useState<Resolution>('patched')
  const [note, setNote] = useState('')
  const [until, setUntil] = useState('')
  const [error, setError] = useState<string | undefined>()
  const [untilError, setUntilError] = useState<string | undefined>()
  const accept = resolution === 'accepted'
  const needNote = NOTE_REQUIRED.includes(resolution)
  function submit() {
    const badUntil = accept && !untilOk(until)
    setUntilError(badUntil ? t('handle.untilRequired') : undefined)
    if (needNote && note.trim().length < 3) { setError(t('handle.noteRequired')); return }
    if (badUntil) return
    setError(undefined)
    handle.mutate({ ids, resolution, note: note.trim(), ...(accept ? { accepted_until: until } : {}) }, {
      onSuccess: (r) => { toast.success(t('handle.done', { count: r.handled }) + (r.skipped ? ` ${t('handle.skipped', { count: r.skipped })}` : '')); onClose() },
      onError: (e) => {
        const code = (e as { code?: string }).code
        if (code === 'bad_until') setUntilError(errMsg(e)); else setError(errMsg(e))
      },
    })
  }
  return (
    <Dialog open onOpenChange={(o) => { if (!o && !handle.isPending) onClose() }}>
      <DialogContent title={t('handle.title', { count: ids.length })} description={subject ? <><span className="font-medium text-ink">{subject}</span><br />{t('handle.description')}</> : t('handle.description')} onCloseAutoFocus={(e) => { e.preventDefault(); opener.current?.focus() }}>
        <RadioGroup value={resolution} onValueChange={(v) => { setResolution(v as Resolution); setError(undefined); setUntilError(undefined) }} aria-label={t('handle.how')}>
          {FINDING_RESOLUTIONS.map((r) => (
            <div key={r} className="flex items-start gap-2.5">
              <RadioItem id={`ex-handle-${r}`} value={r} className="mt-1" />
              <label htmlFor={`ex-handle-${r}`} className="grid text-sm"><span className="font-medium">{label(r)}</span><span className="text-meta text-muted">{t(`handle.hint.${r}`)}</span></label>
            </div>
          ))}
        </RadioGroup>
        {accept ? <AcceptUntil id="ex-handle-until" value={until} onChange={(v) => { setUntil(v); setUntilError(undefined) }} error={untilError} /> : null}
        <Field htmlFor="ex-handle-note" label={needNote ? t('handle.noteRequiredLabel') : t('handle.noteLabel')} error={error}>
          <Textarea id="ex-handle-note" value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} aria-invalid={!!error} aria-describedby={error ? 'ex-handle-note-error' : undefined} />
        </Field>
        <DialogFooter>
          <Button onClick={onClose} disabled={handle.isPending}>{t('common:cancel')}</Button>
          <Button variant="primary" busy={handle.isPending} busyLabel={t('common:busy.saving')} onClick={submit}>{t('handle.submit')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
