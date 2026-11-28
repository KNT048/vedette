// Review AI answers (S-MIT-1, S-AI-6): the AI's "not affected" answers about CVEs Vedette could not decide. Nothing closes until a person
// confirms: each row says the CVE, the device and software, the AI's quote and one evidence line (pages read, whether the box found the
// quote, tokens, model); "How it decided" opens the steps and pages. Confirm one, or tick many and confirm them together: an exploited
// CVE is left out of a bulk confirmation unless the person ticks "Include N exploited". Confirmed answers are listed under Handled,
// where each can be asked again. GET /findings/review, POST /findings/review/confirm.
import { Fragment, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ExternalLink } from 'lucide-react'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { ListRow, ListToolbar } from '@/components/common/ListParts'
import { EmptyState, QueryState } from '@/components/common/States'
import { SeverityBadge } from '@/components/common/status'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Select } from '@/components/ui/input'
import { useCan } from '@/lib/session'
import { useAiConfig } from '@/features/ai/api'
import { useConfirmReview, useRejectProposal, useReview } from './api'
import { errMsg } from './errors'
import { DeviceLine } from './parts'
import { Chip, ExploitedChip } from './Possible'
import { confidenceOf, CONFIDENCES, evidenceUrl, isInferred, modelOf, pagesRead, quoteChecked, researchOf, tokens, type Confidence } from './research'
import type { PossibleRow } from './types'

const keyOf = (r: PossibleRow) => `${r.id}|${r.cve}`
const softwareName = (r: PossibleRow) => (r.software ? (r.software.version ? `${r.software.name} ${r.software.version}` : r.software.name) : '')

/** The one evidence line of an AI answer: "3 pages read · quote checked · 4,210 tokens · qwen3:8b". */
export function EvidenceLine({ row }: { row: PossibleRow }) {
  const { t } = useTranslation('findings')
  const r = researchOf(row.check)
  if (!r) return <span>{t('review.evidence.none')}</span>
  const quote = row.check?.quote ? (quoteChecked(r) ? t('review.evidence.quoteChecked') : t('review.evidence.quoteNotFound')) : t('review.evidence.noQuote')
  const model = modelOf(r)
  return <span data-testid="review-evidence">{[t('review.evidence.pages', { count: pagesRead(r) }), quote, t('review.evidence.tokens', { count: r.tokens, formatted: tokens(r.tokens) }), model].filter(Boolean).join(' · ')}</span>
}

/** "How it decided": every layer that ran (model, how it read the web, pages, tokens, its own answer) and what it could not do. */
function HowItDecided({ row }: { row: PossibleRow }) {
  const { t } = useTranslation('findings')
  const r = researchOf(row.check)!
  const d = r.detail
  return (
    <div className="grid gap-2 border-l border-rule pl-3 text-meta">
      <p className="text-muted">{t('review.how.summary', { mode: d.mode, basis: t(`review.how.basis_${d.basis === 'inferred' ? 'inferred' : 'stated'}`) })}</p>
      {d.note ? <p>{d.note}</p> : null}
      <ol aria-label={t('review.how.steps')} className="grid gap-2">
        {d.steps.map((s, i) => (
          <li key={i} className="grid gap-1">
            <span className="font-medium text-ink">{t('review.how.step', { n: i + 1, layer: t(`review.how.layer_${s.layer}`), model: s.model })}</span>
            <span className="text-muted">
              {t(`review.how.web_${s.web}`)} · {t('review.evidence.tokens', { count: s.tokens_in + s.tokens_out, formatted: tokens(s.tokens_in + s.tokens_out) })}
              {s.verdict ? ` · ${t('review.how.answer', { verdict: s.verdict.replace('_', ' '), confidence: s.confidence || '-' })}` : ''}
            </span>
            {s.error ? <span className="text-muted">{s.error}</span> : null}
            {s.pages.length ? (
              <ul aria-label={t('review.how.pages')} className="grid gap-0.5">
                {s.pages.map((p) => (
                  <li key={p}>
                    <a href={p} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">{p}<ExternalLink aria-hidden className="size-3 shrink-0" /></a>
                  </li>
                ))}
              </ul>
            ) : null}
          </li>
        ))}
      </ol>
    </div>
  )
}

/** Confirm these answers: says how many, that an exploited CVE is named only on purpose, and what it records. */
function ConfirmDialog({ rows, includeExploited, onClose, onDone }: { rows: PossibleRow[]; includeExploited: boolean; onClose: () => void; onDone: () => void }) {
  const { t } = useTranslation('findings')
  const confirm = useConfirmReview()
  const exploited = rows.filter((r) => r.exploited)
  const send = () => confirm.mutate(
    { ids: [...new Set(rows.map((r) => r.id))], ...(includeExploited && exploited.length ? { include_exploited: [...new Set(exploited.map((r) => r.cve))] } : {}) },
    {
      onSuccess: (res) => {
        toast.success(t('review.done', { count: res.confirmed }))
        if (res.skipped.length) toast.warning(t('review.skipped', { count: res.skipped.length }))
        onDone()
      },
      onError: (e) => toast.error(errMsg(e)),
    },
  )
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('review.dialogTitle', { count: rows.length })} description={t('review.dialogBody', { count: rows.length })}>
        {exploited.length ? <p className="text-sm text-muted">{t('review.dialogExploited', { count: exploited.length })}</p> : null}
        <DialogFooter>
          <Button onClick={onClose}>{t('common:cancel')}</Button>
          {/* empty-guard: the dialog opens only for at least one answer */}
          <Button variant="primary" busy={confirm.isPending} busyLabel={t('common:busy.saving')} onClick={send}>{t('review.submit', { count: rows.length })}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

type RowProps = { r: PossibleRow; picked: boolean; onPick: (v: boolean) => void; onConfirm: () => void }

/** One AI answer: tick, the CVE and its badges, the evidence line, the quote and its page, Confirm and Not right?. */
function ReviewRow({ r, picked, onPick, onConfirm }: RowProps) {
  const { t } = useTranslation('findings')
  const operator = useCan('operator')
  const reject = useRejectProposal()
  const [open, setOpen] = useState(false)
  const check = r.check!
  const url = evidenceUrl(check)
  const panel = `review-${keyOf(r).replace(/[^\w-]/g, '_')}`
  const need = operator ? undefined : t('common:needRole', { role: t('common:role.operator') })
  return (
    <div className="flex items-start gap-3">
      <Checkbox className="mt-1.5" checked={picked} onCheckedChange={(v) => onPick(v === true)} aria-label={t('review.pick', { cve: r.cve, device: r.device.name })} />
      <div className="min-w-0 flex-1">
        <ListRow testId="review-row" label={t('review.rowOf', { cve: r.cve, device: r.device.name })} title={r.cve} to={`/cve/${encodeURIComponent(r.cve)}`}
          toggle={researchOf(check) ? { open, onToggle: () => setOpen((o) => !o), controls: panel, label: t('review.how.toggleOf', { cve: r.cve }) } : null}
          badges={<>
            <SeverityBadge severity={r.severity} compact />
            {r.exploited ? <ExploitedChip /> : null}
            {confidenceOf(check) ? <Chip tone={confidenceOf(check) === 'high' ? 'ok' : 'off'}>{t(`review.confidence_${confidenceOf(check)!}`)}</Chip> : null}
            {isInferred(check) ? <Chip tone="off" title={t('review.inferredTitle')}>{t('review.inferred')}</Chip> : null}
          </>}
          meta={[
            <Fragment key="what"><DeviceLine device={r.device} badge={false} />{r.software ? <span className="[overflow-wrap:anywhere]">{softwareName(r)}</span> : null}</Fragment>,
            <Fragment key="why">
              <EvidenceLine row={r} />
              {check.quote ? <span className="[overflow-wrap:anywhere]">“{check.quote}”</span> : <span>{check.reason || t('review.noQuote')}</span>}
              {url ? <a href={url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-accent underline-offset-4 hover:underline">{t('review.source')}<ExternalLink aria-hidden className="size-3" /></a> : null}
              {r.finding ? <Link to={`/findings/${encodeURIComponent(r.finding)}`} className="text-accent underline-offset-4 hover:underline">{t('review.wouldClose')}</Link> : null}
            </Fragment>,
          ]}
          actions={<>
            <Button size="sm" variant="primary" disabled={!operator} title={need} aria-label={t('review.confirmOf', { cve: r.cve, device: r.device.name })} onClick={onConfirm}>{t('review.confirm')}</Button>
            <Button size="sm" disabled={!operator} title={need} busy={reject.isPending} busyLabel={t('common:busy.saving')} aria-label={t('review.notRightOf', { cve: r.cve, device: r.device.name })}
              onClick={() => reject.mutate({ key: check.key }, { onSuccess: () => toast.success(t('review.rejected', { cve: r.cve })), onError: (e) => toast.error(errMsg(e)) })}>{t('review.notRight')}</Button>
          </>}>
          {open ? <div id={panel}><HowItDecided row={r} /></div> : null}
        </ListRow>
      </div>
    </div>
  )
}

const ALL = ''
type Filters = { device: string; software: string; confidence: '' | Confidence; evidence: '' | 'checked' | 'unchecked' }
const NONE: Filters = { device: ALL, software: ALL, confidence: ALL, evidence: ALL }

function applyFilters(rows: PossibleRow[], f: Filters): PossibleRow[] {
  return rows.filter((r) => (!f.device || r.device.id === f.device) && (!f.software || softwareName(r) === f.software)
    && (!f.confidence || confidenceOf(r.check) === f.confidence)
    && (!f.evidence || (f.evidence === 'checked') === (r.check?.reading?.quote_found ?? false)))
}

export function ReviewTab() {
  const { t } = useTranslation('findings')
  const operator = useCan('operator')
  const q = useReview()
  const config = useAiConfig()
  const [f, setF] = useState<Filters>(NONE)
  const [picked, setPicked] = useState<ReadonlySet<string>>(new Set())
  const [includeExploited, setIncludeExploited] = useState(false)
  const [asking, setAsking] = useState<{ rows: PossibleRow[]; include: boolean } | null>(null)
  const all = useMemo(() => (q.data?.items ?? []).filter((r) => r.check), [q.data])
  const rows = useMemo(() => applyFilters(all, f), [all, f])
  const devices = useMemo(() => [...new Map(all.map((r) => [r.device.id, r.device.name])).entries()].sort((a, b) => a[1].localeCompare(b[1])), [all])
  const softwares = useMemo(() => [...new Set(all.map(softwareName).filter(Boolean))].sort(), [all])
  const selected = rows.filter((r) => picked.has(keyOf(r)))
  const selectedExploited = selected.filter((r) => r.exploited)
  const toConfirm = selected.filter((r) => !r.exploited || includeExploited)
  const set = <K extends keyof Filters>(k: K, v: Filters[K]) => setF((p) => ({ ...p, [k]: v }))
  const pick = (r: PossibleRow, v: boolean) => setPicked((p) => { const n = new Set(p); if (v) n.add(keyOf(r)); else n.delete(keyOf(r)); return n })
  const allPicked = rows.length > 0 && selected.length === rows.length
  const columns: ColumnDef<PossibleRow>[] = [
    { id: 'text', header: t('review.col'), accessorFn: (r) => [r.cve, r.device.name, r.device.ip ?? '', softwareName(r), r.check?.quote ?? ''].join(' ') },
  ]
  const configured = config.data?.configured !== false
  return (
    <QueryState query={q}>
      {() => !all.length ? (
        <EmptyState title={t('review.empty')}>{configured ? t('review.emptyBody') : (
          <>{t('review.noAi')} <Link to="/settings/ai" className="text-accent underline underline-offset-4">{t('review.noAiLink')}</Link></>
        )}</EmptyState>
      ) : (
        <div className="grid gap-3">
          <ListToolbar label={t('review.filters')}>
            <Select aria-label={t('review.filterDevice')} value={f.device} onChange={(e) => set('device', e.target.value)}>
              <option value={ALL}>{t('review.anyDevice')}</option>
              {devices.map(([id, name]) => <option key={id} value={id}>{name}</option>)}
            </Select>
            <Select aria-label={t('review.filterSoftware')} value={f.software} onChange={(e) => set('software', e.target.value)}>
              <option value={ALL}>{t('review.anySoftware')}</option>
              {softwares.map((s) => <option key={s} value={s}>{s}</option>)}
            </Select>
            <Select aria-label={t('review.filterConfidence')} value={f.confidence} onChange={(e) => set('confidence', e.target.value as Filters['confidence'])}>
              <option value={ALL}>{t('review.anyConfidence')}</option>
              {CONFIDENCES.map((c) => <option key={c} value={c}>{t(`review.confidence_${c}`)}</option>)}
            </Select>
            <Select aria-label={t('review.filterEvidence')} value={f.evidence} onChange={(e) => set('evidence', e.target.value as Filters['evidence'])}>
              <option value={ALL}>{t('review.anyEvidence')}</option>
              <option value="checked">{t('review.evidenceChecked')}</option>
              <option value="unchecked">{t('review.evidenceUnchecked')}</option>
            </Select>
          </ListToolbar>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-md border border-rule bg-surface px-3 py-2 text-sm" data-testid="review-bar">
            <label className="flex items-center gap-2">
              <Checkbox checked={allPicked ? true : selected.length ? 'indeterminate' : false} disabled={!rows.length}
                onCheckedChange={(v) => setPicked(v === true ? new Set(rows.map(keyOf)) : new Set())} />
              {selected.length ? t('review.selected', { count: selected.length }) : t('review.selectAll', { count: rows.length })}
            </label>
            {selectedExploited.length ? (
              <label className="flex items-center gap-2">
                <Checkbox checked={includeExploited} onCheckedChange={(v) => setIncludeExploited(v === true)} />
                {t('review.includeExploited', { count: selectedExploited.length })}
              </label>
            ) : null}
            <Button size="sm" variant="primary" className="ml-auto" disabled={!operator || !toConfirm.length}
              title={operator ? (toConfirm.length ? undefined : t('review.nothingToConfirm')) : t('common:needRole', { role: t('common:role.operator') })}
              onClick={() => setAsking({ rows: toConfirm, include: includeExploited })}>{t('review.confirmSelected', { count: toConfirm.length })}</Button>
          </div>
          <DataTable urlKey="review" caption={t('review.caption')} data={rows} columns={columns} pageSize={25}
            summary={t('review.summary', { count: rows.length, exploited: rows.filter((r) => r.exploited).length })} filtered={rows.length !== all.length} onClearFilters={() => setF(NONE)}
            list={(r) => <ReviewRow r={r} picked={picked.has(keyOf(r))} onPick={(v) => pick(r, v)} onConfirm={() => setAsking({ rows: [r], include: r.exploited })} />} />
          {asking ? <ConfirmDialog rows={asking.rows} includeExploited={asking.include} onClose={() => setAsking(null)}
            onDone={() => { setPicked((p) => { const n = new Set(p); asking.rows.forEach((r) => n.delete(keyOf(r))); return n }); setAsking(null) }} /> : null}
        </div>
      )}
    </QueryState>
  )
}
