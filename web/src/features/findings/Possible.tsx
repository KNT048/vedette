// Possible findings (S-MIT-1): the CVEs of software a device runs that Vedette cannot decide (GET /findings/possible). They are
// counted apart from the open findings ("158 open findings · 16 possible") and shown after them: in By device one row per device,
// in By fix one row per product and version, on the device page the device's software lines. Each software line says the one input
// that would decide its CVEs (the version, the system, the package release) and each CVE says in plain words why it is undecided,
// with one answer menu (Affected, Not affected, Accept the risk), and one sentence names its cause (what would decide it). "Check N
// possible" reads the CVEs' vendor advisories on the box first and asks the AI only about the rest; with an AI provider set up, the box
// also does this by itself after each match pass. The AI reads the vendor's statement for the release line: affected (its quote found
// in the page) opens a finding labelled "Read by AI from <host>" that a person rejects in one click; not affected from the vendor's own
// page settles the CVE, except an exploited one, which a person confirms. What is settled is listed under "Checked, not affected", and a
// person can still say it is affected.
import { Fragment, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Bot, CircleHelp, ExternalLink, MoreHorizontal, ShieldCheck, type LucideIcon } from 'lucide-react'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { ExpandToggle, ListRow, RowList } from '@/components/common/ListParts'
import { InfoTip } from '@/components/common/InfoTip'
import { Notice } from '@/components/common/PageHeader'
import { QueryState } from '@/components/common/States'
import { SeverityBadge, StatusBadge } from '@/components/common/status'
import { Button } from '@/components/ui/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { fmtDate, fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { cn } from '@/lib/utils'
import { useQueryClient } from '@tanstack/react-query'
import { useDeviceAction } from '@/features/inventory/api'
import { VersionDialog } from '@/features/inventory/VersionDialog'
import { useAllPossible, useAnswer, useAnswered, useConfirmProposal, useIgnoreQuestions, usePossibleCheck, useRejectIdentity, useRejectProposal, useStartPossibleCheck, useUnanswer } from './api'
import { AcceptRiskDialog } from './AcceptRiskDialog'
import { AskDialog } from './AskDialog'
import { PAGE_MAX } from './contract'
import { errMsg } from './errors'
import { linkLabels } from './links'
import { DeviceLine, useDeviceRow } from './parts'
import type { AiIdentity, AnsweredQuestion, DeviceRef, PossibleCheck, PossibleCheckRun, PossibleCounts, PossibleRow, SoftwareRef } from './types'

/** At most this many evidence identities are checked per click (the server's limit). */
export const CHECK_MAX = 40
/** A software line shows this many CVEs before "Show all". */
const FIRST = 8

// ---- grouping

/** A row's key: a version_needed question carries several CVEs under one id. */
export const rowKey = (r: PossibleRow) => `${r.id}|${r.cve}`
/** One software line of one device and its possible CVEs, in the server's order (exploited first). */
export type PossibleLine = { key: string; device: DeviceRef; software: SoftwareRef | null; rows: PossibleRow[] }
/** The possible CVEs of one device, by software line. */
export type PossibleDevice = { device: DeviceRef; lines: PossibleLine[]; rows: PossibleRow[] }
/** One product at one version across devices (By fix). */
export type PossibleProduct = { key: string; name: string; version: string | null; lines: PossibleLine[]; rows: PossibleRow[] }

export function linesOf(rows: PossibleRow[]): PossibleLine[] {
  const m = new Map<string, PossibleLine>()
  for (const r of rows) {
    const key = `${r.device.id}|${r.software?.id ?? r.id}`
    let l = m.get(key)
    if (!l) { l = { key, device: r.device, software: r.software, rows: [] }; m.set(key, l) }
    l.rows.push(r)
  }
  return [...m.values()]
}
export function devicesOf(rows: PossibleRow[]): PossibleDevice[] {
  const m = new Map<string, PossibleDevice>()
  for (const l of linesOf(rows)) {
    let d = m.get(l.device.id)
    if (!d) { d = { device: l.device, lines: [], rows: [] }; m.set(l.device.id, d) }
    d.lines.push(l)
    d.rows.push(...l.rows)
  }
  // the device with the most exploited possible CVEs first, then the most CVEs, then the name
  return [...m.values()].sort((a, b) => exploitedOf(b.rows) - exploitedOf(a.rows) || b.rows.length - a.rows.length || a.device.name.localeCompare(b.device.name))
}
export function productsOf(rows: PossibleRow[]): PossibleProduct[] {
  const m = new Map<string, PossibleProduct>()
  for (const l of linesOf(rows)) {
    const name = l.software?.name ?? l.rows[0]!.cve
    const version = l.software?.version ?? null
    const key = `${name.toLowerCase()}|${version ?? ''}`
    let p = m.get(key)
    if (!p) { p = { key, name, version, lines: [], rows: [] }; m.set(key, p) }
    p.lines.push(l)
    p.rows.push(...l.rows)
  }
  return [...m.values()].sort((a, b) => exploitedOf(b.rows) - exploitedOf(a.rows) || b.rows.length - a.rows.length || a.name.localeCompare(b.name))
}
/** The device page's possible findings: where a device named in a possible list leads. */
const possibleOf = (device: string) => `/devices/${encodeURIComponent(device)}?tab=findings#possible`
const exploitedOf = (rows: PossibleRow[]) => rows.filter((r) => r.exploited).length
const proposalsOf = (rows: PossibleRow[]) => rows.filter((r) => r.state === 'proposal').length
const nameOf = (sw: SoftwareRef | null, fallback: string) => (sw ? (sw.version ? `${sw.name} ${sw.version}` : sw.name) : fallback)

function useRoles() {
  const { t } = useTranslation('findings')
  const operator = useCan('operator')
  const admin = useCan('admin')
  return {
    operator, admin,
    needOperator: operator ? undefined : t('common:needRole', { role: t('common:role.operator') }),
    needAdmin: admin ? undefined : t('common:needRole', { role: t('common:role.admin') }),
  }
}

// ---- small parts

/** A small label next to a CVE: what a check of its advisories says (AI checked, a proposal's verdict and class). */
function Chip({ tone, icon: Icon, children, title }: { tone: 'accent' | 'off' | 'ok'; icon?: LucideIcon; children: string; title?: string }) {
  const cls = { accent: 'border-accent/40 bg-accent-soft text-accent', off: 'border-rule bg-off-soft text-off', ok: 'border-ok/40 bg-ok-soft text-ok' }[tone]
  return (
    <span title={title} className={cn('inline-flex h-6 w-fit shrink-0 items-center gap-1 whitespace-nowrap rounded-sm border px-2 text-caption font-medium leading-none', cls)}>
      {Icon ? <Icon aria-hidden className="size-3.5 shrink-0" /> : null}{children}
    </span>
  )
}

/** The CVE is on an exploited list: the same badge as an exploited finding's. */
export function ExploitedChip() {
  return <StatusBadge code="exploited" />
}

/** What a check of the row's advisories says, as one label: "AI proposal: affected (confident)", "AI checked: unsure", "Not affected
 *  per the vendor's advisory". Nothing when the row has no check. */
export function CheckChip({ check }: { check: PossibleCheck | null }) {
  const { t } = useTranslation('findings')
  if (!check) return null
  const model = check.model ? t('possible.chip.model', { model: check.model }) : undefined
  const rd = check.reading
  if (rd) {
    const host = rd.host ?? t('possible.chip.theRecord')
    if (check.rejected) return <Chip tone="off" icon={Bot} title={model}>{t('possible.chip.readRejected')}</Chip>
    if (check.verdict === 'not_affected') return <Chip tone={check.confidence ? 'ok' : 'off'} icon={Bot} title={model}>{t('possible.chip.readNotAffected', { host })}</Chip>
    if (check.verdict === 'affected') return <Chip tone="accent" icon={Bot} title={model}>{t('possible.chip.readAffected', { host })}</Chip>
    if (rd.status === 'not_affected' && !rd.vendor_page && rd.quote_found) return <Chip tone="off" icon={Bot} title={model}>{t('possible.chip.readThirdParty', { host })}</Chip>
    return <Chip tone="off" icon={Bot} title={model}>{t(rd.quote_found ? 'possible.chip.readUndecided' : 'possible.chip.readUnverified', { host })}</Chip>
  }
  if (check.decided_by !== 'ai') return <Chip tone={check.verdict === 'not_affected' ? 'ok' : 'off'} icon={ShieldCheck}>{t(`possible.chip.advisory_${check.verdict}`)}</Chip>
  if (check.rejected) return <Chip tone="off" icon={Bot} title={model}>{t('possible.chip.rejected')}</Chip>
  if (check.verdict === 'unsure') return <Chip tone="off" icon={Bot} title={model}>{t('possible.chip.unsure')}</Chip>
  return <Chip tone="accent" icon={Bot} title={model}>{t(`possible.chip.proposal_${check.verdict}_${check.confidence ?? 'likely'}`)}</Chip>
}

/** "AI checked" on a finding or an answer a person confirmed from an AI proposal; the check (its reason, quote, pages and model) is
 *  behind the info icon. A finding the AI's reading opened says "Read by AI from <host>" and has its one-click Reject. */
export function AiCheckedBadge({ check }: { check: PossibleCheck }) {
  const { t } = useTranslation('findings')
  if (check.reading) return <AiReadBadge check={check} />
  return (
    <span className="inline-flex items-center gap-1" data-testid="ai-checked">
      <Chip tone="accent" icon={Bot} title={check.model ? t('possible.chip.model', { model: check.model }) : undefined}>{t('possible.aiChecked')}</Chip>
      <InfoTip topic={t('possible.aiCheckedTopic')}><CheckDetails check={check} /></InfoTip>
    </span>
  )
}

/** "Read by AI from <host>" on a finding the AI's reading of the vendor's statement opened: the reading behind the info icon. Its Reject
 *  is AiReadReject, among the page's actions. */
function AiReadBadge({ check }: { check: PossibleCheck }) {
  const { t } = useTranslation('findings')
  const host = check.reading?.host ?? t('possible.chip.theRecord')
  return (
    <span className="inline-flex items-center gap-1" data-testid="ai-read">
      <Chip tone="accent" icon={Bot} title={check.model ? t('possible.chip.model', { model: check.model }) : undefined}>{t('possible.aiRead', { host })}</Chip>
      <InfoTip topic={t('possible.aiReadTopic')}><CheckDetails check={check} /></InfoTip>
      {check.rejected ? <span className="text-meta text-muted">{t('possible.chip.readRejected')}</span> : null}
    </span>
  )
}

/** Reject of the AI's reading a finding rests on, in one click: the finding closes on every device of the line and the CVE is possible
 *  again. Nothing once the reading is rejected. */
export function AiReadReject({ check }: { check: PossibleCheck }) {
  const { t } = useTranslation('findings')
  const roles = useRoles()
  const reject = useRejectProposal()
  if (!check.reading || check.rejected) return null
  const host = check.reading.host ?? t('possible.chip.theRecord')
  return (
    <Button disabled={!roles.operator} title={roles.needOperator} busy={reject.isPending} busyLabel={t('common:busy.saving')}
      aria-label={t('possible.aiReadReject', { host })}
      onClick={() => reject.mutate({ key: check.key }, {
        onSuccess: () => toast.success(t('possible.aiReadRejected')),
        onError: (e) => toast.error(errMsg(e)),
      })}>{t('possible.aiReadRejectShort')}</Button>
  )
}

/** "Identified by AI as <title>" on a finding opened through the AI's identification of its software (no standard data names it): the
 *  AI's reason and model behind the info icon. Its "Not this product" is AiIdentityReject, among the page's actions. */
export function AiIdentityBadge({ identity }: { identity: AiIdentity }) {
  const { t } = useTranslation('findings')
  return (
    <span className="inline-flex items-center gap-1" data-testid="ai-identity">
      <Chip tone="accent" icon={Bot} title={identity.model ? t('possible.chip.model', { model: identity.model }) : undefined}>{t('identity.by', { title: identity.title })}</Chip>
      <InfoTip topic={t('identity.topic')}>
        <div className="grid gap-2">
          <p>{t('identity.info', { title: identity.title, product: `${identity.vendor}:${identity.product}` })}</p>
          {identity.reason ? <p className="text-meta text-muted">{t('identity.reason', { reason: identity.reason })}</p> : null}
          {identity.model ? <p className="text-meta text-muted">{t('possible.chip.model', { model: identity.model })}</p> : null}
        </div>
      </InfoTip>
    </span>
  )
}

/** "Not this product" in one click: the AI's identification is wrong for this software on every device; the findings resting on it
 *  close at once and that product is never offered for this software again. */
export function AiIdentityReject({ findingId, identity }: { findingId: string; identity: AiIdentity }) {
  const { t } = useTranslation('findings')
  const roles = useRoles()
  const reject = useRejectIdentity()
  return (
    <Button disabled={!roles.operator} title={roles.needOperator} busy={reject.isPending} busyLabel={t('common:busy.saving')}
      aria-label={t('identity.rejectOf', { title: identity.title })}
      onClick={() => reject.mutate({ id: findingId }, {
        onSuccess: () => toast.success(t('identity.rejected', { title: identity.title })),
        onError: (e) => toast.error(errMsg(e)),
      })}>{t('identity.reject')}</Button>
  )
}

/** What holds the CVE, and what would decide it, in one sentence. */
export function useCause() {
  const { t } = useTranslation('findings')
  return (r: PossibleRow) => (r.cause ? t(`possible.cause.${r.cause}`) : null)
}

/** Why the CVE is undecided, in plain words. */
export function useReason() {
  const { t } = useTranslation('findings')
  return (r: PossibleRow) => {
    const words = { software: r.software?.name ?? t('possible.theSoftware'), version: r.software?.version ?? '', line: r.line ?? r.software?.version ?? '', fixes: r.fixes.join(', ') }
    if (r.undecided.reason === 'eol_line_unlisted' && r.kind === 'older_line') return t(r.fixes.length ? 'possible.reason.older_line' : 'possible.reason.older_line_none', words)
    return t(`possible.reason.${r.undecided.reason}`, words)
  }
}

/** The pages a check read: a link per page that was read (the cited one first), with why the others were not. */
function Sources({ check }: { check: PossibleCheck }) {
  const { t } = useTranslation('findings')
  const pages = [...check.sources].sort((a, b) => Number(!!b.cited) - Number(!!a.cited))
  if (!pages.length) return <p className="text-meta text-muted">{t('possible.detail.noSources')}</p>
  const labels = linkLabels(t, pages.map((p) => p.url))
  return (
    <ul aria-label={t('possible.detail.sources')} className="grid gap-1">
      {pages.map((p, i) => (
        <li key={p.url} className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-meta">
          <a href={p.url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">
            {p.title || labels[i]}<ExternalLink aria-hidden className="size-3 shrink-0" />
          </a>
          {p.cited ? <span className="text-muted">{t('possible.detail.cited')}</span> : null}
          {p.status !== 'ok' ? <span className="text-muted">{t(`possible.detail.page_${p.status}`)}{p.note ? `: ${p.note}` : ''}</span> : null}
        </li>
      ))}
    </ul>
  )
}

/** The check behind one click: who checked and how, the reason, the sentence it rests on, the pages it read and the model. */
export function CheckDetails({ check }: { check: PossibleCheck }) {
  const { t } = useTranslation('findings')
  return (
    <div className="grid gap-2 border-l border-rule pl-3">
      <p className="text-meta text-muted">
        {t(`possible.detail.by_${check.decided_by}`, { date: fmtDate(check.checked_at), by: check.checked_by })}
        {check.model ? ` · ${t('possible.chip.model', { model: check.model })}` : ''}
      </p>
      {check.reason ? <p className="text-sm">{check.reason}</p> : null}
      {check.quote ? <blockquote className="border-l-2 border-accent/40 pl-3 text-sm italic [overflow-wrap:anywhere]">“{check.quote}”</blockquote> : null}
      <Sources check={check} />
    </div>
  )
}

/** What the person answers against: a stored check whose verdict is not the answer. The answer is kept; the person reads the
 *  evidence once before sending it. */
function Conflict({ check, answer }: { check: PossibleCheck | null; answer: 'affected' | 'not_affected' }) {
  const { t } = useTranslation('findings')
  if (!check || check.rejected || check.verdict === 'unsure' || check.verdict === answer) return null
  const cited = check.sources.find((s) => s.cited) ?? check.sources.find((s) => s.status === 'ok')
  return (
    <Notice tone="warn" role="note" className="mb-0" title={t(`possible.conflict.${check.decided_by === 'ai' ? 'ai' : 'advisory'}_${check.verdict}`)}>
      <span className="grid gap-1">
        {check.quote ? <span className="italic [overflow-wrap:anywhere]">“{check.quote}”</span> : check.reason ? <span>{check.reason}</span> : null}
        {cited ? <a href={cited.url} target="_blank" rel="noopener noreferrer" className="w-fit text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">{cited.title || cited.url}</a> : null}
        <span>{t('possible.conflict.kept')}</span>
      </span>
    </Notice>
  )
}

// ---- answers

type Answering = { kind: 'affected' | 'not_affected' | 'accept' }

/** The answer dialogs of one CVE. Affected needs a note saying what makes the person sure; Not affected says why; both show the
 *  evidence a check found when the answer contradicts it. */
function AnswerDialogs({ r, answering, onClose }: { r: PossibleRow; answering: Answering; onClose: () => void }) {
  const { t } = useTranslation('findings')
  const answer = useAnswer()
  const unanswer = useUnanswer()
  const words = { cve: r.cve, device: r.device.name }
  if (answering.kind === 'accept') {
    return <AcceptRiskDialog device={r.device} line={r.software} question={r.id} what={r.cve} count={1} onClose={onClose} />
  }
  const a = answering.kind
  // "not affected" leaves the list and no finding records it: the toast can take it back (it is also listed under Answered)
  const undo = a === 'not_affected' ? { label: t('possible.undo'), done: t('possible.askedAgain', words), run: () => unanswer.mutateAsync({ id: r.id }) } : undefined
  return (
    <AskDialog title={t(`possible.answer.${a}Title`, words)} description={t(`possible.answer.${a}Body`, words)} submit={t(`possible.answer.${a}`)}
      notice={<Conflict check={r.check} answer={a} />}
      done={t(`possible.answer.${a}Done`, words)} undo={undo} onClose={onClose}
      fields={[{ name: 'note', label: t(`possible.answer.${a}Note`), min: 3, max: 500, long: true }]}
      onSend={(v) => answer.mutateAsync({ id: r.id, answer: a, note: v.note ?? '' })} />
  )
}

/** One CVE's answers in one menu: Affected (an admin, as Confirm vulnerability), Not affected, Accept the risk. */
function AnswerMenu({ r, only }: { r: PossibleRow; only?: 'affected' }) {
  const { t } = useTranslation('findings')
  const roles = useRoles()
  const [answering, setAnswering] = useState<Answering | null>(null)
  const label = t('possible.answer.menuOf', { cve: r.cve, device: r.device.name })
  return (
    <>
      {only ? (
        <Button size="sm" disabled={!roles.admin} title={roles.needAdmin} aria-label={t('possible.answer.affectedOf', { cve: r.cve, device: r.device.name })}
          onClick={() => setAnswering({ kind: 'affected' })}>{t('possible.answer.affectedMenu')}</Button>
      ) : (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button size="sm" variant="ghost" aria-label={label} title={label}>{t('possible.answer.menu')}<MoreHorizontal /></Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem disabled={!roles.admin} title={roles.needAdmin} onSelect={() => setAnswering({ kind: 'affected' })}>{t('possible.answer.affectedMenu')}</DropdownMenuItem>
            <DropdownMenuItem disabled={!roles.operator} title={roles.needOperator} onSelect={() => setAnswering({ kind: 'not_affected' })}>{t('possible.answer.not_affectedMenu')}</DropdownMenuItem>
            <DropdownMenuItem disabled={!roles.admin} title={roles.needAdmin} onSelect={() => setAnswering({ kind: 'accept' })}>{t('possible.answer.acceptMenu')}</DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      )}
      {answering ? <AnswerDialogs r={r} answering={answering} onClose={() => setAnswering(null)} /> : null}
    </>
  )
}

/** Confirm or reject an AI proposal. Confirming "affected" records the finding (an admin, as answering affected); its confirmation
 *  level comes from who stated the version, never from the AI. Rejecting makes the CVE possible again. */
export function ProposalActions({ r }: { r: PossibleRow }) {
  const { t } = useTranslation('findings')
  const roles = useRoles()
  const confirm = useConfirmProposal()
  const reject = useRejectProposal()
  const check = r.check!
  const words = { cve: r.cve, device: r.device.name }
  const affected = check.verdict === 'affected'
  const may = affected ? roles.admin : roles.operator
  return (
    <>
      <Button size="sm" variant="primary" disabled={!may || reject.isPending} title={affected ? roles.needAdmin : roles.needOperator} busy={confirm.isPending} busyLabel={t('common:busy.saving')}
        aria-label={t(`possible.proposal.confirm_${check.verdict}Of`, words)}
        onClick={() => confirm.mutate({ id: r.id }, {
          onSuccess: () => toast.success(t(`possible.proposal.confirmed_${check.verdict}`, words)),
          onError: (e) => toast.error(errMsg(e)),
        })}>{t(`possible.proposal.confirm_${check.verdict}`)}</Button>
      <Button size="sm" disabled={!roles.operator || confirm.isPending} title={roles.needOperator} busy={reject.isPending} busyLabel={t('common:busy.saving')}
        aria-label={t('possible.proposal.rejectOf', words)}
        onClick={() => reject.mutate({ key: check.key }, {
          onSuccess: () => toast.success(t('possible.proposal.rejected', words)),
          onError: (e) => toast.error(errMsg(e)),
        })}>{t('possible.proposal.reject')}</Button>
    </>
  )
}

// ---- rows

/** One possible CVE: its link, severity, exploited, what a check says; why it is undecided; its answers (or the proposal's Confirm
 *  and Reject); the check's evidence behind one click. `device`: name the device (a product's rows across devices). */
export function PossibleCveRow({ r, settled = false }: { r: PossibleRow; settled?: boolean }) {
  const { t } = useTranslation('findings')
  const reason = useReason()
  const cause = useCause()
  const [open, setOpen] = useState(false)
  const panel = `possible-${rowKey(r).replace(/[^\w-]/g, '_')}`
  // a version_needed CVE is decided by the line's version, not one by one
  const perCve = r.kind !== 'version_needed'
  return (
    <ListRow testId="possible-row" title={r.cve} to={`/cve/${encodeURIComponent(r.cve)}`}
      toggle={r.check ? { open, onToggle: () => setOpen((o) => !o), controls: panel, label: t('possible.detail.toggleOf', { cve: r.cve }) } : null}
      badges={<><SeverityBadge severity={r.severity} compact />{r.exploited ? <ExploitedChip /> : null}<CheckChip check={r.check} /></>}
      meta={[
        // a version_needed CVE: the line already says the version decides it
        (settled && r.check) || !perCve ? null : reason(r),
        // the second line: the quote of what settled it, or what holds the CVE (its cause)
        settled ? (r.check?.quote ? <span key="quote" className="[overflow-wrap:anywhere]">“{r.check.quote}”</span> : null)
          : r.cause ? <span key="cause">
            <span data-testid="possible-cause" data-cause={r.cause}>{cause(r)}</span>
            {/* the automatic reading leaves it for now: until when and why, in plain words */}
            {r.held ? <> <span data-testid="possible-held" data-reason={r.held.reason}>
              {t('possible.held.line', { when: fmtDateTime(r.held.until), reason: t(`possible.held.reason.${r.held.reason}`) })}</span></> : null}
          </span> : null,
      ]}
      actions={r.state === 'proposal' && r.check ? <ProposalActions r={r} /> : settled ? <AnswerMenu r={r} only="affected" /> : perCve ? <AnswerMenu r={r} /> : null}>
      {open && r.check ? <div id={panel}><CheckDetails check={r.check} /></div> : null}
    </ListRow>
  )
}

/** The CVEs of a line: the first few, the rest behind "Show all". */
function Rows({ rows, label, settled = false }: { rows: PossibleRow[]; label: string; settled?: boolean }) {
  const { t } = useTranslation('findings')
  const [all, setAll] = useState(false)
  const shown = all ? rows : rows.slice(0, FIRST)
  return (
    <div className="grid gap-1">
      <RowList label={label}>
        {shown.map((r) => <PossibleCveRow key={rowKey(r)} r={r} settled={settled} />)}
      </RowList>
      {rows.length > FIRST ? (
        <Button size="sm" variant="ghost" className="-ml-2 w-fit" onClick={() => setAll((a) => !a)}>
          {all ? t('possible.showFewer') : t('possible.showAll', { count: rows.length })}
        </Button>
      ) : null}
    </div>
  )
}

// ---- a software line

type LineInput = 'version' | 'change_version' | 'system' | 'package' | null
/** The one input that decides a line's CVEs, by why its first CVE is undecided; null when only a per-CVE answer does. */
function inputOf(l: PossibleLine): LineInput {
  if (!l.software) return null
  const r = l.rows[0]!
  if (r.kind === 'version_needed' || r.undecided.reason === 'no_version') return 'version'
  if (r.undecided.reason === 'version_scheme_mismatch') return 'change_version'
  if (r.kind === 'platform' || r.undecided.reason === 'platform_unknown') return 'system'
  if (r.kind === 'package_release' || r.undecided.reason === 'package_unknown') return 'package'
  return null
}

/** The line's input in a dialog: the version (one value; the package release only on a distribution package), or the system the
 *  device runs. */
function LineInputDialog({ l, input, onClose }: { l: PossibleLine; input: Exclude<LineInput, null>; onClose: () => void }) {
  const { t } = useTranslation('findings')
  const act = useDeviceAction(l.device.id)
  const sw = l.software!
  if (input === 'system') {
    return (
      <AskDialog title={t('possible.line.systemTitle', { device: l.device.name })} description={t('possible.line.systemBody', { software: sw.name })} submit={t('possible.line.save')}
        done={t('possible.line.saved', { device: l.device.name })} onClose={onClose}
        fields={[{ name: 'os', label: t('possible.line.systemLabel'), placeholder: t('possible.line.systemPlaceholder'), max: 200 }]}
        onSend={(v) => act.patch.mutateAsync({ os: v.os! })} />
    )
  }
  return <VersionDialog sw={{ id: sw.id, display: sw.name, version: sw.version, package_line: input === 'package' }} assetId={l.device.id} onClose={onClose} />
}

/** Not affected for all (one step): every open question of a software line, or of the whole device. */
function IgnoreDialog({ device, line, count, onClose }: { device: DeviceRef; line: { id: string; name: string } | null; count: number; onClose: () => void }) {
  const { t } = useTranslation('findings')
  const ignore = useIgnoreQuestions()
  const words = { device: device.name, software: line?.name ?? '', count }
  return (
    <AskDialog title={line ? t('possible.bulk.lineTitle', words) : t('possible.bulk.deviceTitle', words)} description={t('possible.bulk.body', words)} submit={t('possible.bulk.submit')}
      done={line ? t('possible.bulk.lineDone', words) : t('possible.bulk.deviceDone', words)} onClose={onClose}
      fields={[{ name: 'note', label: t('possible.answer.not_affectedNote'), min: 3, max: 500, long: true }]}
      onSend={(v) => ignore.mutateAsync({ device: device.id, software: line?.id, note: v.note! })} />
  )
}

/** Not affected for all and Accept the risk of all, for a line or a device, in one menu (what most people never need). */
function BulkMenu({ device, line, count }: { device: DeviceRef; line: { id: string; name: string } | null; count: number }) {
  const { t } = useTranslation('findings')
  const roles = useRoles()
  const [doing, setDoing] = useState<'ignore' | 'accept' | null>(null)
  const label = line ? t('possible.bulk.menuLineOf', { software: line.name, device: device.name }) : t('possible.bulk.menuDeviceOf', { device: device.name })
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button size="icon" variant="ghost" aria-label={label} title={label}><MoreHorizontal /></Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem disabled={!roles.operator} title={roles.needOperator} onSelect={() => setDoing('ignore')}>{t('possible.bulk.ignore', { count })}</DropdownMenuItem>
          <DropdownMenuItem disabled={!roles.admin} title={roles.needAdmin} onSelect={() => setDoing('accept')}>{t('possible.bulk.accept', { count })}</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      {doing === 'ignore' ? <IgnoreDialog device={device} line={line} count={count} onClose={() => setDoing(null)} /> : null}
      {doing === 'accept' ? <AcceptRiskDialog device={device} line={line} what={line?.name ?? t('possible.bulk.everything')} count={count} onClose={() => setDoing(null)} /> : null}
    </>
  )
}

/** One software line: "Junos OS 15.1R7.9 · 12 possible CVEs · 2 exploited", the one input that decides them, then its CVEs.
 *  `withDevice`: name the device (By fix lists one product on several devices); `bulk` false: the device row's own menu already
 *  answers for its only line. */
export function LineBlock({ l, withDevice = false, bulk = true }: { l: PossibleLine; withDevice?: boolean; bulk?: boolean }) {
  const { t } = useTranslation('findings')
  const roles = useRoles()
  const [input, setInput] = useState<Exclude<LineInput, null> | null>(null)
  const name = nameOf(l.software, t('possible.theSoftware'))
  const need = inputOf(l)
  const exploited = exploitedOf(l.rows)
  const proposals = proposalsOf(l.rows)
  const deviceRow = useDeviceRow()
  return (
    <ListRow testId="possible-line" label={withDevice ? `${l.device.name}: ${name}` : name}
      {...(withDevice ? deviceRow(l.device, { badge: false, to: possibleOf(l.device.id) }) : { title: name })}
      meta={[
        <Fragment key="counts">
          <span>{t('possible.line.count', { count: l.rows.length })}</span>
          {exploited ? <span className="text-danger">{t('possible.line.exploited', { count: exploited })}</span> : null}
          {proposals ? <span className="text-accent">{t('possible.line.proposals', { count: proposals })}</span> : null}
        </Fragment>,
        need ? t(`possible.line.${need}Why`, { software: name, count: l.rows.length }) : null,
      ]}
      actions={<>
        {need ? (
          <Button size="sm" variant="primary" disabled={!roles.operator} title={roles.needOperator} aria-label={t(`possible.line.${need}Of`, { software: name, device: l.device.name })}
            onClick={() => setInput(need)}>{t(`possible.line.${need}`)}</Button>
        ) : null}
        {l.software && bulk ? <BulkMenu device={l.device} line={{ id: l.software.id, name }} count={l.rows.length} /> : null}
      </>}>
      <Rows rows={l.rows} label={t('possible.line.cvesOf', { software: name, device: l.device.name })} />
      {input ? <LineInputDialog l={l} input={input} onClose={() => setInput(null)} /> : null}
    </ListRow>
  )
}

// ---- the lists

/** One device of By device's possible list: its software lines, closed until clicked. */
function DeviceGroup({ d }: { d: PossibleDevice }) {
  const { t } = useTranslation('findings')
  const [open, setOpen] = useState(false)
  const panel = `possible-device-${d.device.id.replace(/[^\w-]/g, '_')}`
  const exploited = exploitedOf(d.rows)
  const proposals = proposalsOf(d.rows)
  const lines = d.lines.map((l) => `${nameOf(l.software, t('possible.theSoftware'))}: ${l.rows.length}`)
  const deviceRow = useDeviceRow()
  return (
    <ListRow label={t('possible.deviceOf', { device: d.device.name })} {...deviceRow(d.device, { badge: false, to: possibleOf(d.device.id) })}
      toggle={{ open, onToggle: () => setOpen((o) => !o), controls: panel, label: t('possible.toggleDevice', { device: d.device.name }) }}
      meta={[
        <Fragment key="counts">
          <span>{t('possible.cves', { count: d.rows.length })}</span>
          {exploited ? <span className="text-danger">{t('possible.line.exploited', { count: exploited })}</span> : null}
          {proposals ? <span className="text-accent">{t('possible.line.proposals', { count: proposals })}</span> : null}
        </Fragment>,
        <span key="lines" className="[overflow-wrap:anywhere]">{lines.join(' · ')}</span>,
      ]}
      actions={<BulkMenu device={d.device} line={null} count={d.rows.length} />}>
      {open ? (
        <RowList id={panel} label={t('possible.linesOf', { device: d.device.name })}>
          {d.lines.map((l) => <LineBlock key={l.key} l={l} bulk={d.lines.length > 1} />)}
        </RowList>
      ) : null}
    </ListRow>
  )
}

/** One product at one version of By fix's possible list: "Juniper Junos OS 15.1R7.9 · 12 possible CVEs on 1 device". */
function ProductGroup({ p }: { p: PossibleProduct }) {
  const { t } = useTranslation('findings')
  const [open, setOpen] = useState(false)
  const panel = `possible-product-${p.key.replace(/[^\w-]/g, '_')}`
  const name = p.version ? `${p.name} ${p.version}` : p.name
  const exploited = exploitedOf(p.rows)
  const devices = new Set(p.lines.map((l) => l.device.id)).size
  return (
    <ListRow label={name} title={name}
      toggle={{ open, onToggle: () => setOpen((o) => !o), controls: panel, label: t('possible.toggleProduct', { product: name }) }}
      meta={[
        <>
          <span>{t('possible.productCount', { count: p.rows.length, devices: t('byDevice.devices', { count: devices }) })}</span>
          {exploited ? <span className="text-danger">{t('possible.line.exploited', { count: exploited })}</span> : null}
        </>,
      ]}>
      {open ? (
        <RowList id={panel} label={t('possible.devicesOf', { product: name })}>
          {p.lines.map((l) => <LineBlock key={l.key} l={l} withDevice />)}
        </RowList>
      ) : null}
    </ListRow>
  )
}

/** " · 16 possible" after a list's count, a link to the Possible section below it; nothing at 0. */
export function PossibleLink({ count }: { count: number }) {
  const { t } = useTranslation('findings')
  if (!count) return null
  return <> · <a href="#possible" className="text-accent underline-offset-4 hover:underline">{t('possible.countLink', { count })}</a></>
}

/** The words a list's search reads. */
const searchText = (rows: PossibleRow[]) => [...new Set(rows.flatMap((r) => [r.cve, r.device.name, r.device.ip ?? '', r.software?.name ?? '', r.software?.version ?? '']))].join(' ')

/** "16 possible CVEs on 3 devices" and why they are apart. */
function useSummary() {
  const { t } = useTranslation('findings')
  return (counts: PossibleCounts, devices: number) => {
    const parts = [t('possible.summary', { count: counts.possible, devices: t('byDevice.devices', { count: devices }) })]
    if (counts.proposals) parts.push(t('possible.summaryProposals', { count: counts.proposals }))
    return parts.join(' · ')
  }
}

/** Scrolls the section into view when the page was opened at #possible (a device badge, Home), once its rows are there. */
function useScrollHere(ready: boolean) {
  const { hash } = useLocation()
  const done = useRef(false)
  useEffect(() => {
    if (!ready || done.current || hash !== '#possible') return
    done.current = true
    document.getElementById('possible')?.scrollIntoView?.({ block: 'start' })
  }, [ready, hash])
}

/** The Possible section of the Findings screen, after the open findings: by device (By device) or by product and version (By fix).
 *  `device` narrows it to one device. */
export function PossibleSection({ by, device = '' }: { by: 'device' | 'product'; device?: string }) {
  const { t } = useTranslation('findings')
  const q = useAllPossible({ device: device || undefined })
  const summary = useSummary()
  const rows = useMemo(() => q.data?.items ?? [], [q.data])
  const devices = useMemo(() => devicesOf(rows), [rows])
  const products = useMemo(() => productsOf(rows), [rows])
  useScrollHere(!!q.data)
  const counts = q.data?.counts
  const show = !!counts?.possible || q.isError
  return (
    <section id="possible" aria-label={t('possible.title')} className={cn('grid scroll-mt-4 gap-3', show && 'pt-4')}>
      {show ? (
        <>
          <h2 className="flex items-center gap-2 text-base font-semibold"><CircleHelp aria-hidden className="size-4 text-accent" />{t('possible.title')}</h2>
          <QueryState query={q}>
            {(d) => (
              <>
                <CheckRunLine />
                {by === 'device' ? (
                  <DataTable urlKey="possible" caption={t('possible.caption')} data={devices} pageSize={20}
                    columns={[{ id: 'text', header: t('byDevice.col'), accessorFn: (x: PossibleDevice) => searchText(x.rows) }] satisfies ColumnDef<PossibleDevice>[]}
                    list={(x) => <DeviceGroup d={x} />} resetPageOn={device}
                    summary={summary(d.counts, devices.length)} actions={<CheckPossible counts={d.counts} device={device || undefined} />} />
                ) : (
                  <DataTable urlKey="possible-fix" caption={t('possible.captionProduct')} data={products} pageSize={20}
                    columns={[{ id: 'text', header: t('possible.colProduct'), accessorFn: (x: PossibleProduct) => searchText(x.rows) }] satisfies ColumnDef<PossibleProduct>[]}
                    list={(x) => <ProductGroup p={x} />}
                    summary={summary(d.counts, devices.length)} actions={<CheckPossible counts={d.counts} />} />
                )}
              </>
            )}
          </QueryState>
        </>
      ) : null}
      {device ? <Settled device={device} /> : null}
      <Answered device={device} />
    </section>
  )
}

/** The device page's Possible section: the device's software lines with their possible CVEs, the check for this device, what was
 *  checked not affected, and the answers given. */
export function DevicePossible({ assetId }: { assetId: string }) {
  const { t } = useTranslation('findings')
  const q = useAllPossible({ device: assetId })
  const rows = useMemo(() => q.data?.items ?? [], [q.data])
  const lines = useMemo(() => linesOf(rows), [rows])
  useScrollHere(!!q.data)
  const counts = q.data?.counts
  if (!counts) return null
  return (
    <section id="possible" aria-label={t('possible.title')} className="grid gap-3">
      {counts.possible ? (
        <>
          <h2 className="flex items-center gap-2 text-base font-semibold"><CircleHelp aria-hidden className="size-4 text-accent" />{t('possible.title')}</h2>
          <CheckRunLine />
          <DataTable urlKey="device-possible" caption={t('possible.captionDevice')} data={lines} pageSize={20}
            columns={[{ id: 'text', header: t('possible.colProduct'), accessorFn: (l: PossibleLine) => searchText(l.rows) }] satisfies ColumnDef<PossibleLine>[]}
            list={(l) => <LineBlock l={l} />}
            summary={t('possible.summaryDevice', { count: counts.possible })} actions={<CheckPossible counts={counts} device={assetId} />} />
        </>
      ) : null}
      <Settled device={assetId} />
      <Answered device={assetId} />
    </section>
  )
}

// ---- checking

/** "Check 16 possible": the CVEs a check can still look at (vendor advisories first, the AI only for the rest), at most 40 per
 *  click; while it runs, how far it is. Without an AI profile the reason and the way to set one up. */
export function CheckPossible({ counts, device }: { counts: PossibleCounts; device?: string }) {
  const { t } = useTranslation('findings')
  const roles = useRoles()
  const state = usePossibleCheck()
  const start = useStartPossibleCheck()
  const s = state.data
  if (!s) return null
  if (s.run?.running) return <CheckProgress run={s.run} />
  if (!s.ready) {
    return (
      <span className="flex flex-wrap items-center gap-x-2 text-meta text-muted">
        {s.reason ?? t('possible.check.notReady')}
        <Link to="/settings/ai" className="text-accent underline-offset-4 hover:underline">{t('possible.check.setUp')}</Link>
      </span>
    )
  }
  const n = counts.unchecked
  const label = n > CHECK_MAX ? t('possible.check.someOf', { count: CHECK_MAX, total: n }) : t('possible.check.button', { count: n })
  return (
    <Button size="sm" variant="primary" disabled={!n || !roles.operator} title={!n ? t('possible.check.nothing') : roles.needOperator ?? t('possible.check.how')}
      busy={start.isPending} busyLabel={t('common:busy.starting')}
      onClick={() => start.mutate({ device }, { onSuccess: () => toast.info(t('possible.check.started')), onError: (e) => toast.error(errMsg(e)) })}>
      {label}
    </Button>
  )
}

function CheckProgress({ run }: { run: PossibleCheckRun }) {
  const { t } = useTranslation('findings')
  const pct = run.total ? Math.round((run.done / run.total) * 100) : 0
  return (
    <span className="flex items-center gap-2 text-meta text-muted" role="status" aria-live="polite">
      {t('possible.check.running', { done: run.done, total: run.total })}
      <span aria-hidden className="h-1.5 w-24 overflow-hidden rounded-full bg-rule">
        <span className="block h-full bg-accent" style={{ width: `${pct}%` }} />
      </span>
    </span>
  )
}

/** The last check's outcome, once it ended: how many the vendor advisories decided, how many AI proposals wait, and why it stopped. */
function CheckRunLine() {
  const { t } = useTranslation('findings')
  const run = usePossibleCheck().data?.run
  if (!run || run.running || !run.finished_at) return null
  return (
    <p className="text-meta text-muted">
      {t('possible.check.last', { date: fmtDate(run.finished_at), by: run.by, advisory: run.advisory, proposals: run.proposals, undecided: run.undecided })}
      {run.failed ? ` ${t('possible.check.failed', { failed: run.failed })}` : ''}
      {run.stopped ? ` ${t('possible.check.stopped', { why: run.stopped })}` : ''}
    </p>
  )
}

/** Says once, in a toast, that a check that ran in the background ended, and leads to its proposals; every list is read again. */
export function usePossibleCheckWatch() {
  const { t } = useTranslation('findings')
  const qc = useQueryClient()
  const navigate = useNavigate()
  const run = usePossibleCheck().data?.run
  const was = useRef<boolean | undefined>(undefined)
  useEffect(() => {
    const running = !!run?.running
    if (was.current === true && !running && run) {
      void qc.invalidateQueries({ queryKey: ['findings', 'model'] })
      void qc.invalidateQueries({ queryKey: ['inventory'] })
      const words = { advisory: run.advisory, proposals: run.proposals, undecided: run.undecided }
      if (run.proposals > 0) toast.success(t('possible.check.doneProposals', words), { action: { label: t('possible.check.review'), onClick: () => { void navigate('/findings?tab=proposals') } } })
      else toast.success(t('possible.check.done', words))
    }
    was.current = running
  }, [run, qc, t, navigate])
}

// ---- settled and answered

/** "Checked, not affected": what the box settled from a vendor's advisory on this device, exploited CVEs first. Visible behind one
 *  click and reversible: a person can still say a CVE affects the device (the evidence is shown in the dialog). */
function Settled({ device }: { device: string }) {
  const { t } = useTranslation('findings')
  const q = useAllPossible({ device, state: 'settled' })
  const [open, setOpen] = useState(false)
  const rows = useMemo(() => [...(q.data?.items ?? [])].sort((a, b) => Number(b.exploited) - Number(a.exploited)), [q.data])
  if (!rows.length) return null
  const exploited = exploitedOf(rows)
  return (
    <div className="grid gap-2" data-testid="settled">
      <ExpandToggle open={open} onToggle={() => setOpen((o) => !o)} controls="possible-settled">
        {exploited ? t('possible.settled.toggleExploited', { count: rows.length, exploited }) : t('possible.settled.toggle', { count: rows.length })}
      </ExpandToggle>
      {open ? (
        <div id="possible-settled" className="grid gap-1 sm:pl-6">
          <p className="text-meta text-muted">{t('possible.settled.body')}</p>
          <Rows rows={rows} settled label={t('possible.settled.caption')} />
        </div>
      ) : null}
    </div>
  )
}

/** One question answered "not affected": what it was, who answered, and Ask again. */
function AnsweredRow({ x }: { x: AnsweredQuestion }) {
  const { t } = useTranslation('findings')
  const roles = useRoles()
  const unanswer = useUnanswer()
  const what = x.cve ?? nameOf(x.software, t('possible.theSoftware'))
  const words = { cve: what, device: x.device.name }
  return (
    <ListRow title={what} to={x.cve ? `/cve/${encodeURIComponent(x.cve)}` : undefined}
      // a confirmed AI proposal says so, with its check
      badges={x.check?.decided_by === 'ai' && !x.check.rejected && x.check.verdict === 'not_affected' ? <AiCheckedBadge check={x.check} /> : null}
      meta={[
        <Fragment key="device"><DeviceLine device={x.device} badge={false} />{x.cve && x.software ? <span>{nameOf(x.software, '')}</span> : null}</Fragment>,
        t('possible.answered.by', { by: x.by, date: fmtDate(x.at) }),
      ]}
      actions={<Button size="sm" disabled={!roles.operator} title={roles.needOperator} busy={unanswer.isPending && unanswer.variables?.id === x.id} busyLabel={t('common:busy.saving')}
        aria-label={t('possible.answered.askAgainOf', words)}
        onClick={() => unanswer.mutate({ id: x.id }, { onSuccess: () => toast.success(t('possible.askedAgain', words)), onError: (e) => toast.error(errMsg(e)) })}>
        {t('possible.answered.askAgain')}
      </Button>} />
  )
}

/** The questions answered "not affected" (by a person, or a confirmed AI proposal), behind one click: a wrong answer is never final. */
function Answered({ device }: { device: string }) {
  const { t } = useTranslation('findings')
  const q = useAnswered({ device }, { offset: 0, limit: PAGE_MAX })
  const [open, setOpen] = useState(false)
  const total = q.data?.total ?? 0
  if (!total) return null
  return (
    <div className="grid gap-2" data-testid="answered">
      <ExpandToggle open={open} onToggle={() => setOpen((o) => !o)} controls="possible-answered">{t('possible.answered.toggle', { count: total })}</ExpandToggle>
      {open ? (
        <div id="possible-answered" className="grid gap-1 sm:pl-6">
          <RowList label={t('possible.answered.caption')}>
            {q.data!.items.map((x) => <AnsweredRow key={x.id} x={x} />)}
          </RowList>
          {total > q.data!.items.length ? <p className="text-meta text-muted">{t('possible.answered.more', { count: total - q.data!.items.length })}</p> : null}
        </div>
      ) : null}
    </div>
  )
}
