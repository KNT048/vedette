import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { AiBlock } from '@/components/common/AiBlock'
import { InfoTip } from '@/components/common/InfoTip'
import { Notice, KeyValue } from '@/components/common/PageHeader'
import { Card } from '@/components/common/Card'
import { Chip } from '@/components/common/StatusChip'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Select, Textarea } from '@/components/ui/input'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { errText, useApprove, usePlans, useReject, useRollback } from './api'
import { undoable } from './state'
import { ChangeView, ItemTag, RiskChip, StatusTag } from './parts'
import { useFrozen } from './frozen'
import type { ActionRequest, RequestItem } from './types'

function RejectDialog({ a, onClose }: { a: ActionRequest; onClose: () => void }) {
  const { t } = useTranslation('response')
  const reject = useReject()
  const [reason, setReason] = useState('')
  const [remember, setRemember] = useState<'none' | 'rule' | 'memory'>('none')
  const [error, setError] = useState<string | undefined>()
  return (
    <Dialog open onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent title={t('reject.title')} description={a.title}>
        <Field htmlFor={`rej-${a.id}`} label={t('reject.reason')} hint={a.source === 'ai' ? t('reject.reasonAi') : t('reject.reasonRule')} info={a.source === 'ai' ? t('reject.reasonAiInfo') : undefined}>
          <Textarea id={`rej-${a.id}`} className="min-h-20" maxLength={300} value={reason} onChange={(e) => setReason(e.target.value)} />
        </Field>
        {a.source === 'ai' ? (
          <Field htmlFor={`rem-${a.id}`} label={t('reject.remember')}>
            <Select id={`rem-${a.id}`} value={remember} onChange={(e) => setRemember(e.target.value as typeof remember)}>
              <option value="none">{t('reject.none')}</option><option value="memory">{t('reject.memory')}</option><option value="rule">{t('reject.rule')}</option>
            </Select>
          </Field>
        ) : null}
        {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
        <DialogFooter>
          <Button onClick={onClose}>{t('common:cancel')}</Button>
          <Button variant="danger" busy={reject.isPending} busyLabel={t('common:busy.rejecting')} onClick={() => reject.mutate({ id: a.id, reason, remember }, { onSuccess: () => { toast.success(t('action.rejectedToast')); onClose() }, onError: (e) => setError(errText(e)) })}>{t('action.reject')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** The undo line of an item. Once it ran, the undo time is the one the box set (`remove_at`): none means it is not undone automatically, for
 * example a change that was already on the device before this step. Before it runs, it is the planned `ttl_min`. */
function undoText(i: RequestItem, t: (k: string, o?: Record<string, unknown>) => string): string {
  if (i.status === 'executed') return i.remove_at ? t('request.undoAt', { time: fmtDateTime(i.remove_at) }) : i.reversible ? t('request.noAutoUndo') : t('request.noUndo')
  if (i.ttl_min) return t('request.undoAfter', { time: i.ttl_min >= 60 ? `${Math.round((i.ttl_min / 60) * 10) / 10} h` : `${i.ttl_min} min` })
  return i.reversible ? t('request.undoManual') : t('request.noUndo')
}

function Item({ i, pick, onPick }: { i: RequestItem; pick?: boolean; onPick?: (v: boolean) => void }) {
  const { t } = useTranslation('response')
  return (
    <li className="grid gap-2 rounded-md border border-rule bg-paper p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2.5">
          {onPick ? <Checkbox id={`pick-${i.id}`} checked={pick} onCheckedChange={(v) => onPick(v === true)} aria-label={t('request.pick', { title: i.title })} /> : null}
          <span className="text-sm font-medium">{i.title}</span>
        </div>
        <div className="flex flex-wrap items-center gap-2"><RiskChip risk={i.risk} /><ItemTag status={i.status} /></div>
      </div>
      <p className="text-meta text-muted">
        {i.connection ? t('request.via', { connection: i.connection }) : t('action.viaBox')}
        {' · '}{undoText(i, t)}
        {i.targets > 1 ? ` · ${t('request.targets', { count: i.targets })}` : ''}
      </p>
      {i.result ? <p className="text-meta"><span className="font-medium">{t('action.result')}:</span> {i.result}</p> : null}
      {i.state_unknown ? <p className="text-meta text-danger" role="note">{t('request.unknown')}</p> : null}
      {i.verified ? <p className="text-meta"><Chip tone={i.verified.ok ? 'ok' : 'danger'}>{i.verified.ok ? t('request.verifiedOk') : t('request.verifiedBad')}</Chip> {i.verified.detail}</p> : null}
      <details>
        <summary className="cursor-pointer text-meta text-accent">{t('proposal.exact')}</summary>
        <div className="mt-2"><ChangeView change={i.change} /></div>
      </details>
    </li>
  )
}

/** One bundled request (one per rule run or AI proposal): approve all or pick actions; high risk needs two different approvers. */
export function RequestCard({ a }: { a: ActionRequest }) {
  const { t } = useTranslation('response')
  const can = useCan('operator')
  const frozen = useFrozen() // Reject and Roll back stay, Approve does not
  // N-H1: rolling back a device change needs execution on (INV-7), which cannot be turned on again here: say where to undo it instead of a 409
  const execution = usePlans().data?.execution
  const onDevice = frozen && execution === false && a.items.some((i) => undoable(i) && i.reversible && i.connector_id !== null)
  const approve = useApprove()
  const rollback = useRollback()
  const [picked, setPicked] = useState<string[] | null>(null)
  const [code, setCode] = useState('')
  const [rejecting, setRejecting] = useState(false)
  const pending = a.status === 'pending'
  const first = a.approvals[0]
  const sel = picked ?? (first ? first.items : a.items.map((i) => i.id))
  const locked = !!first // the second approver approves what the first approved
  const role = !can ? t('common:needRole', { role: t('common:role.operator') }) : undefined
  const twoStep = !!a.ai?.in_app_only
  const go = (items?: string[]) => approve.mutate({ id: a.id, items, code }, {
    onSuccess: (r) => { toast.success(r.status === 'pending' ? t('request.recorded', { n: r.approvals.length, of: r.requires_approvals }) : t('action.approved')); setCode('') },
    onError: (e) => toast.error(errText(e)),
  })
  return (
    <Card className="grid gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold">{a.title}</h2>
        <div className="flex flex-wrap items-center gap-2">
          <Chip tone="off">{a.source === 'rule' ? t('action.fromRule') : a.source === 'person' ? t('action.fromPerson') : t('action.fromAi')}</Chip>
          <RiskChip risk={a.risk} />
          {a.requires_approvals > 1 ? <Chip tone="warn">{t('request.twoApprovers')}</Chip> : null}
          {a.pre_approved ? <Chip tone="danger">{t('request.preApproved')}</Chip> : null}
          <StatusTag status={a.status} />
        </div>
      </div>
      <KeyValue items={[
        ...(a.rule_name ? [{ label: t('action.rule'), value: a.rule_name }] : []),
        ...(a.trigger_summary && a.source !== 'ai' ? [{ label: t('request.because'), value: a.trigger_summary }] : []),
        { label: t('action.device'), value: a.asset_id ? <Link className="text-accent underline-offset-4 hover:underline" to={`/devices/${a.asset_id}`}>{a.asset_name}</Link> : a.asset_name },
        ...(a.finding_id ? [{ label: t('action.finding'), value: <Link className="text-accent underline-offset-4 hover:underline" to={`/findings/${a.finding_id}`}>{a.cve ?? a.finding_id}</Link> }] : []),
        { label: t('action.requested'), value: fmtDateTime(a.requested_at) },
        ...(pending ? [{ label: t('action.expires'), value: fmtDateTime(a.expires_at) }] : []),
        { label: t('action.sentTo'), value: a.sent_to.length ? a.sent_to.join(', ') : t('action.appOnly') },
        { label: t('request.approvals'), value: a.approvals.length ? a.approvals.map((p) => t('action.approverVia', { name: p.name, where: t(`via.${p.via}`), time: fmtDateTime(p.at) })).join('; ') + (pending && a.requires_approvals > 1 ? ` (${a.approvals.length}/${a.requires_approvals})` : '') : a.status === 'pending' ? t('action.noApprover') : t('request.none') },
        ...(a.two_because ? [{ label: t('request.whyTwo'), value: a.two_because }] : []),
        ...(a.note ? [{ label: t('action.note'), value: a.note }] : []),
      ]} />
      {a.ai ? (
        <AiBlock model={t('request.confidence', { n: a.ai.confidence.toFixed(2) })}>
          <p>{a.ai.why}</p>
          <ul className="ml-5 list-disc text-meta text-muted">{a.ai.evidence.map((e) => <li key={`${e.kind}-${e.id}`}>{t(`request.evidence.${e.kind}`)} <span className="font-mono text-caption">{e.id}</span>: {e.summary}</li>)}</ul>
          {a.ai.second_check ? <p className="text-meta"><Chip tone={a.ai.second_check.ok ? 'ok' : 'danger'}>{t('request.secondCheck')}</Chip> {a.ai.second_check.notes}</p> : null}
          {a.ai.in_app_only ? <div className="flex items-center gap-1"><p className="text-meta text-danger">{t('request.inAppOnly')}</p><InfoTip topic={t('request.code')}>{t('request.inAppOnlyInfo')}</InfoTip></div> : null}
        </AiBlock>
      ) : null}
      {a.email_links.length ? (
        <div className="grid gap-1 rounded-md border border-dashed border-rule bg-sunken p-3 text-meta">
          <div className="flex items-center gap-1"><p className="font-medium">{t('action.links')}</p><InfoTip topic={t('action.links')}>{t('action.linksHintInfo')}</InfoTip></div>
          <p className="text-muted">{t('action.linksHint')}</p>
          <ul className="grid gap-1">{a.email_links.map((l) => (
            <li key={l.url}>{l.approver} ({l.address}), {l.used ? t('action.linkUsed') : t('action.linkUntil', { time: fmtDateTime(l.expires_at) })}: <a className="break-all text-accent underline underline-offset-4" href={new URL(l.url).pathname}>{l.url}</a></li>
          ))}</ul>
        </div>
      ) : null}
      <ul className="grid gap-2">
        {a.items.map((i) => <Item key={i.id} i={i} pick={pending ? sel.includes(i.id) : undefined}
          onPick={pending && can && !frozen && !locked && a.items.length > 1 ? (v) => setPicked(v ? [...sel, i.id] : sel.filter((x) => x !== i.id)) : undefined} />)}
      </ul>
      {pending ? (
        <div className="grid gap-3">
          {first ? <p className="text-meta">{t('request.secondNeeded', { name: first.name })}</p> : null}
          {twoStep && !frozen ? (
            <Field htmlFor={`code-${a.id}`} label={t('request.code')} hint={t('request.codeHint')} info={t('request.codeInfo')} className="max-w-xs">
              <Input id={`code-${a.id}`} inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} />
            </Field>
          ) : null}
          <div className="flex flex-wrap gap-2">
            <Button variant="primary" disabled={!can || frozen || !sel.length} busy={approve.isPending} busyLabel={t('common:busy.approving')} title={frozen ? t('leaving.frozen') : role}
              aria-describedby={`approve-wait-${a.id}`} onClick={() => go(a.items.length > 1 && sel.length < a.items.length ? sel : undefined)}>
              {a.items.length > 1 ? (sel.length === a.items.length ? t('request.approveAll') : t('request.approveSelected', { count: sel.length })) : t('action.approve')}
            </Button>
            <Button disabled={!can} title={role} onClick={() => setRejecting(true)}>{t('action.reject')}</Button>
          </div>
          {/* The last approval makes the change on the device before it answers (up to 90 s for each change) */}
          <BusyNote id={`approve-wait-${a.id}`} busy={approve.isPending}>{t('action.approveWaiting')}</BusyNote>
        </div>
      ) : a.items.some(undoable) ? (
        <div className="flex flex-wrap items-center gap-3">
          <Button disabled={!can || onDevice} busy={rollback.isPending} busyLabel={t('action.rollingBack')} title={onDevice ? t('leaving.undoOnDevice') : role} aria-describedby={onDevice ? `undo-${a.id}` : `undo-wait-${a.id}`} onClick={() => rollback.mutate(a.id, { onSuccess: () => toast.success(t('action.rolledBackToast')), onError: (e) => toast.error(errText(e)) })}>{t('action.rollback')}</Button>
          {/* what to undo and where: the device above, each change under "Exact change and rollback" */}
          {onDevice ? <p id={`undo-${a.id}`} className="text-meta text-warn">{t('leaving.undoOnDevice')}</p> : null}
          {/* The rollback runs on the device before it answers (up to 90 s for each change) */}
          <BusyNote id={`undo-wait-${a.id}`} busy={rollback.isPending}>{t('action.rollbackWaiting')}</BusyNote>
        </div>
      ) : null}
      {rejecting ? <RejectDialog a={a} onClose={() => setRejecting(false)} /> : null}
    </Card>
  )
}
