import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { OctagonAlert } from 'lucide-react'
import { AiBlock } from '@/components/common/AiBlock'
import { CodeBlock } from '@/components/common/CodeBlock'
import { InfoTip } from '@/components/common/InfoTip'
import { KeyValue } from '@/components/common/PageHeader'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { useCan } from '@/lib/session'
import { errText, useEmergencyStop, useRequestApproval } from './api'
import { useFrozen } from './frozen'
import { ConfirmExecutionOff } from './Leaving'
import type { ActionStatus, Change, ItemStatus, Plan, Proposal, Risk } from './types'

const TONE: Record<ActionStatus, Tone> = { pending: 'warn', approved: 'accent', rejected: 'off', expired: 'off', executed: 'ok', failed: 'danger', rolled_back: 'accent' }
const RISK: Record<Risk, Tone> = { low: 'ok', medium: 'warn', high: 'danger' }
export const RiskChip = ({ risk }: { risk: Risk }) => { const { t } = useTranslation('response'); return <Chip tone={RISK[risk]}>{t(`catalog.risks.${risk}`)}</Chip> }
const ITEM_TONE: Record<ItemStatus, Tone> = { pending: 'warn', skipped: 'off', executed: 'ok', failed: 'danger', rolled_back: 'accent' }
export const ItemTag = ({ status }: { status: ItemStatus }) => { const { t } = useTranslation('response'); return <Chip tone={ITEM_TONE[status]}>{t(`item.${status}`)}</Chip> }
export const StatusTag = ({ status }: { status: ActionStatus }) => { const { t } = useTranslation('response'); return <Chip tone={TONE[status]}>{t(`status.${status}`)}</Chip> }

const restText = (r: NonNullable<Change['rest']>) => `${r.method} ${r.url}${Object.entries(r.headers).map(([k, v]) => `\n${k}: ${v}`).join('')}${r.body ? `\n\n${r.body}` : ''}`

export function ChangeView({ change }: { change: Change }) {
  const { t } = useTranslation('response')
  return (
    <div className="grid gap-2">
      <KeyValue items={[{ label: t('change.before'), value: change.before }, { label: t('change.after'), value: change.after }]} />
      {change.cli ? <CodeBlock code={change.cli} label={t('change.cli')} /> : null}
      {change.rest ? <CodeBlock code={restText(change.rest)} label={t('change.rest')} /> : null}
      {change.precheck ? <div className="grid gap-1"><CodeBlock code={change.precheck} label={t('change.precheck')} />{change.precheck_rules ? <p className="text-[13px] text-muted">{change.precheck_rules}</p> : null}</div> : null}
      {change.verify ? <div className="grid gap-1"><CodeBlock code={change.verify} label={t('change.verify')} />{change.verify_rule ? <p className="text-[13px] text-muted">{change.verify_rule}</p> : null}</div> : null}
      <div className="grid gap-1 border-t border-rule pt-2">
        <p className="text-sm font-medium">{t('change.rollback')}: {change.rollback.title}</p>
        {change.rollback.cli ? <CodeBlock code={change.rollback.cli} label={t('change.cli')} /> : null}
        {change.rollback.rest ? <CodeBlock code={restText(change.rollback.rest)} label={t('change.rest')} /> : null}
      </div>
    </div>
  )
}

/** The reason an action cannot be requested, in the owner's wording. */
function Blocked({ state }: { state: Proposal['state'] }) {
  const { t } = useTranslation('response')
  const admin = useCan('admin')
  const frozen = useFrozen() // D-624 (L2): no reason that invites turning something on; the request button already says why
  if (state === 'ready' || frozen) return null
  return (
    <div className="flex items-start gap-1 rounded-md border border-dashed border-rule bg-sunken px-3 py-2 text-[13px] text-muted">
      <p>{t(`blocked.${state}`)} {admin && state !== 'tool_unavailable' && state !== 'not_publishable' ?<Link className="text-accent underline underline-offset-4" to="/settings/response">{t('blocked.toSettings')}</Link> : null}</p>
      {state === 'not_publishable' ? <InfoTip topic={t('proposal.label')}>{t('blocked.not_publishableInfo')}</InfoTip> : null}
    </div>
  )
}

function ProposalView({ p }: { p: Proposal }) {
  const { t } = useTranslation('response')
  const frozen = useFrozen() // D-624: no new request from a plan
  const can = useCan('operator') && !frozen
  const req = useRequestApproval()
  return (
    <div className="grid gap-2 rounded-md border border-rule bg-paper p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm font-medium">{t('proposal.label')}: {p.title}</p>
        {p.request_id ? <Link className="text-[13px] text-accent underline underline-offset-4" to="/response?tab=requests">{t('proposal.requested')}</Link>
          : <Button size="sm" disabled={!can || p.state !== 'ready' || req.isPending} title={frozen ? t('leaving.frozen') : !can ? t('common:needRole', { role: t('common:role.operator') }) : undefined}
              onClick={() => req.mutate(p.id, { onSuccess: () => toast.success(t('proposal.sent')), onError: (e) => toast.error(errText(e)) })}>{t('proposal.request')}</Button>}
      </div>
      <p className="text-[13px] text-muted">{t('proposal.via', { connection: p.connection, tool: p.tool })}</p>
      <Blocked state={p.state} />
      <details>
        <summary className="cursor-pointer text-[13px] text-accent">{t('proposal.exact')}</summary>
        <div className="mt-2"><ChangeView change={p.change} /></div>
      </details>
    </div>
  )
}

/** AI plan (S-RESP-1): always in an AiBlock with the AI label and the profile name. */
export function PlanView({ plan, heading }: { plan: Plan; heading?: boolean }) {
  const { t } = useTranslation('response')
  return (
    <div className="grid gap-2">
      {heading ? <h3 className="text-sm font-semibold"><Link className="text-accent underline-offset-4 hover:underline" to={`/findings/${plan.finding_id}`}>{plan.cve}</Link> · <Link className="text-accent underline-offset-4 hover:underline" to={`/devices/${plan.asset_id}`}>{plan.asset_name}</Link></h3> : null}
      <AiBlock model={`${plan.model} (${plan.profile})`}>
        <p>{plan.path}</p>
        {plan.reads.length ? <ul className="ml-5 list-disc text-[13px] text-muted">{plan.reads.map((r) => <li key={r.tool}>{t('plan.read', { connection: r.connection, tool: r.tool })} {r.summary}</li>)}</ul> : null}
        <ol className="grid gap-3">
          {plan.steps.map((s, i) => (
            <li key={i} className="grid gap-1.5">
              <p><span className="font-medium">{i + 1}. {s.title}</span> <span className="text-[12px] text-muted">({t(`plan.kind.${s.kind}`)})</span></p>
              <p className="text-[13px]">{s.detail}</p>
              {s.proposal ? <ProposalView p={s.proposal} /> : null}
            </li>
          ))}
        </ol>
        {plan.sent_to.length ? <p className="text-[13px] text-muted">{t('plan.sentTo', { channels: plan.sent_to.join(', ') })}</p> : null}
      </AiBlock>
    </div>
  )
}

/** Always visible while execution is on (D-41). Anyone operator or above can press it. */
export function EmergencyStop() {
  const { t } = useTranslation('response')
  const can = useCan('operator')
  const stop = useEmergencyStop()
  const frozen = useFrozen() // D-624 (N-H1): on a box where it is not offered, stopping is one-way for device changes: confirm first
  const [ask, setAsk] = useState(false)
  const go = () => stop.mutate(undefined, { onSuccess: (r) => { setAsk(false); toast.success(t('stop.done', { count: r.cancelled })) }, onError: (e) => { setAsk(false); toast.error(errText(e)) } })
  return (
    <>
      <Button variant="danger" disabled={!can || stop.isPending} title={!can ? t('common:needRole', { role: t('common:role.operator') }) : undefined}
        onClick={() => (frozen ? setAsk(true) : go())}>
        <OctagonAlert className="size-4" aria-hidden />{t('stop.button')}
      </Button>
      {frozen ? <ConfirmExecutionOff open={ask} onOpenChange={setAsk} title={t('leaving.stopTitle')} confirmLabel={t('stop.button')} busy={stop.isPending} onConfirm={go} /> : null}
    </>
  )
}
