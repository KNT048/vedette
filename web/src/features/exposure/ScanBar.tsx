import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Square } from 'lucide-react'
import { InfoTip } from '@/components/common/InfoTip'
import { Button } from '@/components/ui/button'
import { ScanNowButton } from '@/features/scanning/ScanNow'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { isLive, useScanNode, useStopRun } from './api'
import { InfoLine } from '@/components/common/InfoLine'
import { runHref } from './node'
import { RunState, useTabHref } from './NodeParts'
import type { TargetNode } from './types'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))
const link = 'font-medium text-accent underline-offset-4 hover:underline'

/**
 * Scan now of one node, shared by its button and the line under the header. An administrator's first Scan now is the scan
 * confirmation: the sentence (version and text) comes from the API, is shown beside the button as received, and is sent back.
 */
export function useScanFlow(node: TargetNode) {
  const { t } = useTranslation('exposure')
  const admin = useCan('admin')
  const operator = useCan('operator')
  const scan = useScanNode()
  const notice = node.blocked === 'no_commitment' && admin ? node.commitment_notice : null
  // The page cannot tell an SSO sign-in (the identity provider owns MFA) from no two-step, so the server decides and the refusal is shown with the way out.
  const needTwoStep = !!notice && scan.isError && (scan.error as { code?: string }).code === 'twofa_required'
  const blocked = notice ? null : node.blocked ? t(`blocked.long.${node.blocked}`, { value: node.value }) : null
  const roleReason = operator ? null : t('common:needRole', { role: t('common:role.operator') })
  function run() {
    scan.mutate({ id: node.id, noticeVersion: notice?.version }, {
      onSuccess: (s) => toast.success(t(s.status === 'queued' ? 'run.queuedToast' : 'run.startedToast', { value: node.value })),
      onError: (e) => { if ((e as { code?: string }).code !== 'twofa_required') toast.error(errMsg(e)) },
    })
  }
  return { scan, notice, needTwoStep, blocked, roleReason, run, live: isLive(node.last_scan) }
}
type Flow = ReturnType<typeof useScanFlow>

/** The header's Scan now: "Deep scan now" once the testing terms are accepted; locked with the reason while it cannot run. */
export function ScanButton({ node, flow }: { node: TargetNode; flow: Flow }) {
  const { t } = useTranslation('exposure')
  return (
    <ScanNowButton label={node.deep ? t('scan.deepButton') : t('scan.button')} onStart={flow.run} running={flow.live} pending={flow.scan.isPending} runningLabel={t('scan.running')}
      blocked={flow.blocked ?? flow.roleReason} describedBy={flow.blocked ? 'scan-reason' : flow.notice ? 'scan-notice' : undefined} />
  )
}

/** Under the header: why Scan now is refused or what it does, the confirmation it records, and the live or last scan with its run. */
export function ScanBar({ node, flow }: { node: TargetNode; flow: Flow }) {
  const { t } = useTranslation('exposure')
  const admin = useCan('admin')
  const tabHref = useTabHref()
  const deepKey = `scan.deep${node.kind === 'domain' ? 'Domain' : 'Ip'}`
  const scope = node.deep ? `${t(deepKey)} ${t(node.terms?.disruptive ? 'scan.deepDisruptive' : 'scan.deepNotDisruptive')}` : t('scan.safe')
  return (
    <div className="-mt-3 mb-6 grid max-w-3xl gap-3">
      {flow.needTwoStep ? <p role="alert" className="text-sm text-warn">{t('scan.needTwoStep', { value: node.value })} <Link to="/settings/account?tab=sign-in#two-step" className="underline">{t('scan.needTwoStepLink')}</Link></p> : null}
      {flow.blocked ? <p id="scan-reason" className="text-sm text-warn">{flow.blocked}</p>
        : node.deep ? <InfoLine className="text-meta text-muted" topic={t('scan.scopeTopic')} info={<><p>{t(`${deepKey}Info`)}</p>{node.terms?.disruptive ? <p>{t('scan.deepDisruptiveInfo')}</p> : null}</>}>{scope}</InfoLine>
        : <p className="text-meta text-muted">{scope}{admin ? <> <Link to={tabHref('ownership', '#step-terms')} className={link}>{t('scan.acceptTerms')}</Link></> : null}</p>}
      {flow.notice ? (
        <div id="scan-notice" role="note" aria-label={t('scan.noticeTitle')} className="rounded-md border border-line p-3 text-sm">
          <div className="mb-1 flex items-center gap-1">
            <p className="font-medium">{t('scan.noticeTitle')}</p>
            <InfoTip topic={t('scan.noticeTitle')}>{node.commitment ? <p>{t('scan.noticeChangedInfo')}</p> : null}<p>{t('scan.noticeWho')}</p></InfoTip>
          </div>
          {node.commitment ? <p className="mb-1 text-meta text-muted">{t('scan.noticeChanged')}</p> : null}
          <p>{flow.notice.text}</p>
        </div>
      ) : null}
      <LastScan node={node} />
    </div>
  )
}

/** The node's newest run: live with its state and Stop, or how it ended and what it left; its steps and log are on the run page. */
function LastScan({ node }: { node: TargetNode }) {
  const { t } = useTranslation('exposure')
  const operator = useCan('operator')
  const stop = useStopRun()
  const s = node.last_scan
  if (!s) return null
  const when = s.started_at ?? s.queued_at
  const open = <Link className={link} to={runHref(s.run_id)}>{t('run.open')}</Link>
  if (isLive(s)) {
    return (
      <div role="status" className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
        <RunState scan={s} />
        <span>{s.status === 'queued' || s.status === 'waiting' ? t('run.queuedAt', { time: fmtDateTime(s.queued_at) }) : t('run.startedAt', { time: fmtDateTime(when), mode: t(`run.mode.${s.mode}`) })}</span>
        {s.waiting_for ? <span className="text-meta text-muted">{t('run.waitingFor', { what: s.waiting_for })}</span> : null}
        {open}
        {s.status !== 'stopping' ? (
          <Button size="sm" disabled={!operator} title={operator ? undefined : t('common:needRole', { role: t('common:role.operator') })} busy={stop.isPending} busyLabel={t('run.stopping')}
            onClick={() => stop.mutate(s.run_id, { onSuccess: () => toast.success(t('run.stoppedToast', { value: node.value })), onError: (e) => toast.error(errMsg(e)) })}>
            <Square />{t('run.stop')}
          </Button>
        ) : null}
      </div>
    )
  }
  const c = s.counts
  const result = c ? t('run.result', { services: c.services, newServices: c.new_services, closed: c.closed_services, issues: c.issues, newIssues: c.new_issues }) : null
  return (
    <div className="grid gap-1 text-meta">
      <p className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <span title={fmtDateTime(when)}>{t('run.last', { time: fmtRelative(when) })}</span>
        {s.status !== 'done' ? <RunState scan={s} /> : null}
        {result ? <span className="text-muted">{result}</span> : null}
        {open}
      </p>
      {s.error || s.stop_reason ? <p className={s.status === 'failed' ? 'text-danger' : 'text-muted'}>{s.error ?? s.stop_reason}</p> : null}
    </div>
  )
}
