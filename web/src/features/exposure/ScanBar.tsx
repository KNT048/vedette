import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { ScanNowButton } from '@/features/scanning/ScanNow'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { isLive, useRows, useScanNode, useTree } from './api'
import { InfoLine } from '@/components/common/InfoLine'
import { boxIp, runHref } from './node'
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
  // The scan that records the confirmation asks first, in a dialog that shows the sentence and the scope: Scan now never records a
  // confirmation the person has not seen in front of the button they press. A deep scan asks first too, once, with the one warning
  // of what it can do to the network in front of the target (the same dialog when it also records the confirmation).
  const [confirming, setConfirming] = useState(false)
  function run() {
    scan.mutate({ id: node.id, noticeVersion: notice?.version }, {
      onSuccess: (s) => { setConfirming(false); toast.success(t(s.status === 'queued' ? 'run.queuedToast' : 'run.startedToast', { value: node.value })) },
      onError: (e) => { setConfirming(false); if ((e as { code?: string }).code !== 'twofa_required') toast.error(errMsg(e)) },
    })
  }
  const start = () => (notice || node.deep ? setConfirming(true) : run())
  return { scan, notice, needTwoStep, blocked, roleReason, run, start, confirming, setConfirming, live: isLive(node.last_scan) }
}
type Flow = ReturnType<typeof useScanFlow>

/** The header's Scan now: "Deep scan now" once the testing terms are accepted; locked with the reason while it cannot run. */
export function ScanButton({ node, flow }: { node: TargetNode; flow: Flow }) {
  const { t } = useTranslation('exposure')
  const { scope } = useScope(node)
  return (
    <>
      <ScanNowButton label={node.deep ? t('scan.deepButton') : t('scan.button')} onStart={flow.start} running={flow.live} pending={flow.scan.isPending && !flow.confirming} runningLabel={t('scan.running')}
        blocked={flow.blocked ?? flow.roleReason} describedBy={flow.blocked ? 'scan-reason' : undefined} />
      {flow.notice || node.deep ? (
        <Dialog open={flow.confirming} onOpenChange={(o) => { if (!o && !flow.scan.isPending) flow.setConfirming(false) }}>
          {flow.confirming && flow.notice ? (
            <DialogContent title={t('scan.confirmTitle', { value: node.value })} description={scope} info={<><p>{t('scan.noticeWho')}</p>{node.commitment ? <p>{t('scan.noticeChangedInfo')}</p> : null}</>}>
              {node.commitment ? <p className="text-meta text-muted">{t('scan.noticeChanged')}</p> : null}
              <p className="rounded-md border border-rule p-3 text-sm">{flow.notice.text}</p>
              {node.deep ? <p className="text-sm text-warn">{t('scan.deepLoad')}</p> : null}
              <DialogFooter>
                <Button disabled={flow.scan.isPending} onClick={() => flow.setConfirming(false)}>{t('common:cancel')}</Button>
                <Button variant="primary" busy={flow.scan.isPending} busyLabel={t('common:busy.starting')} onClick={flow.run}>{t('scan.confirmButton')}</Button>
              </DialogFooter>
            </DialogContent>
          ) : flow.confirming ? (
            <DialogContent title={t('scan.deepConfirmTitle', { value: node.value })} description={scope}>
              <p className="text-sm text-warn">{t('scan.deepLoad')}</p>
              <DialogFooter>
                <Button disabled={flow.scan.isPending} onClick={() => flow.setConfirming(false)}>{t('common:cancel')}</Button>
                <Button variant="primary" busy={flow.scan.isPending} busyLabel={t('common:busy.starting')} onClick={flow.run}>{t('scan.deepConfirmButton')}</Button>
              </DialogFooter>
            </DialogContent>
          ) : null}
        </Dialog>
      ) : null}
    </>
  )
}

/** Where the disruptive checks of a deep scan of node go, as the key of its sentence and the addresses it names. They run only on the
 *  box's own public IP (the backend's deepGate): never on a typed-in IP, nor on the box's IP behind carrier-grade NAT; a domain gets
 *  them only on its addresses that are the box's own (as its last scans saw them), the others get the deep scan without them. An
 *  address of kind "box" is one the box may port-scan, which a verified typed-in IP is too: it counts as the box's own only when the
 *  tree has it as an IP the box found (origin box) and not as a typed-in IP. Without the tree the rule is said, naming none. */
function disruptiveLine(node: TargetNode, addresses: { ip: string; class: string; family: string }[] | undefined, nodes: TargetNode[] | undefined): { key: string; ips?: string[] } {
  if (!node.terms?.disruptive) return { key: 'scan.deepNotDisruptive' }
  if (node.kind === 'domain') {
    if (!addresses || !nodes) return { key: 'scan.deepDomainDisruptiveRule' }
    const ipNodes = (ip: string) => nodes.filter((n) => n.kind === 'ip' && n.value === ip)
    const boxOwn = (ip: string) => { const ns = ipNodes(ip); return ns.some(boxIp) && !ns.some((n) => !boxIp(n)) }
    const own = [...new Set(addresses.filter((a) => a.class === 'box' && a.family === 'ipv4' && boxOwn(a.ip)).map((a) => a.ip))]
    const reached = own.filter((ip) => !ipNodes(ip).some((n) => n.terms_warning)) // behind carrier-grade NAT: not the box's to test
    if (reached.length > 0) return { key: 'scan.deepDomainDisruptiveOn', ips: reached }
    if (own.length > 0) return { key: 'scan.deepSharedNotDisruptive' }
    return { key: addresses.length > 0 ? 'scan.deepDomainDisruptiveNone' : 'scan.deepDomainDisruptiveRule' }
  }
  if (!boxIp(node)) return { key: 'scan.deepTypedNotDisruptive' }
  if (node.terms_warning) return { key: 'scan.deepSharedNotDisruptive' }
  return { key: 'scan.deepDisruptive' }
}

/** What Scan now does on this node, in one line: the deep scan the accepted terms allow (and where its disruptive checks go), or the
 *  safe scan; disruptive says whether any address of it gets them. */
function useScope(node: TargetNode): { scope: string; disruptive: boolean } {
  const { t } = useTranslation('exposure')
  const rows = useRows(node.id, 'addresses', { enabled: node.kind === 'domain' && node.deep && !!node.terms?.disruptive })
  const tree = useTree()
  if (!node.deep) return { scope: t('scan.safe'), disruptive: false }
  const deepKey = `scan.deep${node.kind === 'domain' ? 'Domain' : 'Ip'}`
  const d = disruptiveLine(node, rows.data?.items, tree.data?.items)
  const line = d.ips ? t(d.key, { ips: d.ips.join(', '), count: d.ips.length }) : t(d.key)
  return { scope: `${t(deepKey)} ${line}`, disruptive: ['scan.deepDisruptive', 'scan.deepDomainDisruptiveOn', 'scan.deepDomainDisruptiveRule'].includes(d.key) }
}

/** Under the header: why Scan now is refused or what it does, the confirmation it records, and the live or last scan with its run. */
export function ScanBar({ node, flow }: { node: TargetNode; flow: Flow }) {
  const { t } = useTranslation('exposure')
  const admin = useCan('admin')
  const tabHref = useTabHref()
  const deepKey = `scan.deep${node.kind === 'domain' ? 'Domain' : 'Ip'}`
  const { scope, disruptive } = useScope(node)
  return (
    <div className="-mt-3 mb-6 grid max-w-3xl gap-3">
      {flow.needTwoStep ? <p role="alert" className="text-sm text-warn">{t('scan.needTwoStep', { value: node.value })} <Link to="/settings/account?tab=sign-in#two-step" className="underline">{t('scan.needTwoStepLink')}</Link></p> : null}
      {flow.blocked ? <p id="scan-reason" className="text-sm text-warn">{flow.blocked}</p>
        : node.deep ? <InfoLine className="text-meta text-muted" topic={t('scan.scopeTopic')} info={<><p>{t(`${deepKey}Info`)}</p>{disruptive ? <p>{t('scan.deepDisruptiveInfo')}</p> : null}</>}>{scope}</InfoLine>
        : <p className="text-meta text-muted">{scope}{admin ? <> <Link to={tabHref('ownership', '#step-terms')} className={link}>{t('scan.acceptTerms')}</Link></> : null}</p>}
      {flow.notice ? <p className="text-meta text-muted">{t('scan.noticeFirst')}</p> : null}
      <LastScan node={node} />
    </div>
  )
}

/** The node's newest run: live with its state and Stop, or how it ended and what it left; its steps and log are on the run page. */
function LastScan({ node }: { node: TargetNode }) {
  const { t } = useTranslation('exposure')
  const s = node.last_scan
  if (!s) return null
  const when = s.started_at ?? s.queued_at
  const open = <Link className={link} to={runHref(s.run_id)}>{t('run.open')}</Link>
  if (isLive(s)) return null // a running scan is the Scans tab (its label reads Scanning)
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
