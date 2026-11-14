import { useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ArrowLeft, Play, Trash2 } from 'lucide-react'
import { Notice, PageHeader, Section } from '@/components/common/PageHeader'
import { PageTabs } from '@/components/common/PageFrame'
import { QueryState, RequireModule } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { dateTimeText } from './dates'
import { useCan } from '@/lib/session'
import { useDeleteTarget, useScan, useScanRun, useTarget } from './api'
import { AnchorRedirect, ScrollToHash } from './anchors'
import { ScanProgress } from './ScanProgress'
import { CommitmentPanel } from './CommitmentPanel'
import { CommitChip, OwnerChip } from './OwnerChip'
import { RemoveDialog } from './RemoveDialog'
import { OutsidePanel } from './OutsidePanel'
import { ResultsPanel } from './ResultsPanel'
import { VerifyPanel } from './VerifyPanel'
import type { Target } from './types'
import { blockedKey } from './types'

// Old #anchor → tab (before the tabs these were stacked blocks of one page).
const ANCHOR_TAB: Record<string, string> = { 'step-verify': 'ownership', 'step-commit': 'ownership', results: 'results', compare: 'results', outside: 'outside' }

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

export default function TargetPage() {
  const { t } = useTranslation('exposure')
  const { id = '' } = useParams()
  const q = useTarget(id)
  return (
    <RequireModule module="exposure">
      <Link to="/exposure" className="mb-3 inline-flex items-center gap-1 text-[13px] text-muted hover:text-ink"><ArrowLeft className="size-3.5" />{t('target.back')}</Link>
      <QueryState query={q}>{(tg) => <TargetView target={tg} />}</QueryState>
    </RequireModule>
  )
}

function TargetView({ target }: { target: Target }) {
  const { t } = useTranslation('exposure')
  const operator = useCan('operator')
  const scan = useScan()
  const [params, setParams] = useSearchParams()
  const running = useScanRun().data?.status === 'running'
  const admin = useCan('admin')
  // D-473: an administrator's first Scan now is the D-26 confirmation. The sentence (version and text) comes from the API and is shown beside the button as received.
  const notice = target.blocked_reason === 'no_commitment' && admin ? target.commitment_notice : null
  // The page cannot tell an SSO sign-in (the identity provider owns MFA) from no two-step, so the server decides and the refusal is shown here with the way out.
  const needTwoStep = !!notice && scan.isError && (scan.error as { code?: string }).code === 'twofa_required'
  const blocked = notice ? null : target.blocked_reason ? t(`blocked.reasonLong.${blockedKey(target)}`, { value: target.value }) : null
  const roleReason = !operator ? t('common:needRole', { role: t('common:role.operator') }) : null
  const c = target.latest
  const title = target.blocked_reason && !notice ? t(`target.title.${blockedKey(target)}`, { value: target.value })
    : c ? (target.kind === 'domain' ? t('target.title.result', { value: target.value, subs: c.subdomains, admin: c.admin_panels }) : t('target.title.resultIp', { value: target.value, ports: c.ports, admin: c.admin_panels }))
    : t('target.title.ready', { value: target.value })

  // The person has something to do on the Ownership tab: prove ownership, or the proof expired or went missing.
  const needsOwnership = target.status === 'unverified' || target.validity === 'expired' || target.blocked_reason === 'txt_missing'

  // A paused or blocked ownership is a page-level state: it shows above the tabs whatever tab is open.
  const stateNotice = target.kind === 'domain' ? (target.status !== 'unverified' && target.blocked_reason === 'txt_missing' ? t('verify.txtMissing') : null)
    : target.blocked_reason === 'ip_not_current' ? t('verify.paused', { time: dateTimeText(target.verified_at) })
    : target.validity === 'expired' ? t('verify.ipExpired') : null

  function run() {
    scan.mutate({ id: target.id, noticeVersion: notice?.version }, {
      // After Scan now the person wants the results, not the tab they pressed it from.
      onSuccess: () => { const p = new URLSearchParams(params); p.set('tab', 'results'); setParams(p, { replace: true }) },
      onError: (e) => { if ((e as { code?: string }).code !== 'twofa_required') toast.error(errMsg(e)) },
    })
  }
  return (
    <>
      <PageHeader title={title} stories={['S-EXP-1']}
        meta={<span className="flex flex-wrap items-center gap-2"><OwnerChip target={target} /><CommitChip target={target} />{target.last_scan_at ? t('target.lastScan', { time: dateTimeText(target.last_scan_at) }) : t('targets.neverScanned')}</span>}
        actions={<>
          <Button variant="primary" onClick={run} disabled={!!blocked || !operator || scan.isPending || running} title={blocked ?? roleReason ?? undefined} aria-describedby={blocked ? 'scan-reason' : notice ? 'scan-notice' : undefined}>
            <Play />{scan.isPending || running ? t('scan.running') : t('scan.button')}
          </Button>
          <DeleteTarget target={target} />
        </>} />
      <ScanProgress />
      {needTwoStep ? <p role="alert" className="-mt-3 mb-6 max-w-3xl text-sm text-warn">{t('scan.needTwoStep', { value: target.value })} <Link to="/account#two-step" className="underline">{t('scan.needTwoStepLink')}</Link></p> : null}
      {blocked ? <p id="scan-reason" className="-mt-3 mb-6 max-w-3xl text-sm text-warn">{blocked}</p> : <p className="-mt-3 mb-6 max-w-3xl text-[13px] text-muted">{t('scan.safe')}</p>}
      {notice ? (
        <div id="scan-notice" role="note" aria-label={t('scan.noticeTitle')} className="-mt-3 mb-6 max-w-3xl rounded-md border border-line p-3 text-sm">
          <p className="mb-1 font-medium">{t('scan.noticeTitle')}</p>
          {target.commitment ? <p className="mb-1 text-[13px] text-muted">{t('scan.noticeChanged')}</p> : null}
          <p>{notice.text}</p>
          <p className="mt-1 text-[13px] text-muted">{t('scan.noticeWho')}</p>
        </div>
      ) : null}
      {!operator ? <p className="-mt-3 mb-6 max-w-3xl text-[13px] text-muted">{t('target.viewOnly')}</p> : null}
      {stateNotice ? <Notice tone={target.validity === 'expired' && target.kind === 'ip' ? 'danger' : 'warn'} role="alert" title={stateNotice}
        actions={<Button onClick={() => { const p = new URLSearchParams(params); p.set('tab', 'ownership'); setParams(p, { replace: true }) }}>{t('verify.goOwnership')}</Button>} /> : null}
      <AnchorRedirect map={target.kind === 'ip' ? ANCHOR_TAB : { ...ANCHOR_TAB, outside: 'results' }} />
      <ScrollToHash />
      <PageTabs label={t('tabs.label')} tabs={[
        { id: 'results', label: t('tabs.results'), panel: <ResultsPanel target={target} blockedText={blocked} /> },
        { id: 'ownership', label: t('tabs.ownership'), badge: needsOwnership ? { count: 1, label: t('tabs.needsYou') } : undefined, panel: <>
          <Section id="step-verify" title={t('step.verify')} description={target.kind === 'domain' ? t('step.verifyHintDomain') : t('step.verifyHintIp')}>
            <VerifyPanel target={target} />
          </Section>
          {target.commitment ? (
            <Section id="step-commit" title={t('step.commit')} description={t('step.commitHint')}>
              <CommitmentPanel target={target} />
            </Section>
          ) : null}
        </> },
        ...(target.kind === 'ip' ? [{ id: 'outside', label: t('tabs.outsideView'), panel: <OutsidePanel target={target} /> }] : []),
      ]} />
    </>
  )
}

function DeleteTarget({ target }: { target: Target }) {
  const { t } = useTranslation('exposure')
  const can = useCan('admin')
  const del = useDeleteTarget()
  const nav = useNavigate()
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button onClick={() => setOpen(true)} disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.admin') })}><Trash2 />{t('delete.button')}</Button>
      {/* A public IP uses the same dialog as the list (with "Don't add it again if detected" ticked); a domain has nothing to ignore. */}
      {target.kind === 'ip' ? <RemoveDialog target={open ? target : null} onClose={() => setOpen(false)} onDone={() => void nav('/exposure')} /> : (
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent title={t('delete.title', { value: target.value })} description={t('delete.body')}>
          <DialogFooter>
            <Button onClick={() => setOpen(false)}>{t('common:cancel')}</Button>
            <Button variant="danger" disabled={del.isPending} onClick={() => { del.mutateAsync({ id: target.id }).then(() => { toast.success(t('delete.toast', { value: target.value })); void nav('/exposure') }, (e: unknown) => toast.error(errMsg(e))) }}>{t('delete.confirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      )}
    </>
  )
}
