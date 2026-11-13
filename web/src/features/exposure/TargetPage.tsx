import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ArrowLeft, Play, Trash2 } from 'lucide-react'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { QueryState, RequireModule } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { dateTimeText } from './dates'
import { useCan, useMe } from '@/lib/session'
import { useDeleteTarget, useScan, useTarget } from './api'
import { CommitmentPanel } from './CommitmentPanel'
import { OwnerChip } from './OwnerChip'
import { RemoveDialog } from './RemoveDialog'
import { ResultsPanel } from './ResultsPanel'
import { VerifyPanel } from './VerifyPanel'
import type { Target } from './types'

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
  const admin = useCan('admin')
  const twofa = useMe().data?.twofa ?? false
  // D-473: an administrator's first Scan now is the D-26 confirmation. The sentence (version and text) comes from the API and is shown beside the button as received.
  const notice = target.blocked_reason === 'no_commitment' && admin ? target.commitment_notice : null
  const needTwoStep = !!notice && !twofa
  const blocked = needTwoStep ? t('scan.needTwoStep', { value: target.value }) : notice ? null : target.blocked_reason ? t(`blocked.reasonLong.${target.blocked_reason}`, { value: target.value }) : null
  const roleReason = !operator ? t('common:needRole', { role: t('common:role.operator') }) : null
  const c = target.latest
  const title = target.blocked_reason && !notice ? t(`target.title.${target.blocked_reason}`, { value: target.value })
    : c ? (target.kind === 'domain' ? t('target.title.result', { value: target.value, subs: c.subdomains, admin: c.admin_panels }) : t('target.title.resultIp', { value: target.value, ports: c.ports, admin: c.admin_panels }))
    : t('target.title.ready', { value: target.value })

  function run() {
    scan.mutate({ id: target.id, noticeVersion: notice?.version }, {
      onSuccess: (s) => toast.success(t('scan.done', { ports: s.counts.ports, admin: s.counts.admin_panels })),
      onError: (e) => toast.error(errMsg(e)),
    })
  }
  return (
    <>
      <PageHeader title={title} stories={['S-EXP-1']}
        meta={<span className="flex flex-wrap items-center gap-2"><OwnerChip target={target} />{target.commitment ? <Chip tone="ok">{t('status.commitYes')}</Chip> : <Chip tone="off">{t('status.commitNo')}</Chip>}{target.last_scan_at ? t('target.lastScan', { time: dateTimeText(target.last_scan_at) }) : t('targets.neverScanned')}</span>}
        actions={<>
          <Button variant="primary" onClick={run} disabled={!!blocked || !operator || scan.isPending} title={blocked ?? roleReason ?? undefined} aria-describedby={blocked ? 'scan-reason' : notice ? 'scan-notice' : undefined}>
            <Play />{scan.isPending ? t('scan.running') : t('scan.button')}
          </Button>
          <DeleteTarget target={target} />
        </>} />
      {blocked ? <p id="scan-reason" className="-mt-3 mb-6 max-w-3xl text-sm text-warn">{blocked}{needTwoStep ? <> <Link to="/account#two-step" className="underline">{t('scan.needTwoStepLink')}</Link></> : null}</p> : <p className="-mt-3 mb-6 max-w-3xl text-[13px] text-muted">{t('scan.safe')}</p>}
      {notice ? (
        <div id="scan-notice" role="note" aria-label={t('scan.noticeTitle')} className="-mt-3 mb-6 max-w-3xl rounded-md border border-line p-3 text-sm">
          <p className="mb-1 font-medium">{t('scan.noticeTitle')}</p>
          <p>{notice.text}</p>
          <p className="mt-1 text-[13px] text-muted">{t('scan.noticeWho')}</p>
        </div>
      ) : null}
      {!operator ? <p className="-mt-3 mb-6 max-w-3xl text-[13px] text-muted">{t('target.viewOnly')}</p> : null}
      <Section id="step-verify" title={t('step.verify')} description={target.kind === 'domain' ? t('step.verifyHintDomain') : t('step.verifyHintIp')}>
        <VerifyPanel target={target} />
      </Section>
      {target.commitment ? (
        <Section id="step-commit" title={t('step.commit')} description={t('step.commitHint')}>
          <CommitmentPanel target={target} />
        </Section>
      ) : null}
      <ResultsPanel target={target} blockedText={blocked} />
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
