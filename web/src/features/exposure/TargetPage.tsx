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
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useDeleteTarget, useScan, useTarget } from './api'
import { CommitmentPanel } from './CommitmentPanel'
import { OwnerChip } from './OwnerChip'
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
  const blocked = target.blocked_reason ? t(`blocked.reasonLong.${target.blocked_reason}`, { value: target.value }) : null
  const roleReason = !operator ? t('common:needRole', { role: t('common:role.operator') }) : null
  const c = target.latest
  const title = target.blocked_reason ? t(`target.title.${target.blocked_reason}`, { value: target.value })
    : c ? (target.kind === 'domain' ? t('target.title.result', { value: target.value, subs: c.subdomains, admin: c.admin_panels }) : t('target.title.resultIp', { value: target.value, ports: c.ports, admin: c.admin_panels }))
    : t('target.title.ready', { value: target.value })

  function run() {
    scan.mutate(target.id, {
      onSuccess: (s) => toast.success(t('scan.done', { ports: s.counts.ports, admin: s.counts.admin_panels })),
      onError: (e) => toast.error(errMsg(e)),
    })
  }
  return (
    <>
      <PageHeader title={title} stories={['S-EXP-1']}
        meta={<span className="flex flex-wrap items-center gap-2"><OwnerChip target={target} />{target.commitment ? <Chip tone="ok">{t('status.commitYes')}</Chip> : <Chip tone="off">{t('status.commitNo')}</Chip>}{target.last_scan_at ? t('target.lastScan', { time: fmtDateTime(target.last_scan_at) }) : t('targets.neverScanned')}</span>}
        actions={<>
          <Button variant="primary" onClick={run} disabled={!!blocked || !operator || scan.isPending} title={blocked ?? roleReason ?? undefined} aria-describedby={blocked ? 'scan-reason' : undefined}>
            <Play />{scan.isPending ? t('scan.running') : t('scan.button')}
          </Button>
          <DeleteTarget target={target} />
        </>} />
      {blocked ? <p id="scan-reason" className="-mt-3 mb-6 max-w-3xl text-sm text-warn">{blocked}</p> : <p className="-mt-3 mb-6 max-w-3xl text-[13px] text-muted">{t('scan.safe')}</p>}
      {!operator ? <p className="-mt-3 mb-6 max-w-3xl text-[13px] text-muted">{t('target.viewOnly')}</p> : null}
      <Section id="step-verify" title={t('step.verify')} description={target.kind === 'domain' ? t('step.verifyHintDomain') : t('step.verifyHintIp')}>
        <VerifyPanel target={target} />
      </Section>
      <Section id="step-commit" title={t('step.commit')} description={t('step.commitHint')}>
        <CommitmentPanel target={target} />
      </Section>
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
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent title={t('delete.title', { value: target.value })} description={t('delete.body')}>
          {target.kind === 'ip' ? <p className="text-sm">{t('boxIp.comeBack')}</p> : null}
          <DialogFooter>
            <Button onClick={() => setOpen(false)}>{t('common:cancel')}</Button>
            <Button variant="danger" disabled={del.isPending} onClick={() => { del.mutateAsync({ id: target.id }).then(() => { toast.success(t('delete.toast', { value: target.value })); void nav('/exposure') }, (e: unknown) => toast.error(errMsg(e))) }}>{t('delete.confirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
