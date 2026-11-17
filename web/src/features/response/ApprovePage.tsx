import { useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useState } from 'react'
import { AiBlock } from '@/components/common/AiBlock'
import { Notice } from '@/components/common/PageHeader'
import { Card } from '@/components/common/Card'
import { StandalonePage } from '@/components/common/StandalonePage'
import { ErrorState, Loading } from '@/components/common/States'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from '@/components/ui/button'
import { fmtDateTime } from '@/lib/format'
import { errText, useApprovalView, useDecideByLink } from './api'
import { ChangeView, RiskChip } from './parts'

/** Public page behind an emailed approval link. Opening it changes nothing: only the buttons below POST a decision. */
export default function ApprovePage() {
  const { t } = useTranslation('response')
  const token = useParams().token ?? ''
  const q = useApprovalView(token)
  const decide = useDecideByLink()
  const [done, setDone] = useState<'approve' | 'reject' | 'waiting' | null>(null)
  const [error, setError] = useState<string | undefined>()
  const go = (decision: 'approve' | 'reject') => decide.mutate({ token, decision }, { onSuccess: (r) => { setDone(decision === 'approve' && r.status === 'pending' ? 'waiting' : decision); setError(undefined) }, onError: (e) => setError(errText(e)) })
  return (
    // UI.md §3: a page outside the shell (an emailed link), as sign-in is
    <StandalonePage size="lg" title={t('approve.title')}>
      {q.isPending ? <Loading /> : q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : done ? (
        <Notice tone="accent" role="status" className="mb-0" title={done === 'approve' ? t('approve.doneApprove') : done === 'waiting' ? t('approve.doneWaiting') : t('approve.doneReject')} />
      ) : q.data.state === 'ready' ? (
        <Card className="grid gap-4">
          <p className="text-sm">{t('approve.intro', { name: q.data.approver ?? '' })}</p>
          {q.data.ai_generated ? <AiBlock><h2 className="text-base font-semibold">{q.data.title}</h2></AiBlock> : <h2 className="text-base font-semibold">{q.data.title}</h2>}
          <ul className="grid gap-3">{q.data.items.map((i) => <li key={i.title} className="grid gap-2 rounded-md border border-rule bg-paper p-3"><p className="flex flex-wrap items-center gap-2 text-sm font-medium">{i.title} <RiskChip risk={i.risk} /></p><ChangeView change={i.change} /></li>)}</ul>
          {q.data.requires_approvals && q.data.requires_approvals > 1 ? <p className="text-meta">{t('approve.twoNeeded', { n: q.data.approved_so_far ?? 0, of: q.data.requires_approvals })}</p> : null}
          <p className="text-meta text-muted">{t('approve.until', { time: fmtDateTime(q.data.expires_at) })} {t('approve.once')}</p>
          {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
          <div className="flex flex-wrap gap-2">
            <Button variant="primary" disabled={decide.isPending} busy={decide.isPending && decide.variables?.decision === 'approve'} busyLabel={t('common:busy.approving')}
              aria-describedby="approve-wait" onClick={() => go('approve')}>{t('action.approve')}</Button>
            <Button disabled={decide.isPending} busy={decide.isPending && decide.variables?.decision === 'reject'} busyLabel={t('common:busy.rejecting')} onClick={() => go('reject')}>{t('action.reject')}</Button>
          </div>
          {/* The last approval makes the change on the device before it answers (up to 90 s for each change) */}
          <BusyNote id="approve-wait" busy={decide.isPending && decide.variables?.decision === 'approve'}>{t('action.approveWaiting')}</BusyNote>
        </Card>
      ) : (
        <Notice tone="off" role="alert" className="mb-0" title={t(`approve.state.${q.data.state}`, { status: q.data.status ? t(`status.${q.data.status}`).toLowerCase() : '' })} />
      )}
    </StandalonePage>
  )
}
