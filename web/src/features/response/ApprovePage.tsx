import { useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useState } from 'react'
import { Panel } from '@/components/common/PageHeader'
import { ErrorState, Loading } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { fmtDateTime } from '@/lib/format'
import { errText, useApprovalView, useDecideByLink } from './api'
import { ChangeView, RiskChip } from './parts'

/** Public page behind an emailed approval link (D-46). Opening it changes nothing: only the buttons below POST a decision. */
export default function ApprovePage() {
  const { t } = useTranslation('response')
  const token = useParams().token ?? ''
  const q = useApprovalView(token)
  const decide = useDecideByLink()
  const [done, setDone] = useState<'approve' | 'reject' | 'waiting' | null>(null)
  const [error, setError] = useState<string | undefined>()
  const go = (decision: 'approve' | 'reject') => decide.mutate({ token, decision }, { onSuccess: (r) => { setDone(decision === 'approve' && r.status === 'pending' ? 'waiting' : decision); setError(undefined) }, onError: (e) => setError(errText(e)) })
  return (
    <main className="mx-auto grid max-w-3xl gap-4 px-4 py-10 sm:px-8">
      <h1 className="text-xl font-semibold">{t('approve.title')}</h1>
      {q.isPending ? <Loading /> : q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : done ? (
        <p role="status" className="rounded-md border border-rule bg-surface px-4 py-3 text-sm">{done === 'approve' ? t('approve.doneApprove') : done === 'waiting' ? t('approve.doneWaiting') : t('approve.doneReject')}</p>
      ) : q.data.state === 'ready' ? (
        <Panel className="grid gap-4 p-4">
          <p className="text-sm">{t('approve.intro', { name: q.data.approver ?? '' })}</p>
          <h2 className="text-base font-semibold">{q.data.title}</h2>
          <ul className="grid gap-3">{q.data.items.map((i) => <li key={i.title} className="grid gap-2 rounded-md border border-rule bg-paper p-3"><p className="flex flex-wrap items-center gap-2 text-sm font-medium">{i.title} <RiskChip risk={i.risk} /></p><ChangeView change={i.change} /></li>)}</ul>
          {q.data.requires_approvals && q.data.requires_approvals > 1 ? <p className="text-[13px]">{t('approve.twoNeeded', { n: q.data.approved_so_far ?? 0, of: q.data.requires_approvals })}</p> : null}
          <p className="text-[13px] text-muted">{t('approve.until', { time: fmtDateTime(q.data.expires_at) })} {t('approve.once')}</p>
          {error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{error}</p> : null}
          <div className="flex flex-wrap gap-2">
            <Button variant="primary" disabled={decide.isPending} onClick={() => go('approve')}>{t('action.approve')}</Button>
            <Button disabled={decide.isPending} onClick={() => go('reject')}>{t('action.reject')}</Button>
          </div>
        </Panel>
      ) : (
        <p role="alert" className="rounded-md border border-dashed border-rule bg-surface px-4 py-3 text-sm">{t(`approve.state.${q.data.state}`, { status: q.data.status ? t(`status.${q.data.status}`).toLowerCase() : '' })}</p>
      )}
    </main>
  )
}
