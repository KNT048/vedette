import { useTranslation } from 'react-i18next'
import { AiBlock } from '@/components/common/AiBlock'
import { StatusChip } from '@/components/common/StatusChip'
import { fmtDate, fmtDateTime } from '@/lib/format'
import { Scroll } from './parts'
import type { ActionItem, FindingRow, WeeklyReport } from './types'

function Rows({ rows, caption }: { rows: FindingRow[]; caption: string }) {
  const { t } = useTranslation('reports')
  return (
    <Scroll>
      <table className="w-full border-collapse text-[13px]">
        <caption className="sr-only">{caption}</caption>
        <thead><tr className="border-b border-rule text-left text-muted">
          <th scope="col" className="py-1 pr-3 font-medium">{t('doc.col.device')}</th><th scope="col" className="py-1 pr-3 font-medium">{t('doc.col.cve')}</th>
          <th scope="col" className="py-1 pr-3 font-medium">{t('doc.col.product')}</th><th scope="col" className="py-1 pr-3 font-medium">{t('doc.col.status')}</th><th scope="col" className="py-1 font-medium">{t('doc.col.since')}</th>
        </tr></thead>
        <tbody>{rows.map((r) => (
          <tr key={r.id} className="border-b border-rule last:border-b-0">
            <td className="py-1 pr-3">{r.device}</td><td className="py-1 pr-3">{r.cve}</td><td className="py-1 pr-3">{r.product}</td><td className="py-1 pr-3"><StatusChip status={r.status} /></td><td className="py-1">{fmtDate(r.since)}</td>
          </tr>
        ))}</tbody>
      </table>
    </Scroll>
  )
}

export function actionText(a: ActionItem, t: (k: string, o?: Record<string, unknown>) => string) {
  return a.kind === 'fix' || a.kind === 'verify' ? t(`doc.weekly.act.${a.kind}`, { cve: a.cve, device: a.device }) : t(`doc.weekly.act.${a.kind}`, { count: a.count })
}

/** Báo cáo tuần 1 trang (S-REP-1). Dùng cho xem trước, lịch sử và bản in. */
export function WeeklyDocument({ report: r, org }: { report: WeeklyReport; org: string }) {
  const { t } = useTranslation('reports')
  const c = r.counts
  const open = c.open_confirmed + c.open_suspected
  // A finding new this week and still open is listed once, under What is new; Remaining lists the older ones (walk 3 G13). New is
  // judged by first seen within the period, as the box does (weekly.go), not by being in the new list: each list is cut at 100.
  const isNew = (f: FindingRow) => f.since > r.period.from && f.since <= r.period.to
  const older = r.open.filter((f) => !isNew(f))
  const newOpen = r.open.length - older.length
  const notListed = Math.max(0, open - r.open.length)
  const stat = (label: string, value: string) => <div className="grid"><dt className="text-[12px] text-muted">{label}</dt><dd className="text-base font-semibold">{value}</dd></div>
  return (
    <article className="grid grid-cols-[minmax(0,1fr)] gap-5 text-sm" aria-label={t('doc.weekly.title')}>
      <header className="grid gap-1 border-b border-rule pb-3">
        <p className="text-[13px] text-muted">{org}</p>
        <h2 className="text-lg font-semibold">{t('doc.weekly.title')}</h2>
        <p className="text-[13px] text-muted">{t('doc.weekly.period', { from: fmtDate(r.period.from), to: fmtDate(r.period.to) })}</p>
        <p className="mt-1 text-base">{open ? t('doc.weekly.headline', { open, confirmed: c.open_confirmed, unapproved: c.devices_unapproved }) : t('doc.weekly.headlineClear', { unapproved: c.devices_unapproved })}</p>
      </header>
      <dl className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
        {stat(t('doc.weekly.stat.new'), String(c.new_findings))}
        {stat(t('doc.weekly.stat.resolved'), String(c.resolved))}
        {stat(t('doc.weekly.stat.open'), String(open))}
        {stat(t('doc.weekly.stat.devices'), t('doc.weekly.stat.devicesValue', { total: c.devices, unapproved: c.devices_unapproved }))}
        {stat(t('doc.weekly.stat.kev'), t('doc.weekly.stat.kevValue', { matched: c.kev_matched, n: c.kev_new }))}
      </dl>
      <section aria-labelledby="wk-new"><h3 id="wk-new" className="mb-1 font-semibold">{t('doc.weekly.new')}</h3>{r.new_findings.length ? <Rows rows={r.new_findings} caption={t('doc.weekly.new')} /> : <p className="text-muted">{t('doc.weekly.noneNew')}</p>}</section>
      <section aria-labelledby="wk-done"><h3 id="wk-done" className="mb-1 font-semibold">{t('doc.weekly.done')}</h3>{r.resolved.length ? <Rows rows={r.resolved} caption={t('doc.weekly.done')} /> : <p className="text-muted">{t('doc.weekly.noneDone')}</p>}</section>
      <section aria-labelledby="wk-open"><h3 id="wk-open" className="mb-1 font-semibold">{t('doc.weekly.remaining')}</h3>
        {older.length ? <Rows rows={older} caption={t('doc.weekly.remaining')} /> : null}
        {newOpen ? <p className={older.length ? 'mt-1 text-[13px] text-muted' : undefined}>{t(older.length || notListed ? 'doc.weekly.plusNew' : 'doc.weekly.allNewRemain', { count: newOpen })}</p> : null}
        {notListed ? <p className="mt-1 text-[13px] text-muted">{t('doc.weekly.notListed', { count: notListed })}</p> : null}
        {r.open.length ? null : <p className="text-muted">{t('doc.weekly.noneOpen')}</p>}
      </section>
      <section aria-labelledby="wk-act"><h3 id="wk-act" className="mb-1 font-semibold">{t('doc.weekly.next')}</h3>{r.actions.length ? <ol className="ml-5 list-decimal">{r.actions.map((a, i) => <li key={i}>{actionText(a, t)}</li>)}</ol> : <p className="text-muted">{t('doc.weekly.noneNext')}</p>}</section>
      {r.ai_summary ? (
        <div className="grid gap-1">
          <AiBlock model={r.ai_summary.profile ? `${r.ai_summary.model} (${r.ai_summary.profile})` : r.ai_summary.model} tokens={r.ai_summary.tokens} citations={[{ title: t('doc.weekly.aiCite') }]}>
            {r.ai_summary.paragraphs.map((p, i) => <p key={i}>{p}</p>)}
          </AiBlock>
          <p className="text-[12px] text-muted">{t('doc.aiAt', { time: fmtDateTime(r.ai_summary.generated_at) })}</p>
        </div>
      ) : null}
      <footer className="grid gap-0.5 border-t border-rule pt-2 text-[12px] text-muted">
        <p>{t('doc.sources')} {r.sources.map((s) => t(`doc.src.${s.id}`)).join(', ')}.</p>
        <p>{t('doc.weekly.notIncluded')}</p>
        <p>{t('doc.weekly.footer', { time: fmtDateTime(r.generated_at) })}</p>
      </footer>
    </article>
  )
}
