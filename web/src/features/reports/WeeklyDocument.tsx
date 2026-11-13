import { useTranslation } from 'react-i18next'
import { AiBlock } from '@/components/common/AiBlock'
import { SeverityChip, StatusChip } from '@/components/common/StatusChip'
import { fmtDate, fmtDateTime } from '@/lib/format'
import { Scroll } from './parts'
import type { ActionItem, FindingRow, TopRisk, WeeklyReport } from './types'

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
  if ((a.kind === 'fix' || a.kind === 'verify') && a.text) return a.text // the box wrote it, naming the fixed version when NVD says (D-490)
  if (a.kind === 'fix' || a.kind === 'verify') {
    // Since D-485 an action is about one top risk (a product); reports sent before it name one CVE.
    return a.product ? t(`doc.weekly.act.${a.kind}Product`, { product: a.product, device: a.device, count: a.count ?? 1, cve: a.cve }) : t(`doc.weekly.act.${a.kind}`, { cve: a.cve, device: a.device })
  }
  return t(`doc.weekly.act.${a.kind}`, { count: a.count })
}

/** The few lines of what was closed this week, with who closed it; the rest is in the appendix. */
const DONE_LINES = 5

function Risk({ r }: { r: TopRisk }) {
  const { t } = useTranslation('reports')
  return (
    <li className="grid gap-0.5">
      <span className="flex flex-wrap items-center gap-2"><span className="font-medium">{r.product}</span><SeverityChip severity={r.severity} /></span>
      {r.action ? <span>{r.action}</span> : null}
      <span className="text-[13px] text-muted">{t('doc.weekly.risk', { device: r.device, count: r.open, confirmed: r.confirmed, cve: r.cve })}</span>
    </li>
  )
}

/**
 * Báo cáo tuần (S-REP-1). Trang đầu cho lãnh đạo (W1-24, D-485): số liệu cùng định nghĩa với Home/Devices, 3 rủi ro lớn nhất, đã làm gì, tuần sau làm
 * gì; danh sách đầy đủ ở phụ lục (in: sang trang mới). Dùng cho xem trước, lịch sử và bản in.
 */
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
    <article className="text-sm" aria-label={t('doc.weekly.title')}>
      <div className="grid grid-cols-[minmax(0,1fr)] gap-5">
        <header className="grid gap-1 border-b border-rule pb-3">
          <p className="text-[13px] text-muted">{org}</p>
          <h2 className="text-lg font-semibold">{t('doc.weekly.title')}</h2>
          <p className="text-[13px] text-muted">{t('doc.weekly.period', { from: fmtDate(r.period.from), to: fmtDate(r.period.to) })}</p>
          <p className="mt-1 text-base">{open ? t('doc.weekly.headline', { open, confirmed: c.open_confirmed, unapproved: c.devices_unapproved }) : t('doc.weekly.headlineClear', { unapproved: c.devices_unapproved })}</p>
        </header>
        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
          {stat(t('doc.weekly.stat.open'), t('doc.weekly.stat.openValue', { open, confirmed: c.open_confirmed }))}
          {stat(t('doc.weekly.stat.new'), String(c.new_findings))}
          {stat(t('doc.weekly.stat.resolved'), String(c.resolved))}
          {stat(t('doc.weekly.stat.devices'), t('doc.weekly.stat.devicesValue', { total: c.devices, unapproved: c.devices_unapproved }))}
          {stat(t('doc.weekly.stat.kev'), t(r.top_risks ? 'doc.weekly.stat.kevValueHome' : 'doc.weekly.stat.kevValue', { matched: c.kev_matched, n: c.kev_new }))}
        </dl>
        {r.top_risks ? (
          <>
            <section aria-labelledby="wk-risks"><h3 id="wk-risks" className="mb-1 font-semibold">{t('doc.weekly.risks')}</h3>
              {r.top_risks.length ? <ol className="ml-5 grid list-decimal gap-2">{r.top_risks.map((x) => <Risk key={x.finding_id} r={x} />)}</ol> : <p className="text-muted">{t('doc.weekly.noneOpen')}</p>}
            </section>
            {r.happened ? (
              <section aria-labelledby="wk-hap"><h3 id="wk-hap" className="mb-1 font-semibold">{t('doc.weekly.happened')}</h3>
                <p>{r.happened.summary}</p>
                {r.happened.top.length ? (
                  <ul className="ml-5 mt-1 list-disc">
                    {r.happened.top.map((h, i) => <li key={i}>{h.title}{h.count > 1 ? ` ${t('doc.weekly.times', { count: h.count })}` : ''} <SeverityChip severity={h.severity} /></li>)}
                  </ul>
                ) : null}
              </section>
            ) : null}
            <section aria-labelledby="wk-did"><h3 id="wk-did" className="mb-1 font-semibold">{t('doc.weekly.done')}</h3>
              {r.resolved.length ? (
                <ul className="ml-5 list-disc">
                  {r.resolved.slice(0, DONE_LINES).map((f) => <li key={f.id}>{t(f.by ? 'doc.weekly.doneLineBy' : 'doc.weekly.doneLine', { cve: f.cve, product: f.product, device: f.device, status: t(`common:status.${f.status}`), by: f.by })}</li>)}
                </ul>
              ) : <p className="text-muted">{t('doc.weekly.noneDone')}</p>}
              {c.resolved > DONE_LINES ? <p className="mt-1 text-[13px] text-muted">{t('doc.weekly.doneMore', { count: c.resolved - DONE_LINES })}</p> : null}
            </section>
          </>
        ) : null}
        <section aria-labelledby="wk-act"><h3 id="wk-act" className="mb-1 font-semibold">{t('doc.weekly.next')}</h3>{r.actions.length ? <ol className="ml-5 list-decimal">{r.actions.map((a, i) => <li key={i}>{actionText(a, t)}</li>)}</ol> : <p className="text-muted">{t('doc.weekly.noneNext')}</p>}</section>
        {r.ai_summary ? (
          <div className="grid gap-1">
            <AiBlock model={r.ai_summary.profile ? `${r.ai_summary.model} (${r.ai_summary.profile})` : r.ai_summary.model} tokens={r.ai_summary.tokens} citations={[{ title: t('doc.weekly.aiCite') }]}>
              {r.ai_summary.paragraphs.map((p, i) => <p key={i}>{p}</p>)}
            </AiBlock>
            <p className="text-[12px] text-muted">{t('doc.aiAt', { time: fmtDateTime(r.ai_summary.generated_at) })}</p>
          </div>
        ) : null}
      </div>
      {/* A block outside the grid: browsers (Firefox) ignore a page break on a grid item, so the appendix starts a new printed page. */}
      <section aria-labelledby="wk-appendix" className="mt-5 block border-t border-rule pt-4 print:break-before-page">
        <div className="grid gap-4">
          <div className="grid gap-0.5"><h3 id="wk-appendix" className="font-semibold">{t('doc.weekly.appendix')}</h3><p className="text-[13px] text-muted">{t('doc.weekly.appendixNote')}</p></div>
          <section aria-labelledby="wk-new"><h4 id="wk-new" className="mb-1 font-semibold">{t('doc.weekly.new')}</h4>{r.new_findings.length ? <Rows rows={r.new_findings} caption={t('doc.weekly.new')} /> : <p className="text-muted">{t('doc.weekly.noneNew')}</p>}{c.new_findings > r.new_findings.length ? <p className="mt-1 text-[13px] text-muted">{t('doc.weekly.notListedNew', { count: c.new_findings - r.new_findings.length })}</p> : null}</section>
          <section aria-labelledby="wk-done"><h4 id="wk-done" className="mb-1 font-semibold">{t('doc.weekly.handled')}</h4>{r.resolved.length ? <Rows rows={r.resolved} caption={t('doc.weekly.handled')} /> : <p className="text-muted">{t('doc.weekly.noneDone')}</p>}</section>
          <section aria-labelledby="wk-open"><h4 id="wk-open" className="mb-1 font-semibold">{t('doc.weekly.remaining')}</h4>
            {older.length ? <Rows rows={older} caption={t('doc.weekly.remaining')} /> : null}
            {newOpen ? <p className={older.length ? 'mt-1 text-[13px] text-muted' : undefined}>{t(older.length || notListed ? 'doc.weekly.plusNew' : 'doc.weekly.allNewRemain', { count: newOpen })}</p> : null}
            {notListed ? <p className="mt-1 text-[13px] text-muted">{t('doc.weekly.notListed', { count: notListed })}</p> : null}
            {r.open.length ? null : <p className="text-muted">{t('doc.weekly.noneOpen')}</p>}
          </section>
        </div>
      </section>
      <footer className="mt-5 grid gap-0.5 border-t border-rule pt-2 text-[12px] text-muted">
        <p>{t('doc.sources')} {r.sources.map((s) => t(`doc.src.${s.id}`)).join(', ')}.</p>
        {r.happened ? null : <p>{t('doc.weekly.notIncluded')}</p>}
        <p>{t('doc.weekly.footer', { time: fmtDateTime(r.generated_at) })}</p>
      </footer>
    </article>
  )
}
