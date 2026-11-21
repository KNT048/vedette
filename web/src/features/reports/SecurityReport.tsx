import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { AiBlock } from '@/components/common/AiBlock'
import { Chip } from '@/components/common/StatusChip'
import { HandledLine, SeverityBadge, StatusBadge, useStatusLabel, VerificationLine } from '@/components/common/status'
import { Logo } from '@/components/brand/Logo'
import { NotAddedChip } from '@/features/findings/NotAdded'
import { useFixTitle } from '@/features/findings/parts'
import { fmtDate, fmtDateTime } from '@/lib/format'
import { FINDING_RESOLUTIONS, OPEN_FINDING_STATUSES } from '@/lib/statusCodes'
import { cn } from '@/lib/utils'
import { BarList, OpenFlow } from './charts'
import { Scroll } from './parts'
import type {
  DeviceRef, ExposureService, ExposureTarget, HandledStatus, OpenStatus, ReportCoverage, ReportDetections, ReportDocument, ReportExposure,
  ReportFinding, ReportHandled, ReportNew, ReportOpen, ReportSummary,
} from './types'

// The periodic security report as one document: the Report tab, a sent report in History and the printed copy (A4) all draw it,
// so what a manager reads on paper is what the page shows. One column, tables of four columns at most, so it also reads as an
// email. Sections follow the order a manager asks: where do we stand, what was done, what is left, what is new, what the
// Internet sees, what happened, and what Vedette cannot see. A section switched off in Settings is absent from the document.

const BAR: Record<OpenStatus | HandledStatus, string> = {
  under_attack: 'bg-danger', exploited: 'bg-danger/70', public_exploit: 'bg-warn', critical_edge: 'bg-warn/70', update_recommended: 'bg-warn/40',
  patched: 'bg-ok', mitigated: 'bg-ok/60', accepted: 'bg-off/60', not_relevant: 'bg-off/40', false_positive: 'bg-off/30',
}
/** The statuses whose meaning says "now" (the words of the badges). */
const NOW: OpenStatus[] = ['under_attack', 'exploited', 'critical_edge']

const th = 'py-1.5 pr-3 text-left text-caption font-medium text-muted'
const td = 'py-2 pr-3 align-top'

/** The period as people say it; a calendar month ends the moment the next one starts, so its last day is shown. */
function periodText(p: ReportDocument['period'], t: (k: string, o?: Record<string, unknown>) => string) {
  const to = p.kind === 'calendar_month' ? new Date(Date.parse(p.to) - 1).toISOString() : p.to
  return t('sr.period', { kind: t(`sr.kind.${p.kind}`), from: fmtDate(p.from), to: fmtDate(to) })
}

function Heading({ id, n, children, aside }: { id: string; n: number; children: ReactNode; aside?: ReactNode }) {
  return (
    <div className="mb-3 flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-t-2 border-ink pt-2">
      <h3 id={id} className="flex items-baseline gap-2 text-base font-semibold">
        <span aria-hidden className="text-meta tabular-nums text-muted">{String(n).padStart(2, '0')}</span>{children}
      </h3>
      {aside ? <span className="text-meta text-muted">{aside}</span> : null}
    </div>
  )
}

function DeviceName({ device }: { device: DeviceRef }) {
  return <span className="inline-flex flex-wrap items-center gap-2"><span className="font-medium">{device.name}</span><NotAddedChip asset={{ approved: device.added }} /></span>
}

/** A CVE, linked to its finding where the finding is listed for good (Still open, Handled); the summary and New name it only, so one
 *  screen never carries the same link twice. */
function CveLink({ cve, finding, plain = false }: { cve: string; finding: string; plain?: boolean }) {
  if (plain) return <span className="whitespace-nowrap font-medium">{cve}</span>
  return <Link to={`/findings/${encodeURIComponent(finding)}`} className="whitespace-nowrap font-medium text-accent underline-offset-4 hover:underline">{cve}</Link>
}

/** The document of one period. `org` names the organisation in the masthead. */
export function SecurityReport({ doc, org }: { doc: ReportDocument; org: string }) {
  const { t } = useTranslation('reports')
  const s = doc.summary
  const order = (['summary', 'handled', 'open', 'new', 'exposure', 'detections', 'coverage'] as const).filter((k) => doc[k] !== undefined)
  const num = (k: (typeof order)[number]) => order.indexOf(k) + 1
  const urgent = s ? s.open_by_status.filter((r) => NOW.includes(r.status)).reduce((n, r) => n + r.n, 0) : 0
  const handledN = s?.handled ?? (doc.handled ? doc.handled.totals.reduce((n, x) => n + x.n, 0) : null)
  const o = doc.options
  return (
    <article aria-label={doc.title} className="grid grid-cols-[minmax(0,1fr)] gap-8 text-sm">
      <header className="grid gap-3">
        <div className="flex items-start justify-between gap-4">
          <div className="grid gap-0.5">
            {org ? <p className="text-meta font-medium text-muted">{org}</p> : null}
            <h2 className="text-lg font-semibold">{doc.title}</h2>
            <p className="text-meta text-muted">{periodText(doc.period, t)}</p>
          </div>
          <Logo decorative className="h-6 w-auto shrink-0" />
        </div>
        {s ? (
          <p className="max-w-2xl text-base">
            {s.open_now ? t('sr.headline', { count: s.open_now }) : t('sr.headlineClear')}
            {urgent ? ` ${t('sr.headlineUrgent', { count: urgent })}` : ''}
            {handledN !== null ? ` ${t('sr.headlineHandled', { count: handledN })}` : ''}
          </p>
        ) : null}
      </header>

      {s ? <Summary s={s} handled={doc.handled} charts={o.charts} n={num('summary')} /> : null}
      {doc.handled ? <Handled h={doc.handled} charts={o.charts} n={num('handled')} /> : null}
      {doc.open ? <Open open={doc.open} n={num('open')} /> : null}
      {doc.new ? <New fresh={doc.new} n={num('new')} /> : null}
      {doc.exposure ? <Exposure e={doc.exposure} at={doc.generated_at} n={num('exposure')} /> : null}
      {doc.detections ? <Detections d={doc.detections} charts={o.charts} n={num('detections')} /> : null}
      {doc.coverage ? <Coverage c={doc.coverage} charts={o.charts} n={num('coverage')} /> : null}

      {doc.ai_summary ? (
        <AiBlock model={doc.ai_summary.profile ? `${doc.ai_summary.model} (${doc.ai_summary.profile})` : doc.ai_summary.model} tokens={doc.ai_summary.tokens}>
          {doc.ai_summary.paragraphs.map((p, i) => <p key={i}>{p}</p>)}
        </AiBlock>
      ) : null}

      <footer className="grid gap-0.5 border-t border-rule pt-2 text-caption text-muted">
        <p>{[t(o.include_not_added ? 'sr.options.notAddedIn' : 'sr.options.notAddedOut'), t(o.include_not_relevant ? 'sr.options.nrIn' : 'sr.options.nrOut'), doc.open ? t(o.grouping === 'cve' ? 'sr.options.groupCve' : 'sr.options.groupDevice') : null].filter(Boolean).join(' ')}</p>
        <p>{t('sr.footer', { time: fmtDateTime(doc.generated_at), tz: doc.period.tz })}</p>
      </footer>
    </article>
  )
}

function Summary({ s, handled, charts, n }: { s: ReportSummary; handled?: ReportHandled; charts: boolean; n: number }) {
  const { t } = useTranslation('reports')
  const fixTitle = useFixTitle()
  const delta = s.open_now - s.open_before
  const days = handled?.median_days
  const kpi = (label: string, value: ReactNode, sub?: ReactNode, tone?: 'ok' | 'danger') => (
    <div className="grid content-start gap-0.5 bg-surface px-4 py-3">
      <dt className="text-meta text-muted">{label}</dt>
      <dd className={cn('text-lg font-semibold tabular-nums', tone === 'ok' && 'text-ok', tone === 'danger' && 'text-danger')}>{value}</dd>
      {sub ? <dd className="text-caption text-muted">{sub}</dd> : null}
    </div>
  )
  return (
    <section aria-labelledby="sr-summary">
      <Heading id="sr-summary" n={n}>{t('sr.section.summary')}</Heading>
      <dl aria-label={t('sr.kpi.label')} className="report-block mb-5 grid grid-cols-2 gap-px overflow-hidden rounded-md border border-rule bg-rule sm:grid-cols-4">
        {kpi(t('sr.kpi.open'), s.open_now, delta > 0 ? t('sr.kpi.up', { count: delta }) : delta < 0 ? t('sr.kpi.down', { count: -delta }) : t('sr.kpi.same'), delta > 0 ? 'danger' : undefined)}
        {kpi(t('sr.kpi.new'), s.new)}
        {kpi(t('sr.kpi.handled'), s.handled, undefined, s.handled > 0 ? 'ok' : undefined)}
        {handled ? kpi(t('sr.kpi.days'), days === null || days === undefined ? t('sr.kpi.daysNone') : t('sr.kpi.daysValue', { count: Math.round(days * 10) / 10 })) : null}
      </dl>
      {charts && (s.open_by_status.length || s.open_before || s.handled) ? (
        <div className="report-block mb-6 grid gap-6 sm:grid-cols-2">
          <OpenFlow start={s.open_before} added={s.new} handled={s.handled} end={s.open_now} />
          {s.open_by_status.length ? (
            <div className="grid content-start gap-2">
              <p className="text-meta font-medium text-muted">{t('sr.byStatus')}</p>
              <BarList label={t('sr.byStatus')} rows={OPEN_FINDING_STATUSES.flatMap((st) => {
                const r = s.open_by_status.find((x) => x.status === st)
                return r ? [{ key: st, label: <StatusBadge code={st} />, n: r.n, bar: BAR[st] }] : []
              })} />
            </div>
          ) : null}
        </div>
      ) : !charts && s.open_by_status.length ? (
        <ul aria-label={t('sr.byStatus')} className="mb-6 flex flex-wrap gap-x-4 gap-y-2">
          {s.open_by_status.map((r) => <li key={r.status} className="inline-flex items-center gap-2"><StatusBadge code={r.status} /><span className="font-semibold tabular-nums">{r.n}</span></li>)}
        </ul>
      ) : null}
      <h4 className="mb-2 font-semibold">{t('sr.first')}</h4>
      {s.first.length ? (
        <ol className="grid gap-2">
          {s.first.map((f, i) => {
            const names = f.devices.map((d) => d.name).join(', ')
            const more = f.device_count - f.devices.length
            return (
              <li key={f.finding_id} className="report-block grid grid-cols-[1.75rem_minmax(0,1fr)] gap-3 rounded-md border border-rule bg-surface p-3">
                <span aria-hidden className="grid size-7 place-items-center rounded-full bg-ink text-meta font-semibold text-paper">{i + 1}</span>
                <div className="grid min-w-0 gap-1">
                  <p className="font-semibold">{fixTitle(f.fix)}</p>
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusBadge code={f.status} />
                    <CveLink cve={f.cve} finding={f.finding_id} plain />
                    <SeverityBadge severity={f.severity} compact />
                  </div>
                  <p className="text-meta text-muted">
                    {more > 0 ? t('sr.firstMore', { list: names, count: more }) : t('sr.firstDevices', { list: names, count: f.device_count })}
                    {' · '}{t('sr.firstFindings', { count: f.finding_count })}
                  </p>
                </div>
              </li>
            )
          })}
        </ol>
      ) : <p className="text-muted">{t('sr.firstNone')}</p>}
    </section>
  )
}

function Handled({ h, charts, n }: { h: ReportHandled; charts: boolean; n: number }) {
  const { t } = useTranslation('reports')
  const label = useStatusLabel()
  const total = h.totals.reduce((a, x) => a + x.n, 0)
  const byRes = FINDING_RESOLUTIONS.map((r) => ({ r, n: h.totals.filter((x) => x.resolution === r).reduce((a, x) => a + x.n, 0), via: h.totals.filter((x) => x.resolution === r) })).filter((x) => x.n > 0)
  // Credit for what Vedette saw by itself: an update, a removal or a fixed package, nobody had to tell it.
  const seen = h.totals.filter((x) => x.via === 'version_moved' || x.via === 'software_removed' || x.via === 'distro_fixed' || x.via === 'scan_clear').reduce((a, x) => a + x.n, 0)
  const how = (via: typeof byRes[number]['via']) => via.map((v) => t(`sr.via.${v.via}`, { count: v.n })).join(', ')
  return (
    <section aria-labelledby="sr-handled">
      <Heading id="sr-handled" n={n} aside={total ? t('sr.groupCount', { count: total }) : undefined}>{t('sr.section.handled')}</Heading>
      {total === 0 ? <p className="text-muted">{t('sr.handledNone')}</p> : (
        <div className="grid gap-4">
          <div className="report-block grid gap-2">
            <p className="sr-only">{t('sr.handledTotals')}</p>
            {charts ? (
              <BarList label={t('sr.handledTotals')} rows={byRes.map((x) => ({ key: x.r, label: <StatusBadge code={x.r} />, n: x.n, bar: BAR[x.r] }))} />
            ) : (
              <ul aria-label={t('sr.handledTotals')} className="flex flex-wrap gap-x-4 gap-y-2">
                {byRes.map((x) => <li key={x.r} className="inline-flex items-center gap-2"><StatusBadge code={x.r} /><span className="font-semibold tabular-nums">{x.n}</span></li>)}
              </ul>
            )}
            <ul className="grid gap-0.5 text-meta text-muted">
              {byRes.map((x) => <li key={x.r}><span className="font-medium text-ink">{label(x.r)}</span>: {how(x.via)}</li>)}
            </ul>
            {seen ? <p className="text-meta font-medium text-ok">{t('sr.handledFound', { count: seen })}</p> : null}
          </div>
          <Scroll>
            <table className="w-full border-collapse">
              <caption className="sr-only">{t('sr.section.handled')}</caption>
              <thead><tr className="border-b border-rule"><th scope="col" className={th}>{t('sr.col.finding')}</th><th scope="col" className={th}>{t('sr.col.handled')}</th></tr></thead>
              {h.devices.map((g) => (
                <tbody key={g.device.id}>
                  <tr className="border-b border-rule bg-sunken"><th scope="rowgroup" colSpan={2} className="px-2 py-1.5 text-left font-normal"><DeviceName device={g.device} /></th></tr>
                  {g.items.map((i) => (
                    <tr key={i.finding_id} className="border-b border-rule last:border-b-0">
                      <td className={cn(td, 'pl-2')}>
                        <div className="flex flex-wrap items-center gap-x-2 gap-y-1"><CveLink cve={i.cve} finding={i.finding_id} /><SeverityBadge severity={i.severity} compact /></div>
                        <div className="text-meta text-muted">{i.product}</div>
                      </td>
                      <td className={td}><div className="flex flex-wrap items-center gap-2"><StatusBadge code={i.handled.resolution} until={i.handled.accepted_until} /></div><HandledLine handled={i.handled} software={i.product} className="mt-1 block" /></td>
                    </tr>
                  ))}
                </tbody>
              ))}
            </table>
          </Scroll>
          {h.more ? <p className="text-meta text-muted">{t('sr.moreHandled', { count: h.more })}</p> : null}
        </div>
      )}
    </section>
  )
}

/** A finding's status with how Vedette knows, and the day a list asks for the fix (CISA KEV). */
function StatusCell({ f }: { f: ReportFinding }) {
  const { t } = useTranslation()
  const due = f.reasons.map((r) => r.due).filter((d): d is string => !!d).sort()[0]
  return (
    <div className="grid gap-1">
      <StatusBadge code={f.status} />
      <VerificationLine verified={f.verification.verified} basis={f.verification.basis} by={f.verification.by} at={f.verification.at} />
      {due ? <span className="text-meta font-medium text-danger">{t('reasons.due', { date: fmtDate(due) })}</span> : null}
    </div>
  )
}

function Open({ open, n }: { open: ReportOpen; n: number }) {
  const { t } = useTranslation('reports')
  const fixTitle = useFixTitle()
  const byDevice = open.grouping === 'device'
  return (
    <section aria-labelledby="sr-open">
      <Heading id="sr-open" n={n} aside={open.total ? t('sr.groupCount', { count: open.total }) : undefined}>{t('sr.section.open')}</Heading>
      {open.total === 0 ? <p className="text-muted">{t('sr.openNone')}</p> : (
        <div className="grid gap-2">
          <Scroll>
            <table className="w-full border-collapse">
              <caption className="sr-only">{t('sr.section.open')}</caption>
              <thead><tr className="border-b border-rule">
                <th scope="col" className={cn(th, 'pl-2')}>{byDevice ? t('sr.col.finding') : t('sr.col.device')}</th>
                <th scope="col" className={th}>{t('sr.col.status')}</th>
                <th scope="col" className={th}>{t('sr.col.fix')}</th>
              </tr></thead>
              {open.groups.map((g) => (
                <tbody key={g.key}>
                  <tr className="border-b border-rule bg-sunken">
                    <th scope="rowgroup" colSpan={3} className="px-2 py-1.5 text-left font-normal">
                      {byDevice && g.items[0] ? <DeviceName device={g.items[0].device} /> : (
                        <span className="inline-flex flex-wrap items-center gap-2">
                          {g.items[0] ? <CveLink cve={g.label} finding={g.items[0].finding_id} /> : <span className="font-medium">{g.label}</span>}
                          {g.items[0] ? <><span className="text-muted">{g.items[0].product}</span><SeverityBadge severity={g.items[0].severity} compact /></> : null}
                        </span>
                      )}
                      <span className="ml-2 text-meta text-muted">{t('sr.groupCount', { count: g.items.length })}</span>
                    </th>
                  </tr>
                  {g.items.map((f) => (
                    <tr key={f.finding_id} className="border-b border-rule last:border-b-0">
                      <td className={cn(td, 'pl-2')}>
                        {byDevice ? (
                          <>
                            <div className="flex flex-wrap items-center gap-x-2 gap-y-1"><CveLink cve={f.cve} finding={f.finding_id} /><SeverityBadge severity={f.severity} compact /></div>
                            <div className="text-meta text-muted">{f.version ? `${f.product} ${f.version}` : f.product}</div>
                          </>
                        ) : <DeviceName device={f.device} />}
                      </td>
                      <td className={td}><StatusCell f={f} /></td>
                      <td className={cn(td, 'text-meta')}>{fixTitle(f.fix, f.version ? { id: '', name: f.product, version: f.version } : null)}</td>
                    </tr>
                  ))}
                </tbody>
              ))}
            </table>
          </Scroll>
          {open.more ? <p className="text-meta text-muted">{t('sr.moreOpen', { count: open.more })}</p> : null}
        </div>
      )}
    </section>
  )
}

function New({ fresh, n }: { fresh: ReportNew; n: number }) {
  const { t } = useTranslation('reports')
  const still = fresh.items.filter((f) => (OPEN_FINDING_STATUSES as readonly string[]).includes(f.status)).length
  return (
    <section aria-labelledby="sr-new">
      <Heading id="sr-new" n={n} aside={fresh.total ? `${t('sr.groupCount', { count: fresh.total })} · ${t('sr.newStill', { count: still })}` : undefined}>{t('sr.section.new')}</Heading>
      {fresh.total === 0 ? <p className="text-muted">{t('sr.newNone')}</p> : (
        <div className="grid gap-2">
          <Scroll>
            <table className="w-full border-collapse">
              <caption className="sr-only">{t('sr.section.new')}</caption>
              <thead><tr className="border-b border-rule">
                <th scope="col" className={th}>{t('sr.col.finding')}</th><th scope="col" className={th}>{t('sr.col.device')}</th>
                <th scope="col" className={th}>{t('sr.col.status')}</th><th scope="col" className={th}>{t('sr.col.seen')}</th>
              </tr></thead>
              <tbody>
                {fresh.items.map((f) => (
                  <tr key={f.finding_id} className="border-b border-rule last:border-b-0">
                    <td className={td}>
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-1"><CveLink cve={f.cve} finding={f.finding_id} plain /><SeverityBadge severity={f.severity} compact /></div>
                      <div className="text-meta text-muted">{f.product}</div>
                    </td>
                    <td className={td}><DeviceName device={f.device} /></td>
                    <td className={td}><StatusBadge code={f.status} /></td>
                    <td className={cn(td, 'whitespace-nowrap text-meta')}>{fmtDate(f.first_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Scroll>
          {fresh.more ? <p className="text-meta text-muted">{t('sr.moreNew', { count: fresh.more })}</p> : null}
        </div>
      )}
    </section>
  )
}

const DAY = 864e5

function Cert({ svc, at }: { svc: ExposureService; at: string }) {
  const { t } = useTranslation('reports')
  if (!svc.cert_expires_at) return <span className="text-muted">–</span>
  const left = Date.parse(svc.cert_expires_at) - Date.parse(at)
  const date = fmtDate(svc.cert_expires_at)
  if (left <= 0) return <span className="font-medium text-danger">{t('sr.certExpired', { date })}</span>
  if (left < 30 * DAY) return <span className="font-medium text-warn">{t('sr.certSoon', { date })}</span>
  return <span>{t('sr.certOk', { date })}</span>
}

function Target({ x, at }: { x: ExposureTarget; at: string }) {
  const { t } = useTranslation('reports')
  const open = x.services.filter((s) => s.change !== 'closed')
  const closed = x.services.length - open.length
  const issues = x.issues.filter((i) => i.open > 0)
  const proofTone = x.proof === 'proven' || x.proof === 'covered' ? 'ok' : x.proof === 'not_current' ? 'warn' : 'danger'
  return (
    <div className="report-block grid gap-3 rounded-md border border-rule bg-surface p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="grid gap-0.5">
          <p className="flex flex-wrap items-baseline gap-2"><span className="font-mono text-sm font-semibold">{x.value}</span>{x.parent ? <span className="text-meta text-muted">{t('sr.under', { parent: x.parent })}</span> : null}</p>
          <p className="text-meta text-muted">
            {x.last_scan_at ? t('sr.lastScan', { time: fmtDateTime(x.last_scan_at) }) : t('sr.neverScanned')}
            {' · '}{open.length ? t('sr.ports', { count: open.length }) : t('sr.portsNone')}
            {closed ? ` · ${t('sr.closedCount', { count: closed })}` : ''}
          </p>
        </div>
        <Chip tone={proofTone}>{x.proof === 'covered' ? (x.parent ? t('sr.proof.covered', { parent: x.parent }) : t('sr.proof.coveredNoParent')) : t(`sr.proof.${x.proof}`)}</Chip>
      </div>
      <div className="grid gap-1">
        <p className="text-meta font-medium">{t('sr.issues')}</p>
        {issues.length ? (
          <ul className="flex flex-wrap gap-x-4 gap-y-1.5">
            {issues.map((i) => (
              <li key={`${i.engine}-${i.severity}`} className="inline-flex flex-wrap items-center gap-1.5 text-meta">
                <span className="font-medium">{t(`sr.engine.${i.engine}`)}</span>
                <SeverityBadge severity={i.severity} compact />
                <span className="tabular-nums">{i.open}</span>
                {i.new ? <span className="text-warn">({t('sr.issueNew', { count: i.new })})</span> : null}
              </li>
            ))}
          </ul>
        ) : <p className="text-meta text-muted">{t('sr.issuesNone')}</p>}
      </div>
      {x.services.length ? (
        <Scroll>
          <table className="w-full border-collapse text-meta">
            <caption className="sr-only">{x.value}</caption>
            <thead><tr className="border-b border-rule">
              <th scope="col" className={th}>{t('sr.svc.port')}</th><th scope="col" className={th}>{t('sr.svc.software')}</th>
              <th scope="col" className={th}>{t('sr.svc.change')}</th><th scope="col" className={th}>{t('sr.svc.cert')}</th>
            </tr></thead>
            <tbody>
              {x.services.map((s) => (
                <tr key={`${s.ip}-${s.port}-${s.proto}`} className={cn('border-b border-rule last:border-b-0', s.change === 'closed' && 'text-muted')}>
                  <td className={cn(td, 'whitespace-nowrap')}><span className={cn('font-mono', s.change === 'closed' && 'line-through')}>{s.port}/{s.proto}</span>{s.name ? <span className="ml-1.5 text-muted">{s.name}</span> : null}</td>
                  <td className={td}>{[s.product, s.version].filter(Boolean).join(' ') || '–'}</td>
                  <td className={td}>{s.change === 'new' ? <Chip tone="warn">{t('sr.change.new')}</Chip> : s.change === 'closed' ? <Chip tone="off">{t('sr.change.closed')}</Chip> : '–'}</td>
                  <td className={cn(td, 'whitespace-nowrap')}><Cert svc={s} at={at} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </Scroll>
      ) : null}
    </div>
  )
}

function Exposure({ e, at, n }: { e: ReportExposure; at: string; n: number }) {
  const { t } = useTranslation('reports')
  return (
    <section aria-labelledby="sr-exposure">
      <Heading id="sr-exposure" n={n}>{t('sr.section.exposure')}</Heading>
      {!e.module_on ? <p className="text-muted">{t('sr.exposureOff')}</p>
        : e.targets.length === 0 ? <p className="text-muted">{t('sr.exposureNone')}</p>
        : <div className="grid gap-3">{e.targets.map((x) => <Target key={x.target_id} x={x} at={at} />)}</div>}
    </section>
  )
}

function Detections({ d, charts, n }: { d: ReportDetections; charts: boolean; n: number }) {
  const { t } = useTranslation('reports')
  const total = d.by_kind.reduce((a, k) => a + k.n, 0)
  return (
    <section aria-labelledby="sr-detections">
      <Heading id="sr-detections" n={n} aside={total ? String(total) : undefined}>{t('sr.section.detections')}</Heading>
      {!d.module_on ? <p className="text-muted">{t('sr.detectionsOff')}</p>
        : total === 0 ? <p className="text-muted">{t('sr.detectionsNone')}</p> : (
          <div className="grid gap-4">
            {charts ? (
              <BarList label={t('sr.section.detections')} rows={[...d.by_kind].sort((a, b) => b.n - a.n).map((k) => ({ key: k.kind, label: <span className="text-meta">{t(`sr.dkind.${k.kind}`)}</span>, n: k.n, bar: k.kind === 'intrusion' || k.kind === 'trap' ? 'bg-danger/70' : 'bg-off/60' }))} />
            ) : (
              <table className="w-full border-collapse text-meta">
                <caption className="sr-only">{t('sr.section.detections')}</caption>
                <thead><tr className="border-b border-rule"><th scope="col" className={th}>{t('sr.kindCol')}</th><th scope="col" className={th}>{t('sr.countCol')}</th><th scope="col" className={th}>{t('sr.lastCol')}</th></tr></thead>
                <tbody>{d.by_kind.map((k) => <tr key={k.kind} className="border-b border-rule last:border-b-0"><td className={td}>{t(`sr.dkind.${k.kind}`)}</td><td className={cn(td, 'tabular-nums')}>{k.n}</td><td className={td}>{fmtDateTime(k.last_at)}</td></tr>)}</tbody>
              </table>
            )}
            {d.top.length ? (
              <div className="grid gap-1.5">
                <p className="text-meta font-medium">{t('sr.notable')}</p>
                <ul className="grid gap-2">
                  {d.top.map((x, i) => (
                    <li key={i} className="report-block grid gap-0.5 border-l-2 border-rule pl-3">
                      <span className="flex flex-wrap items-center gap-2"><SeverityBadge severity={x.severity} compact /><span className="font-medium">{x.title}</span></span>
                      <span className="text-meta text-muted">{[t(`sr.dkind.${x.kind}`), x.device?.name, fmtDateTime(x.at)].filter(Boolean).join(' · ')}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        )}
    </section>
  )
}

function Coverage({ c, charts, n }: { c: ReportCoverage; charts: boolean; n: number }) {
  const { t } = useTranslation('reports')
  const noAgent = c.devices - c.with_agent
  return (
    <section aria-labelledby="sr-coverage">
      <Heading id="sr-coverage" n={n}>{t('sr.section.coverage')}</Heading>
      <div className="report-block grid gap-4">
        <dl className="grid grid-cols-3 gap-px overflow-hidden rounded-md border border-rule bg-rule">
          <div className="grid gap-0.5 bg-surface px-4 py-3"><dt className="text-meta text-muted">{t('sr.cov.devices')}</dt><dd className="text-lg font-semibold tabular-nums">{c.devices}</dd></div>
          <div className="grid gap-1 bg-surface px-4 py-3">
            <dt className="text-meta text-muted">{t('sr.cov.agents')}</dt>
            <dd className="text-lg font-semibold tabular-nums">{t('sr.cov.agentsValue', { n: c.with_agent, total: c.devices })}</dd>
            {charts && c.devices ? <dd aria-hidden className="h-1.5 overflow-hidden rounded-full bg-sunken"><span className="block h-full rounded-full bg-ok" style={{ width: `${(c.with_agent / c.devices) * 100}%` }} /></dd> : null}
          </div>
          <div className="grid gap-0.5 bg-surface px-4 py-3"><dt className="text-meta text-muted">{t('sr.cov.notAdded')}</dt><dd className="text-lg font-semibold tabular-nums">{c.not_added}</dd></div>
        </dl>
        {noAgent > 0 ? <p className="text-meta text-muted">{t('sr.cov.noAgent', { count: noAgent })}</p> : null}
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="grid content-start gap-1.5">
            <p className="text-meta font-medium">{t('sr.cov.sources')}</p>
            <ul className="grid gap-1 text-meta">
              {c.sources.map((s) => (
                <li key={s.id} className="flex items-center justify-between gap-3 border-b border-rule pb-1 last:border-b-0">
                  <span>{t(`sr.source.${s.id}`, { defaultValue: s.id })}</span>
                  {s.on ? <Chip tone="ok">{t('sr.cov.on')}</Chip> : <Chip tone="off">{t('sr.cov.off')}</Chip>}
                </li>
              ))}
            </ul>
          </div>
          <div className="grid content-start gap-1.5">
            <p className="text-meta font-medium">{t('sr.cov.feeds')}</p>
            <ul className="grid gap-1 text-meta">
              {c.feeds.map((f) => (
                <li key={f.id} className="flex flex-wrap items-center justify-between gap-x-3 border-b border-rule pb-1 last:border-b-0">
                  <span className="font-medium">{f.name}</span>
                  <span className={f.stale ? 'font-medium text-warn' : 'text-muted'}>{!f.last_ok_at ? t('sr.cov.feedNever') : f.stale ? t('sr.cov.feedStale', { time: fmtDateTime(f.last_ok_at) }) : t('sr.cov.feedOk', { time: fmtDateTime(f.last_ok_at) })}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </section>
  )
}
