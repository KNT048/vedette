import { useTranslation } from 'react-i18next'
import { AiBlock } from '@/components/common/AiBlock'
import { Chip, StatusChip, type Tone } from '@/components/common/StatusChip'
import { fmtDate, fmtDateTime } from '@/lib/format'
import { Scroll } from './parts'
import type { PdplReport } from './types'

const MEASURE_TONE: Record<string, Tone> = { ok: 'ok', attention: 'warn', unknown: 'off' }

/** Báo cáo đánh giá an toàn theo Luật BVDLCN (S-REP-2). Câu miễn trừ nằm ở đầu và cuối mọi bản. */
export function PdplDocument({ report: r }: { report: PdplReport }) {
  const { t } = useTranslation('reports')
  const o = r.org
  const h = (id: string, key: string) => <h3 id={id} className="mb-2 text-base font-semibold">{t(key)}</h3>
  const disclaimer = (
    <div role="note" className="rounded-md border border-warn/50 bg-warn-soft px-4 py-3">
      <p className="font-semibold">{t('doc.pdpl.disclaimerTitle')}</p>
      <p className="text-[13px]">{t('doc.pdpl.disclaimerBody')}</p>
    </div>
  )
  return (
    <article className="grid grid-cols-[minmax(0,1fr)] gap-6 text-sm" aria-label={t('doc.pdpl.title')}>
      <header className="grid gap-1 border-b border-rule pb-3">
        <p className="text-[13px] text-muted">{o.name}</p>
        <h2 className="text-lg font-semibold">{t('doc.pdpl.title')}</h2>
        <p className="text-[13px] text-muted">{t('doc.pdpl.subtitle')}</p>
        <p className="text-[13px] text-muted">{t('doc.pdpl.generated', { time: fmtDateTime(r.generated_at) })}</p>
      </header>
      {disclaimer}

      <section aria-labelledby="pd-org">
        {h('pd-org', 'doc.pdpl.s.org')}
        <dl className="grid gap-x-6 gap-y-1 sm:grid-cols-[minmax(160px,max-content)_1fr]">
          {([['name', o.name], ['tax', o.tax_code], ['address', o.address], ['sector', t(`pdpl.sector.${o.sector}`, { defaultValue: o.sector })], ['employees', String(o.employees)], ['volume', t(`pdpl.volume.${o.data_volume}`)], ['size', t(`pdpl.size.${o.size}`)], ['service', o.processing_service ? t('doc.pdpl.yes') : t('doc.pdpl.no')], ['level', o.level ? t('doc.pdpl.levelValue', { level: o.level }) : t('doc.pdpl.levelNone')], ['contact', `${o.contact_name}, ${o.contact_email}, ${o.contact_phone}`],
            ['flags', [o.sensitive && t('pdpl.sensitive'), o.cross_border && t('pdpl.crossBorder'), o.processors && t('pdpl.processors')].filter(Boolean).join('; ') || t('doc.pdpl.noFlags')]] as [string, string][]).map(([k, v]) => (
            <div key={k} className="contents"><dt className="text-muted">{t(`doc.pdpl.org.${k}`)}</dt><dd>{v}</dd></div>
          ))}
        </dl>
        <p className="mt-2 text-[12px] text-muted">{t('doc.pdpl.levelNote')}</p>
      </section>

      <section aria-labelledby="pd-inv">
        {h('pd-inv', 'doc.pdpl.s.inventory')}
        <p>{t('doc.pdpl.inventorySummary', { total: r.inventory.total, approved: r.inventory.approved, unapproved: r.inventory.unapproved, fragile: r.inventory.fragile })}</p>
        {r.inventory.by_kind.length > 0 ? <p className="mt-1 text-muted">{t('doc.pdpl.byKind')} {r.inventory.by_kind.map((k) => `${t(`doc.kind.${k.kind}`, { defaultValue: k.kind })} ${k.n}`).join(', ')}.</p> : null}
        {r.inventory.key_systems.length === 0 ? <p className="mt-2 text-muted">{r.inventory.total === 0 ? t('doc.pdpl.noDevices') : t('doc.pdpl.noKeySystems')}</p> : <div className="mt-2"><Scroll>
          <table className="w-full border-collapse text-[13px]">
            <caption className="mb-1 text-left text-muted">{t('doc.pdpl.keyCaption')}</caption>
            <thead><tr className="border-b border-rule text-left text-muted"><th scope="col" className="py-1 pr-3 font-medium">{t('doc.col.device')}</th><th scope="col" className="py-1 pr-3 font-medium">IP</th><th scope="col" className="py-1 pr-3 font-medium">{t('doc.col.kind')}</th><th scope="col" className="py-1 font-medium">{t('doc.col.os')}</th></tr></thead>
            <tbody>{r.inventory.key_systems.map((k) => <tr key={k.id} className="border-b border-rule last:border-b-0"><td className="py-1 pr-3">{k.name}</td><td className="py-1 pr-3">{k.ip}</td><td className="py-1 pr-3">{t(`doc.kind.${k.kind}`, { defaultValue: k.kind })}</td><td className="py-1">{k.os}</td></tr>)}</tbody>
          </table>
        </Scroll></div>}
      </section>

      <section aria-labelledby="pd-mea">
        {h('pd-mea', 'doc.pdpl.s.measures')}
        <Scroll>
          <table className="w-full border-collapse text-[13px]" aria-labelledby="pd-mea">
            <thead><tr className="border-b border-rule text-left text-muted"><th scope="col" className="py-1 pr-3 font-medium">{t('doc.col.measure')}</th><th scope="col" className="py-1 pr-3 font-medium">{t('doc.col.status')}</th><th scope="col" className="py-1 font-medium">{t('doc.col.detail')}</th></tr></thead>
            <tbody>{r.measures.map((m) => (
              <tr key={m.id} className="border-b border-rule align-top last:border-b-0">
                <th scope="row" className="py-1 pr-3 text-left font-normal">{t(`doc.measure.${m.id}.title`)}</th>
                <td className="py-1 pr-3"><Chip tone={MEASURE_TONE[m.status] ?? 'off'}>{t(`doc.measureStatus.${m.status}`)}</Chip></td>
                <td className="py-1">{t(`doc.measure.${m.id}.${m.status}`, { n: m.n, names: m.names.join(', ') })}</td>
              </tr>
            ))}</tbody>
          </table>
        </Scroll>
      </section>

      <section aria-labelledby="pd-risk">
        {h('pd-risk', 'doc.pdpl.s.risks')}
        {r.risks.length === 0 ? <p className="text-muted">{t('doc.pdpl.noRisks')}</p> : (
          <Scroll>
            <table className="w-full border-collapse text-[13px]" aria-labelledby="pd-risk">
              <thead><tr className="border-b border-rule text-left text-muted"><th scope="col" className="py-1 pr-3 font-medium">{t('doc.col.device')}</th><th scope="col" className="py-1 pr-3 font-medium">{t('doc.col.cve')}</th><th scope="col" className="py-1 pr-3 font-medium">{t('doc.col.product')}</th><th scope="col" className="py-1 pr-3 font-medium">{t('doc.col.status')}</th><th scope="col" className="py-1 font-medium">{t('doc.col.since')}</th></tr></thead>
              <tbody>{r.risks.map((f) => <tr key={f.id} className="border-b border-rule last:border-b-0"><td className="py-1 pr-3">{f.device}</td><td className="py-1 pr-3">{f.cve}</td><td className="py-1 pr-3">{f.product}</td><td className="py-1 pr-3"><StatusChip status={f.status} /></td><td className="py-1">{fmtDate(f.since)}</td></tr>)}</tbody>
            </table>
          </Scroll>
        )}
      </section>

      <section aria-labelledby="pd-obl">
        {h('pd-obl', 'doc.pdpl.s.obligations')}
        <p className="mb-2 text-muted">{t('doc.pdpl.obligationsIntro')}</p>
        <ul className="grid gap-3">
          {r.obligations.filter((x) => x.applies).map((x) => (
            <li key={x.id} className="grid gap-0.5">
              <p className="flex flex-wrap items-center gap-2 font-medium">{t(`doc.obligation.${x.id}.title`)}
                {x.regime === 'required' ? <Chip tone={x.done ? 'ok' : 'warn'}>{x.done ? t('doc.pdpl.recorded') : t('doc.pdpl.todo')}</Chip> : <Chip tone="off">{t(`doc.pdpl.regime.${x.regime}`)}</Chip>}
                {x.regime !== 'required' && x.done ? <Chip tone="ok">{t('doc.pdpl.recorded')}</Chip> : null}
              </p>
              <p className="text-[13px] text-muted">{t(`doc.obligation.${x.id}.body`)}</p>
              {x.regime !== 'required' ? <p className="text-[13px] text-muted">{t('doc.pdpl.regimeNote')}</p> : null}
            </li>
          ))}
        </ul>
      </section>

      <section aria-labelledby="pd-cov">
        {h('pd-cov', 'doc.pdpl.s.coverage')}
        <p className="mb-1 text-muted">{t('doc.pdpl.coverageIntro')}</p>
        <ul className="grid gap-0.5">{r.coverage.map((c) => <li key={c.module}>{t(`doc.cov.${c.module}`)}: {c.on ? t('doc.pdpl.covOn') : t('doc.pdpl.covOff')}</li>)}</ul>
      </section>

      <section aria-labelledby="pd-basis">
        {h('pd-basis', 'doc.pdpl.s.basis')}
        <ul className="ml-5 grid list-disc gap-1 text-[13px] text-muted">{(t('doc.pdpl.basis', { returnObjects: true }) as string[]).map((b, i) => <li key={i}>{b}</li>)}</ul>
      </section>

      {r.ai_summary ? (
        <div className="grid gap-1">
          <AiBlock model={r.ai_summary.profile ? `${r.ai_summary.model} (${r.ai_summary.profile})` : r.ai_summary.model} tokens={r.ai_summary.tokens} citations={[{ title: t('doc.pdpl.aiCite') }]}>
            {r.ai_summary.paragraphs.map((p, i) => <p key={i}>{p}</p>)}
          </AiBlock>
          <p className="text-[12px] text-muted">{t('doc.aiAt', { time: fmtDateTime(r.ai_summary.generated_at) })}</p>
        </div>
      ) : null}

      {disclaimer}
      <div className="grid grid-cols-3 gap-6 pt-4 text-[13px]">
        {(['author', 'approver', 'date'] as const).map((k) => <div key={k} className="grid gap-8"><p className="text-muted">{t(`doc.pdpl.sign.${k}`)}</p><p className="border-t border-rule pt-1 text-[12px] text-muted">{k === 'date' ? fmtDate(r.generated_at) : ' '}</p></div>)}
      </div>
    </article>
  )
}
