import { useQuery } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { Card } from '@/components/common/Card'
import { Section } from '@/components/common/PageHeader'
import { Chip } from '@/components/common/StatusChip'
import { api } from '@/lib/api'
import { fmtDateTime, fmtNumber } from '@/lib/format'
import type { PossibleCheck, PossibleRow } from '@/features/findings/types'

type Reading = NonNullable<PossibleCheck['reading']>
type Line = { line: string; check: PossibleCheck; reading: Reading; devices: number }

const TONE = { affected: 'danger', fixed: 'danger', not_affected: 'ok', unsure: 'warn' } as const
const safeUrl = (u: string) => { try { const x = new URL(u); return x.protocol === 'https:' || x.protocol === 'http:' ? x.href : null } catch { return null } }

/** The researched lines of one CVE: one entry per release line, since every device on a line shares the answer. */
function useCveResearch(cve: string) {
  return useQuery({
    queryKey: ['ai', 'research', cve],
    queryFn: async (): Promise<Line[]> => {
      const r = await api.get<{ items: PossibleRow[] }>(`/findings/possible?q=${encodeURIComponent(cve)}&limit=200`)
      const by = new Map<string, Line>()
      for (const row of r.items) {
        if (row.cve !== cve || !row.check?.reading?.research) continue
        const k = row.check.reading.line
        const e = by.get(k)
        if (e) e.devices++
        else by.set(k, { line: k, check: row.check, reading: row.check.reading, devices: 1 })
      }
      return [...by.values()]
    },
  })
}

/** Slot `cve.panels`: what the customer's AI found for each release line of this CVE, with the quote it relies on and how the box checked it. */
export default function ResearchPanel({ cve }: { cve: string }) {
  const { t } = useTranslation('ai')
  const q = useCveResearch(cve)
  if (!q.data?.length) return null
  return (
    <Section title={t('cve.research.title')} description={t('cve.research.intro')}>
      <div className="grid gap-3">{q.data.map((l) => <LineCard key={l.line} l={l} />)}</div>
    </Section>
  )
}

function LineCard({ l }: { l: Line }) {
  const { t } = useTranslation('ai')
  const { reading: r, check: c } = l
  const res = r.research!
  const d = res.detail
  const cited = c.sources.find((s) => s.cited)
  const href = cited ? safeUrl(cited.url) : r.host ? safeUrl(`https://${r.host}`) : null
  const pages = [...new Set(d.steps.flatMap((s) => s.pages))]
  return (
    <Card className="grid gap-2" aria-label={t('cve.research.line', { line: l.line })}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{t('cve.research.line', { line: l.line })}</span>
        <Chip tone={TONE[r.status]}>{t(`cve.research.verdict.${r.status}`)}</Chip>
        <Chip tone={d.basis === 'inferred' ? 'warn' : 'off'}>{t(d.basis === 'inferred' ? 'cve.research.basis.inferred' : 'cve.research.basis.stated')}</Chip>
        {r.fixed_in ? <span className="text-sm">{t('cve.research.fixedIn', { version: r.fixed_in })}</span> : null}
        <span className="text-meta text-muted">{t('cve.research.devices', { count: l.devices })}</span>
      </div>
      <div>
        <p className="text-caption text-muted">{t('cve.research.quote')}</p>
        {c.quote ? <blockquote lang="en" className="border-l-2 border-rule pl-3 text-sm">{c.quote}</blockquote> : <p className="text-sm text-muted">{t('cve.research.noQuote')}</p>}
        <p className={`text-meta ${res.quote_check === 'not_found' ? 'text-warn' : 'text-muted'}`}>{t(`cve.research.quoteCheck.${res.quote_check}`)}</p>
        <p className="text-meta">
          {href ? <a href={href} target="_blank" rel="noopener noreferrer" className="text-accent underline-offset-4 hover:underline">{t('cve.research.source', { host: r.host ?? new URL(href).host })}</a>
            : <span className="text-muted">{t('cve.research.sourceRecord')}</span>}
        </p>
      </div>
      <p className="text-meta text-muted">
        {[c.model ?? d.steps.at(-1)?.model, t('cve.research.tokens', { tokens: fmtNumber(res.tokens) }), t(`cve.research.layer.${res.layer}`), t('cve.research.when', { time: fmtDateTime(c.checked_at) })].filter(Boolean).join(' · ')}
      </p>
      <details className="text-sm">
        <summary className="cursor-pointer font-medium">{t('cve.research.how')}</summary>
        <ol className="mt-2 grid gap-1">
          {d.steps.map((s, i) => (
            <li key={i}>
              <span className="font-medium">{t('cve.research.step', { n: i + 1, layer: t(`cve.research.stepLayer.${s.layer}`), verdict: s.verdict || t('cve.research.stepNone') })}</span>{' '}
              <span className="text-muted">{s.model} · {t('cve.research.stepFacts', { tokens: fmtNumber(s.tokens_in + s.tokens_out), pages: s.pages.length })}</span>
              {s.error ? <span className="block text-meta text-warn">{s.error}</span> : null}
            </li>
          ))}
        </ol>
        <p className="mt-2 text-caption text-muted">{t('cve.research.pages')}</p>
        {pages.length ? <ul className="ml-5 list-disc">{pages.map((p) => { const u = safeUrl(p); return <li key={p} className="break-all">{u ? <a href={u} target="_blank" rel="noopener noreferrer" className="text-accent underline-offset-4 hover:underline">{p}</a> : p}</li> })}</ul> : <p className="text-muted">{t('cve.research.noPages')}</p>}
        {d.note ? <p className="mt-2 text-meta text-warn">{t('cve.research.note')}: {d.note}</p> : null}
      </details>
    </Card>
  )
}
