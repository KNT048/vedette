import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { AiBlock } from '@/components/common/AiBlock'
import { EmptyState, ModuleOff } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { fmtDateTime } from '@/lib/format'
import { useCveCached, useExplain, useNews } from './api'
import { ActionError, ToSettings, useAiGate } from './parts'
import type { ExplainResult, FetchedSource, NewsResult } from './types'

/** Slot `cve.panels` (S-AI-2/S-AI-3): giải thích tiếng Việt và tin mới. Nguồn tin do hộp tự tải; AI không tự duyệt web. */
export default function CvePanels({ cve }: Record<string, unknown>) {
  const id = String(cve ?? '')
  const gate = useAiGate('operator')
  if (gate.state === 'loading') return null
  if (gate.state === 'off') return <Section title="AI"><ModuleOff module="ai" /></Section>
  return <Panels id={id} />
}

function Panels({ id }: { id: string }) {
  const { t } = useTranslation('ai')
  const gateExplain = useAiGate('operator', 'explain-finding')
  const gateNews = useAiGate('operator', 'cve-news')
  const cached = useCveCached(id)
  const explain = useExplain(id)
  const news = useNews(id)
  const ex = explain.data ?? cached.data?.explain ?? null
  const nw = news.data ?? cached.data?.news ?? null
  return (
    <>
      <Section title={t('cve.explainTitle')} description={t('cve.explainDesc')} stories={['S-AI-3']}
        actions={<Button onClick={() => explain.mutate()} disabled={!gateExplain.canRun || explain.isPending} title={gateExplain.reason}>{explain.isPending ? t('cve.working') : ex ? t('cve.explainAgain') : t('cve.explain')}</Button>}>
        {blocked(gateExplain.state) ? <EmptyState title={t(`gate.${gateExplain.state}`)}>{t(`gate.${gateExplain.state}Body`)} <ToSettings /></EmptyState> : null}
        <ActionError error={explain.error} />
        {ex ? <Explain r={ex} /> : !blocked(gateExplain.state) && !explain.error ? <p className="text-sm text-muted">{t('cve.explainEmpty')}</p> : null}
      </Section>
      <Section title={t('cve.newsTitle')} description={t('cve.newsDesc')} stories={['S-AI-3']}
        actions={<Button onClick={() => news.mutate()} disabled={!gateNews.canRun || news.isPending} title={gateNews.reason}>{news.isPending ? t('cve.working') : nw ? t('cve.newsAgain') : t('cve.news')}</Button>}>
        {blocked(gateNews.state) ? <EmptyState title={t(`gate.${gateNews.state}`)}>{t(`gate.${gateNews.state}Body`)} <ToSettings /></EmptyState> : null}
        <ActionError error={news.error} />
        {nw ? <News r={nw} /> : !blocked(gateNews.state) && !news.error ? <p className="text-sm text-muted">{t('cve.newsEmpty')}</p> : null}
      </Section>
    </>
  )
}

const blocked = (st: string) => st === 'unconfigured' || st === 'unassigned'
const AFF = { yes: 'danger', unknown: 'warn', no: 'ok' } as const

function Explain({ r }: { r: ExplainResult }) {
  const { t } = useTranslation('ai')
  return (
    <div className="grid gap-2">
      <AiBlock model={`${r.model} (${r.profile})`} tokens={r.cached ? undefined : r.tokens} citations={r.citations}>
        <p><Chip tone={AFF[r.affected]}>{t(`cve.affected.${r.affected}`)}</Chip></p>
        <p>{r.why}</p>
        {r.patch_steps.length ? <div><p className="font-medium">{t('cve.patch')}</p><ol className="ml-5 list-decimal">{r.patch_steps.map((s, i) => <li key={i}>{s}</li>)}</ol></div> : null}
        {r.temp_mitigations.length ? <div><p className="font-medium">{t('cve.temp')}</p><ul className="ml-5 list-disc">{r.temp_mitigations.map((s, i) => <li key={i}>{s}</li>)}</ul></div> : null}
        {r.detection_hints.length ? <div><p className="font-medium">{t('cve.detect')}</p><ul className="ml-5 list-disc">{r.detection_hints.map((s, i) => <li key={i}>{s}</li>)}</ul></div> : null}
      </AiBlock>
      <p className="text-[12px] text-muted">{r.cached ? t('cve.cached', { time: fmtDateTime(r.generated_at) }) : t('cve.generated', { time: fmtDateTime(r.generated_at) })}</p>
    </div>
  )
}

function SourceList({ sources }: { sources: FetchedSource[] }) {
  const { t } = useTranslation('ai')
  return (
    <div>
      <p className="mb-1 text-sm font-medium">{t('cve.fetched')}</p>
      <ul className="grid divide-y divide-rule rounded-md border border-rule bg-surface text-sm">
        {sources.map((s) => (
          <li key={s.url} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
            <span className="grid"><a href={s.url} target="_blank" rel="noopener noreferrer" className="text-accent underline-offset-4 hover:underline">{s.title}</a><span className="text-[12px] text-muted">{s.note}</span></span>
            <Chip tone={s.status === 'ok' ? 'ok' : 'warn'}>{t(`cve.source.${s.status}`)}</Chip>
          </li>
        ))}
      </ul>
    </div>
  )
}

function News({ r }: { r: NewsResult }) {
  const { t } = useTranslation('ai')
  return (
    <div className="grid gap-3">
      <SourceList sources={r.sources} />
      <AiBlock model={`${r.model} (${r.profile})`} tokens={r.tokens} citations={r.citations}>
        {r.lines.map((l, i) => <p key={i}>{l}</p>)}
      </AiBlock>
      <p className="text-[12px] text-muted">{t('cve.newsMeta', { time: fmtDateTime(r.generated_at) })}</p>
    </div>
  )
}
