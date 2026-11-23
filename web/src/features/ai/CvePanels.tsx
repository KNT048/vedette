import { useTranslation } from 'react-i18next'
import { Card } from '@/components/common/Card'
import { Section } from '@/components/common/PageHeader'
import { AiBlock } from '@/components/common/AiBlock'
import { EmptyState, ModuleOff } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from '@/components/ui/button'
import { fmtDateTime } from '@/lib/format'
import { useCveCached, useExplain, useNews } from './api'
import { ActionError, ToSettings, useAiGate } from './parts'
import type { ExplainResult, FetchedSource, NewsResult } from './types'

/** Slot `cve.panels` (S-AI-2/S-AI-3): explanation and news. The box fetches the news sources itself; the AI does not browse the web. */
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
      <Section title={t('cve.explainTitle')} description={t('cve.explainDesc')} info={t('cve.explainDescInfo')} stories={['S-AI-3']}
        actions={<Button onClick={() => explain.mutate()} disabled={!gateExplain.canRun} busy={explain.isPending} busyLabel={t('common:busy.asking')} title={gateExplain.reason}>{ex ? t('cve.explainAgain') : t('cve.explain')}</Button>}>
        {/* An AI answer takes 10–90 s; say so while it runs */}
        <BusyNote busy={explain.isPending}>{t('cve.explainWaiting')}</BusyNote>
        {blocked(gateExplain.state) ? <EmptyState title={t(`gate.${gateExplain.text}`)} info={t(`gate.${gateExplain.text}Info`, { defaultValue: '' }) || undefined}>{t(`gate.${gateExplain.text}Body`)} <ToSettings state={gateExplain.text} job="explain-finding" /></EmptyState> : null}
        <ActionError error={explain.error} />
        {ex ? <Explain r={ex} /> : !blocked(gateExplain.state) && !explain.error ? <p className="text-sm text-muted">{t('cve.explainEmpty')}</p> : null}
      </Section>
      <Section title={t('cve.newsTitle')} description={t('cve.newsDesc')} info={t('cve.newsDescInfo')} stories={['S-AI-3']}
        actions={<Button onClick={() => news.mutate()} disabled={!gateNews.canRun} busy={news.isPending} busyLabel={t('common:busy.asking')} title={gateNews.reason}>{nw ? t('cve.newsAgain') : t('cve.news')}</Button>}>
        <BusyNote busy={news.isPending}>{t('cve.newsWaiting')}</BusyNote>
        {blocked(gateNews.state) ? <EmptyState title={t(`gate.${gateNews.text}`)} info={t(`gate.${gateNews.text}Info`, { defaultValue: '' }) || undefined}>{t(`gate.${gateNews.text}Body`)} <ToSettings state={gateNews.text} job="cve-news" /></EmptyState> : null}
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
      <p className="text-caption text-muted">{r.cached ? t('cve.cached', { time: fmtDateTime(r.generated_at) }) : t('cve.generated', { time: fmtDateTime(r.generated_at) })}</p>
    </div>
  )
}

function SourceList({ sources }: { sources: FetchedSource[] }) {
  const { t } = useTranslation('ai')
  return (
    <Card flush level={3} title={t('cve.fetched')}>
      <ul className="grid divide-y divide-rule text-sm">
        {sources.map((s) => (
          <li key={s.url} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
            <span className="grid"><a href={s.url} target="_blank" rel="noopener noreferrer" className="text-accent underline-offset-4 hover:underline">{s.title}</a><span className="text-caption text-muted">{s.note}</span></span>
            <Chip tone={s.status === 'ok' ? 'ok' : 'warn'}>{t(`cve.source.${s.status}`)}</Chip>
          </li>
        ))}
      </ul>
    </Card>
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
      <p className="text-caption text-muted">{t('cve.newsMeta', { time: fmtDateTime(r.generated_at) })}</p>
    </div>
  )
}
