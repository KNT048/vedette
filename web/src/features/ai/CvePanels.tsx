import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Card } from '@/components/common/Card'
import { Section } from '@/components/common/PageHeader'
import { AiBlock } from '@/components/common/AiBlock'
import { EmptyState, ModuleOff } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { BusyNote } from '@/components/common/BusyNote'
import { InfoTip } from '@/components/common/InfoTip'
import { Button } from '@/components/ui/button'
import { fmtDateTime } from '@/lib/format'
import { useCveCached, useExplain, useNews } from './api'
import { ActionError, ToSettings, useAiGate } from './parts'
import type { ExplainResult, FetchedSource, NewsResult } from './types'

/** Slot `cve.panels` (S-AI-2/S-AI-3): one "Ask my AI" button with four answers and an option to include the latest news. The box fetches the news sources; the AI does not browse the web. */
export default function CvePanels({ cve }: Record<string, unknown>) {
  const id = String(cve ?? '')
  const gate = useAiGate('operator')
  if (gate.state === 'loading') return null
  if (gate.state === 'off') return <Section title="AI"><ModuleOff module="ai" /></Section>
  return <Panels id={id} />
}

function Panels({ id }: { id: string }) {
  const { t } = useTranslation('ai')
  const [includeNews, setIncludeNews] = useState(false)
  const gateAsk = useAiGate('operator', 'explain-finding')
  const gateNews = useAiGate('operator', 'cve-news')
  const cached = useCveCached(id)
  const explain = useExplain(id)
  const news = useNews(id)
  const ex = explain.data ?? cached.data?.explain ?? null
  const nw = news.data ?? cached.data?.news ?? null
  const newsOk = !includeNews || gateNews.canRun
  const busy = explain.isPending || news.isPending
  const ask = async () => {
    try {
      await explain.mutateAsync()
      if (includeNews) await news.mutateAsync()
    } catch {
      // the error of the failed call is shown below it
    }
  }
  return (
    <Section title={t('cve.askTitle')} description={t('cve.askDesc')} info={t('cve.askDescInfo')} stories={['S-AI-3']}
      actions={<Button onClick={() => void ask()} disabled={!gateAsk.canRun || !newsOk} busy={busy} busyLabel={t('common:busy.asking')} title={gateAsk.reason}>{ex ? t('cve.askAgain') : t('cve.ask')}</Button>}>
      <div className="flex items-center gap-2 text-sm">
        <label className="flex items-center gap-2">
          <input type="checkbox" checked={includeNews} onChange={(e) => setIncludeNews(e.target.checked)} disabled={!gateNews.canRun} />
          {t('cve.includeNews')}
        </label>
        <InfoTip topic={t('cve.includeNews')}>{t('cve.includeNewsInfo')}</InfoTip>
      </div>
      {/* An AI answer takes 10–90 s; say so while it runs */}
      <BusyNote busy={busy}>{news.isPending ? t('cve.newsWaiting') : t('cve.askWaiting')}</BusyNote>
      {blocked(gateAsk.state) ? <EmptyState title={t(`gate.${gateAsk.text}`)} info={t(`gate.${gateAsk.text}Info`, { defaultValue: '' }) || undefined}>{t(`gate.${gateAsk.text}Body`)} <ToSettings state={gateAsk.text} job="explain-finding" /></EmptyState> : null}
      <ActionError error={explain.error} />
      <ActionError error={news.error} />
      {ex ? <Answers r={ex} /> : null}
      {nw && (includeNews || news.data) ? <News r={nw} /> : null}
    </Section>
  )
}

const blocked = (st: string) => st === 'unconfigured' || st === 'unassigned'
const AFF = { yes: 'danger', unknown: 'warn', no: 'ok' } as const

function Answers({ r }: { r: ExplainResult }) {
  const { t } = useTranslation('ai')
  return (
    <div className="grid gap-2">
      <AiBlock model={`${r.model} (${r.profile})`} tokens={r.cached ? undefined : r.tokens} citations={r.citations}>
        <p><Chip tone={AFF[r.affected]}>{t(`cve.affected.${r.affected}`)}</Chip></p>
        {r.answers.map((a) => (
          <div key={a.key}>
            <p className="font-medium">{t(`cve.answer.${a.key}`)}</p>
            <p>{a.text}</p>
            {a.links.length ? <ul className="ml-5 list-disc">{a.links.map((l) => <li key={l.url}><a href={l.url} target="_blank" rel="noopener noreferrer" className="text-accent underline-offset-4 hover:underline">{l.title}</a></li>)}</ul> : null}
          </div>
        ))}
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
