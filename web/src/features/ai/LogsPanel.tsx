import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { AiBlock } from '@/components/common/AiBlock'
import { EmptyState, ErrorState, Loading, ModuleOff } from '@/components/common/States'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useDigest, useRefreshDigest } from './api'
import { ActionError, ToSettings, useAiGate } from './parts'

const SEV: Record<string, Tone> = { high: 'danger', medium: 'warn', info: 'off' }

/** Slot `logs.panels` (S-AI-4): digest log bằng AI theo mức đã chọn. Log là dữ liệu không tin cậy; AI chỉ tóm tắt, không hành động. */
export default function LogsPanel() {
  const { t } = useTranslation('ai')
  const admin = useCan('admin') // the Memory tab is the administrator's (S-AI-7)
  const gate = useAiGate('operator', 'log-digest')
  const digest = useDigest()
  const refresh = useRefreshDigest()
  if (gate.state === 'loading') return null
  if (gate.state === 'off') return <Section title={t('logs.title')}><ModuleOff module="ai" /></Section>
  const d = refresh.data?.digest ?? digest.data?.digest ?? undefined // null = nothing generated yet (INV-6)
  return (
    <Section title={t('logs.title')} description={t('logs.description')} stories={['S-AI-4']}
      actions={<Button onClick={() => refresh.mutate()} disabled={!gate.canRun || refresh.isPending || d?.empty === true} title={gate.reason ?? (d?.empty ? d.summary : undefined)}>{refresh.isPending ? t('logs.working') : t('logs.refresh')}</Button>}>
      {gate.state === 'unconfigured' || gate.state === 'unassigned' ? <EmptyState title={t(`gate.${gate.state}`)}>{t(`gate.${gate.state}Body`)} <ToSettings /></EmptyState> : null}
      <ActionError error={refresh.error} />
      {gate.state === 'ready' && digest.isPending ? <Loading /> : null}
      {gate.state === 'ready' && digest.error && !d ? <ErrorState error={digest.error} onRetry={() => void digest.refetch()} /> : null}
      {gate.state === 'ready' && digest.data && !d ? <p className="text-sm text-muted">{t('logs.none')}</p> : null}
      {d?.empty ? <p className="text-sm text-muted">{d.summary}</p> : null}
      {d && !d.empty ? (
        <div className="grid gap-2">
          <p className="text-[13px] text-muted">{t('logs.tier', { tier: t(`settings.tier.${d.tier}.name`), cadence: d.cadence })} <ToSettings /></p>
          <AiBlock model={`${d.model} (${d.profile})`} tokens={d.tokens} citations={d.items.length ? [{ title: t('logs.cite') }] : []}>
            <p>{d.summary}</p>
            <ul className="grid gap-4">
              {d.items.length === 0 ? <li className="text-muted">{t('logs.noItems')}</li> : d.items.map((it, i) => (
                <li key={i} className="grid gap-1.5">
                  <p className="flex flex-wrap items-center gap-2 font-medium"><Chip tone={SEV[it.severity] ?? 'off'}>{t(`logs.severity.${it.severity}`)}</Chip>{it.title}</p>
                  <pre tabIndex={0} className="overflow-x-auto rounded-md bg-sunken p-2 font-mono text-[12px] leading-relaxed">{it.evidence.join('\n')}</pre>
                  <p>{it.recommendation}{it.asset_id ? <> <Link to={`/devices/${it.asset_id}`} className="text-accent underline underline-offset-4">{t('logs.device')}</Link></> : null}</p>
                </li>
              ))}
            </ul>
            {d.tool_calls.length ? (
              <div>
                <p className="font-medium">{t('logs.tools')}</p>
                <ul className="grid gap-1 text-[13px]">{d.tool_calls.map((c, i) => <li key={i}><code className="font-mono text-[12.5px]">{c.tool}({c.args})</code> <span className="text-muted">{t('ask.toolResult', { result: c.result })}</span></li>)}</ul>
              </div>
            ) : null}
          </AiBlock>
          {d.memories_suggested > 0 ? <p className="text-[13px]">{t('logs.suggested', { count: d.memories_suggested })} {admin ? <Link to="/settings/ai?tab=memory" className="text-accent underline underline-offset-4">{t('logs.suggestedLink')}</Link> : null}</p> : null}
          <p className="text-[12px] text-muted">{t('logs.meta', { time: fmtDateTime(d.generated_at) })}</p>
        </div>
      ) : null}
    </Section>
  )
}
