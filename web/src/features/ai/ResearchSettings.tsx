import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Section } from '@/components/common/PageHeader'
import { InfoTip } from '@/components/common/InfoTip'
import { Button } from '@/components/ui/button'
import { RadioGroup, RadioItem } from '@/components/ui/checkbox'
import { Field, Input, Label } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { fmtDate, fmtNumber } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useRuns, useSaveConfig } from './api'
import { ActionError } from './parts'
import type { AiConfigView, AiRun } from './types'

/** Tokens per researched CVE from this box's own run log: the research tokens of the last 30 days over the distinct CVEs researched. null when none. */
function measuredPerCve(runs: AiRun[] | undefined): number | null {
  const since = Date.now() - 30 * 86_400_000
  const mine = (runs ?? []).filter((r) => r.skill === 'research-cves' && r.status === 'ok' && new Date(r.ts).getTime() >= since)
  const cves = new Set(mine.map((r) => r.target).filter(Boolean))
  if (mine.length === 0 || cves.size === 0) return null
  return Math.round(mine.reduce((n, r) => n + r.tokens_in + r.tokens_out, 0) / cves.size)
}

const MODES = ['economy', 'balanced', 'thorough'] as const
type Mode = (typeof MODES)[number]

/** Settings, AI assistant: how the customer's own AI researches CVEs Vedette cannot decide (switch, mode, share of the monthly
 *  token budget, calls a day, what is sent). Tokens only, never money. */
export function ResearchForm({ cfg }: { cfg: AiConfigView }) {
  const { t } = useTranslation('ai')
  const admin = useCan('admin')
  const save = useSaveConfig()
  const fromLog = measuredPerCve(useRuns().data?.items)
  const [on, setOn] = useState(cfg.auto_read)
  const [mode, setMode] = useState<Mode>(cfg.research_mode)
  const [share, setShare] = useState(String(cfg.research_share))
  const [daily, setDaily] = useState(String(cfg.daily_reads))
  const [errs, setErrs] = useState<{ share?: string; daily?: string }>({})
  const reason = admin ? undefined : t('common:needRole', { role: t('common:role.admin') })
  const allowed = Math.floor((cfg.monthly_budget * cfg.research_share) / 100)
  const left = Math.max(0, allowed - cfg.research_used_month)
  function submit(e: React.FormEvent) {
    e.preventDefault()
    const s = Number(share)
    const d = Number(daily)
    const next: typeof errs = {}
    if (!Number.isInteger(s) || s < 1 || s > 100) next.share = t('settings.research.shareErr')
    if (!Number.isInteger(d) || d < 1 || d > 5000) next.daily = t('settings.research.err')
    setErrs(next)
    if (next.share || next.daily) return
    save.mutate({ tier: cfg.tier, monthly_budget: cfg.monthly_budget, redact_pii: cfg.redact_pii, auto_read: on, daily_reads: d, research_mode: mode, research_share: s },
      { onSuccess: () => toast.success(t('settings.saved')) })
  }
  const title = t('settings.research.title')
  return (
    <form onSubmit={submit} noValidate aria-label={title}>
      <Section title={title} description={t('settings.research.intro')} stories={['S-MIT-1', 'S-AI-6']}>
        <div className="flex items-start gap-3">
          <Switch id="ai-auto-read" checked={on} onCheckedChange={setOn} disabled={!admin} />
          <div className="grid gap-0.5">
            <Label htmlFor="ai-auto-read">{t('settings.research.switch')}</Label>
            <p className="text-meta text-muted">{t('settings.research.switchHint')}</p>
          </div>
        </div>
        <div className="mt-4 grid gap-2">
          <p className="text-sm font-medium">{t('settings.research.mode')}</p>
          <RadioGroup value={mode} onValueChange={(v) => setMode(v as Mode)} aria-label={t('settings.research.mode')} disabled={!admin || !on}>
            {MODES.map((k) => {
              const est = cfg.research_estimates[k]
              const figure = est.measured ? est.tokens : k === cfg.research_mode ? fromLog : null
              return (
                <div key={k} className="flex items-start gap-3 rounded-md border border-rule bg-surface p-3">
                  <RadioItem id={`ai-research-${k}`} value={k} className="mt-0.5" />
                  <div className="grid gap-0.5">
                    <Label htmlFor={`ai-research-${k}`}>{t(`settings.research.modes.${k}.name`)}</Label>
                    <p className="text-meta text-muted">{t(`settings.research.modes.${k}.what`)}</p>
                    {figure !== null ? <p className="text-meta text-muted">{t('settings.research.perCveMeasured', { tokens: fmtNumber(figure) })}</p> : null}
                  </div>
                </div>
              )
            })}
          </RadioGroup>
        </div>
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <Field label={t('settings.research.share')} htmlFor="ai-research-share" hint={t('settings.research.shareHint')} info={t('settings.research.shareInfo')} error={errs.share}>
            <div className="relative">
              <Input id="ai-research-share" type="number" min={1} max={100} step={1} value={share} onChange={(e) => { setShare(e.target.value); setErrs((x) => ({ ...x, share: undefined })) }} className="pr-8"
                disabled={!admin || !on} aria-invalid={errs.share ? true : undefined} aria-describedby={errs.share ? 'ai-research-share-error' : 'ai-research-share-hint'} />
              <span aria-hidden className="pointer-events-none absolute inset-y-0 right-3 flex items-center text-muted">{t('settings.research.unitPercent')}</span>
            </div>
            <p className={`text-meta ${left === 0 ? 'text-warn' : ''}`}>{t('settings.research.shareUse', { used: fmtNumber(cfg.research_used_month), allowed: fmtNumber(allowed), left: fmtNumber(left) })}</p>
            {left === 0 ? <p role="status" className="text-meta text-warn">{t('settings.research.shareOver', { date: fmtDate(cfg.renews_on) })}</p> : null}
          </Field>
          <Field label={t('settings.research.daily')} htmlFor="ai-daily-reads" hint={t('settings.research.dailyHint')} info={t('settings.research.dailyInfo')} error={errs.daily}>
            <Input id="ai-daily-reads" type="number" min={1} max={5000} step={1} value={daily} onChange={(e) => { setDaily(e.target.value); setErrs((x) => ({ ...x, daily: undefined })) }}
              disabled={!admin || !on} aria-invalid={errs.daily ? true : undefined} aria-describedby={errs.daily ? 'ai-daily-reads-error' : 'ai-daily-reads-hint'} />
            <p className="text-meta">{t('settings.research.today', { used: fmtNumber(cfg.reads_today), daily: fmtNumber(cfg.daily_reads) })}</p>
          </Field>
        </div>
        <details className="mt-4 rounded-md border border-rule bg-surface p-3 text-sm">
          <summary className="cursor-pointer font-medium">{t('settings.research.sentTitle')}</summary>
          <p className="mt-2 text-muted">{t('settings.research.sentBody')}</p>
          <div className="mt-1"><InfoTip topic={t('settings.research.sentTitle')}>{t('settings.research.info')}</InfoTip></div>
        </details>
        {save.error ? <div className="mt-3"><ActionError error={save.error} /></div> : null}
        <div className="mt-4"><Button type="submit" variant="primary" disabled={!admin} busy={save.isPending} busyLabel={t('common:busy.saving')} title={reason}>{t('common:save')}</Button></div>
      </Section>
    </form>
  )
}
