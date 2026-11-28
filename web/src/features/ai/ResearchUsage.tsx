import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Card } from '@/components/common/Card'
import { Section } from '@/components/common/PageHeader'
import { dayOf, fmtDayMonth, fmtNumber } from '@/lib/format'
import { useRuns } from './api'

const DAYS = 14
const DAY_MS = 86_400_000

/** Usage tab: the tokens the research of CVEs used on each of the last 14 days (every layer), from the run log. Tokens only. */
export default function ResearchUsage() {
  const { t } = useTranslation('ai')
  const runs = useRuns()
  const [now] = useState(() => Date.now())
  if (!runs.data) return null
  const days = Array.from({ length: DAYS }, (_, i) => { const key = dayOf(new Date(now - (DAYS - 1 - i) * DAY_MS).toISOString()); return { key, label: fmtDayMonth(key), tokens: 0 } })
  for (const r of runs.data.items) {
    if (r.skill !== 'research-cves') continue
    const day = days.find((d) => d.key === dayOf(r.ts))
    if (day) day.tokens += r.tokens_in + r.tokens_out
  }
  const max = Math.max(...days.map((d) => d.tokens))
  return (
    <Section title={t('meter.research.title')} stories={['S-AI-4', 'S-AI-6']}>
      {max === 0 ? <p className="text-sm text-muted">{t('meter.research.none')}</p> : (
        <Card>
          <ul aria-label={t('meter.research.caption')} className="flex h-32 items-end gap-1">
            {days.map((d) => (
              <li key={d.key} className="flex h-full flex-1 flex-col justify-end" title={t('meter.research.day', { day: d.label, tokens: fmtNumber(d.tokens) })}>
                <span className="sr-only">{t('meter.research.day', { day: d.label, tokens: fmtNumber(d.tokens) })}</span>
                <div aria-hidden className="w-full rounded-t-sm bg-accent" style={{ height: `${Math.round((d.tokens / max) * 100)}%`, minHeight: d.tokens ? 2 : 0 }} />
              </li>
            ))}
          </ul>
          <div aria-hidden className="mt-1 flex justify-between text-caption text-muted"><span>{days[0]!.label}</span><span>{days[DAYS - 1]!.label}</span></div>
        </Card>
      )}
    </Section>
  )
}
