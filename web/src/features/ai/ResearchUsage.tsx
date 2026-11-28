import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Card } from '@/components/common/Card'
import { Section } from '@/components/common/PageHeader'
import { fmtNumber } from '@/lib/format'
import { useRuns } from './api'

const DAYS = 14
const dayKey = (d: Date) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`

/** Usage tab: the tokens the research of CVEs used on each of the last 14 days (every layer), from the run log. Tokens only. */
export default function ResearchUsage() {
  const { t } = useTranslation('ai')
  const runs = useRuns()
  const [today] = useState(() => new Date())
  if (!runs.data) return null
  const days = Array.from({ length: DAYS }, (_, i) => { const d = new Date(today.getFullYear(), today.getMonth(), today.getDate() - (DAYS - 1 - i)); return { key: dayKey(d), label: d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }), tokens: 0 } })
  for (const r of runs.data.items) {
    if (r.skill !== 'research-cves') continue
    const day = days.find((d) => d.key === dayKey(new Date(r.ts)))
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
