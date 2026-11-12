import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { Section, Panel } from '@/components/common/PageHeader'
import { Chip, type Tone } from '@/components/common/StatusChip'

type Level = 'covered' | 'partial' | 'none'
const TONE: Record<Level, Tone> = { covered: 'ok', partial: 'warn', none: 'off' }
// Static guidance, not a score (S-HP-2). Each row: an attacker move and whether traps and tokens see it.
const ROWS: { id: string; level: Level }[] = [
  { id: 'lateral', level: 'covered' },
  { id: 'credentials', level: 'covered' },
  { id: 'scanning', level: 'covered' },
  { id: 'documents', level: 'covered' },
  { id: 'outbound', level: 'partial' },
  { id: 'endpoint', level: 'none' },
  { id: 'email', level: 'none' },
]

/** listening: at least one trap really listens. Without one, nothing the traps would see is covered, and the list says so (2026-11-12 walk). */
export default function CoverageSection({ listening }: { listening: boolean }) {
  const { t } = useTranslation('honeypot')
  const level = (l: Level): Level => (listening || l !== 'covered' ? l : 'none')
  return (
    <Section id="coverage" title={t('coverage.title')} description={t('coverage.description')}>
      <Panel className="p-4">
        <ul className="grid divide-y divide-rule" aria-label={t('coverage.listLabel')}>
          {ROWS.map((r) => (
            <li key={r.id} className="grid gap-1 py-2.5 first:pt-0 last:pb-0 sm:grid-cols-[minmax(0,1fr)_auto] sm:gap-4">
              <span className="grid"><span className="text-sm font-medium">{t(`coverage.row.${r.id}.move`)}</span><span className="text-[13px] text-muted">{t(`coverage.row.${r.id}.how`)}{r.id === 'outbound' ? <> <Link to="/logs" className="text-accent underline-offset-4 hover:underline">{t('coverage.openLogs')}</Link></> : null}</span></span>
              <span className="sm:justify-self-end"><Chip tone={TONE[level(r.level)]}>{t(`coverage.level.${level(r.level)}`)}</Chip></span>
            </li>
          ))}
        </ul>
        <p className="mt-3 text-[13px] text-muted">{listening ? t('coverage.note') : t('coverage.notListening')}</p>
      </Panel>
    </Section>
  )
}
