import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { Section, Panel } from '@/components/common/PageHeader'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { SPAN_IN_UI } from '@/lib/span'
import { LOGIN_SERVICES } from './presets'
import type { HpService } from './types'

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

/** What really fires now (D-467: Coverage claims only that). services: the services some Trap IP listens on; listeningIps: how many Trap IPs listen.
 * Without one, nothing the traps would see is covered (2026-11-12 walk); URL tokens are answered by the box itself, so bait stays partly covered (W6-2).
 * Moving to shares needs SMB, stolen credentials need a service whose login names an account, and a sweep alert needs two Trap IPs: one alone
 * still alerts on each touch. */
export default function CoverageSection({ services, listeningIps }: { services: HpService[]; listeningIps: number }) {
  const { t } = useTranslation('honeypot')
  const listening = listeningIps > 0
  const needs: Record<string, { ok: boolean; why: string; level?: Level }> = {
    lateral: { ok: services.includes('smb'), why: 'howNoSmb' },
    credentials: { ok: services.some((s) => LOGIN_SERVICES.includes(s)), why: 'howNoLogin' },
    scanning: { ok: listeningIps >= 2, why: 'howOneTrap', level: 'partial' },
  }
  const level = (id: string, l: Level): Level => {
    if (l !== 'covered') return l
    if (!listening) return id === 'documents' ? 'partial' : 'none'
    const n = needs[id]
    return !n || n.ok ? l : (n.level ?? 'none')
  }
  const how = (id: string) => {
    if (id === 'outbound' && !SPAN_IN_UI) return 'howNoSpan'
    if (id === 'documents' && !listening) return 'howNoTrap'
    const n = needs[id]
    return listening && n && !n.ok ? n.why : 'how'
  }
  return (
    <Section id="coverage" title={t('coverage.title')} description={t('coverage.description')}>
      <Panel className="p-4">
        <ul className="grid divide-y divide-rule" aria-label={t('coverage.listLabel')}>
          {ROWS.map((r) => (
            <li key={r.id} className="grid gap-1 py-2.5 first:pt-0 last:pb-0 sm:grid-cols-[minmax(0,1fr)_auto] sm:gap-4">
              <span className="grid"><span className="text-sm font-medium">{t(`coverage.row.${r.id}.move`)}</span><span className="text-[13px] text-muted">{t(`coverage.row.${r.id}.${how(r.id)}`)}{r.id === 'outbound' ? <> <Link to="/logs" className="text-accent underline-offset-4 hover:underline">{t('coverage.openLogs')}</Link></> : null}</span></span>
              <span className="sm:justify-self-end"><Chip tone={TONE[level(r.id, r.level)]}>{t(`coverage.level.${level(r.id, r.level)}`)}</Chip></span>
            </li>
          ))}
        </ul>
        <p className="mt-3 text-[13px] text-muted">{listening ? t('coverage.note') : t('coverage.notListening')}</p>
      </Panel>
    </Section>
  )
}
