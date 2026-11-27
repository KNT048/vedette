import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { InfoTip } from '@/components/common/InfoTip'
import { Section } from '@/components/common/PageHeader'
import { Card } from '@/components/common/Card'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { ListRow, RowList } from '@/components/common/ListParts'
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

/** Row lines whose detail sits behind ⓘ (#824). */
const ROW_INFO = new Set(['howNoLogin', 'howOneTrap'])

/** Where a row's gap is closed, for an administrator: the Trap IPs tab with the Add dialog open on a look that has what is
 *  missing, or the Tokens tab, where the ready-made decoys switch on in one click. */
const FIX: Record<string, { to: string; label: string }> = {
  howNoSmb: { to: '?tab=trap-ips&add=file_server#trap-ips', label: 'addSmb' },
  howNoLogin: { to: '?tab=trap-ips&add=linux#trap-ips', label: 'addLogin' },
  howOneTrap: { to: '?tab=trap-ips&add=suggested#trap-ips', label: 'addSecond' },
  howNoBait: { to: '?tab=tokens#tokens', label: 'addToken' },
}

/** What really fires now (Coverage claims only that). services: the services some Trap IP listens on; listeningIps: how many Trap IPs listen;
 * bait: how many decoy files and URL tokens exist (undefined while unknown); admin: the reader may add Trap IPs and tokens.
 * Without a listening Trap IP, nothing the traps would see is covered; URL tokens are answered by the box itself, so bait stays
 * partly covered, and only once a decoy file or URL token exists. Moving to shares needs SMB, stolen credentials need a service whose login
 * names an account, and a sweep alert needs two Trap IPs: one alone still alerts on each touch. Each gap a person can close carries its action. */
export default function CoverageSection({ services, listeningIps, bait, admin = false }: { services: HpService[]; listeningIps: number; bait?: number; admin?: boolean }) {
  const { t } = useTranslation('honeypot')
  const listening = listeningIps > 0
  const noBait = bait === 0
  const needs: Record<string, { ok: boolean; why: string; level?: Level }> = {
    lateral: { ok: services.includes('smb'), why: 'howNoSmb' },
    credentials: { ok: services.some((s) => LOGIN_SERVICES.includes(s)), why: 'howNoLogin' },
    scanning: { ok: listeningIps >= 2, why: 'howOneTrap', level: 'partial' },
  }
  const level = (id: string, l: Level): Level => {
    if (l !== 'covered') return l
    if (id === 'documents' && noBait) return 'none'
    if (!listening) return id === 'documents' ? 'partial' : 'none'
    const n = needs[id]
    return !n || n.ok ? l : (n.level ?? 'none')
  }
  const how = (id: string) => {
    if (id === 'outbound' && !SPAN_IN_UI) return 'howNoSpan'
    if (id === 'documents' && noBait) return 'howNoBait'
    if (id === 'documents' && !listening) return 'howNoTrap'
    const n = needs[id]
    return listening && n && !n.ok ? n.why : 'how'
  }
  const fix = (id: string) => (admin ? FIX[how(id)] : undefined)
  return (
    <Section id="coverage" title={t('coverage.title')} description={t('coverage.description')} info={<><p>{t('coverage.descriptionInfo')}</p><p>{t('coverage.note')}</p></>}>
      <Card>
        <RowList label={t('coverage.listLabel')}>
          {ROWS.map((r) => {
            const f = fix(r.id)
            return (
              <ListRow key={r.id} title={t(`coverage.row.${r.id}.move`)} badges={<Chip tone={TONE[level(r.id, r.level)]}>{t(`coverage.level.${level(r.id, r.level)}`)}</Chip>}
                meta={[
                  <span key="how">{t(`coverage.row.${r.id}.${how(r.id)}`)}{ROW_INFO.has(how(r.id)) ? <InfoTip topic={t(`coverage.row.${r.id}.move`)}>{t(`coverage.row.${r.id}.${how(r.id)}Info`)}</InfoTip> : null}{r.id === 'outbound' ? <> <Link to="/logs" className="text-accent underline-offset-4 hover:underline">{t('coverage.openLogs')}</Link></> : null}</span>,
                  f ? <Link key="fix" to={f.to} className="font-medium text-accent underline underline-offset-4">{t(`coverage.fix.${f.label}`)}</Link> : null,
                ]} />
            )
          })}
        </RowList>
        {listening ? null : (
          <div className="mt-3 flex flex-wrap items-center gap-1 text-meta text-muted">
            <p>{t('coverage.notListening')}</p>
            <InfoTip topic={t('coverage.title')}>{t('coverage.notListeningInfo')}</InfoTip>
            {admin ? <Link to="?tab=trap-ips&add=file_server#trap-ips" className="ml-1 font-medium text-accent underline underline-offset-4">{t('coverage.fix.addTrap')}</Link> : null}
          </div>
        )}
      </Card>
    </Section>
  )
}
