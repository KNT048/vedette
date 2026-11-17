import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Notice } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { fmtDate, fmtNumber } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useMe } from '@/lib/session'
import { useAiConfig, useProfiles } from './api'

/** The share of a monthly budget used, rounded down, as the box counts it (80 % warns, 100 % stops). */
export const budgetPct = (used: number, budget: number) => (budget > 0 ? Math.floor((used * 100) / budget) : 0)
const tone = (pct: number) => (pct >= 100 ? 'font-medium text-danger' : pct >= 80 ? 'font-medium text-warn' : undefined)

/** "1,234 of 6,000,000 tokens (0 %)", red at 100 %, amber from 80 % (S-AI-4). */
export function BudgetUse({ used, budget }: { used: number; budget: number }) {
  const { t } = useTranslation('ai')
  const pct = budgetPct(used, budget)
  return <span className={tone(pct)}>{t('budget.use', { used: fmtNumber(used), budget: fmtNumber(budget), pct })}</span>
}

/**
 * S-AI-4: Home says when this month's AI budget (the box's, or a profile's own) is at 80 % or used up, before AI jobs
 * stop and when they have stopped, with the renewal day and, for an administrator, a link to raise it. Shown while the AI module is on.
 */
export function AiBudgetPrompt() {
  const { t } = useTranslation('ai')
  const on = useModuleEnabled('ai') === true
  const cfg = useAiConfig(on)
  const profiles = useProfiles(on)
  const { data: me } = useMe()
  if (!on || !cfg.data) return null
  const c = cfg.data
  const date = fmtDate(c.renews_on)
  const lines: { key: string; title: string; body: string; info: string; stop: boolean }[] = []
  const box = budgetPct(c.month_used, c.monthly_budget)
  if (box >= 80) {
    const v = { used: fmtNumber(c.month_used), budget: fmtNumber(c.monthly_budget), pct: box, date }
    lines.push({ key: 'box', stop: box >= 100, title: t(box >= 100 ? 'budget.home.boxStopTitle' : 'budget.home.boxWarnTitle', v), body: t(box >= 100 ? 'budget.home.boxStop' : 'budget.home.boxWarn', v), info: t(box >= 100 ? 'budget.home.boxStopInfo' : 'budget.home.boxWarnInfo', v) })
  }
  for (const p of profiles.data?.items ?? []) {
    const pct = budgetPct(p.used_month, p.monthly_budget)
    if (pct < 80) continue
    const v = { name: p.name, used: fmtNumber(p.used_month), budget: fmtNumber(p.monthly_budget), pct, date }
    lines.push({ key: p.id, stop: pct >= 100, title: t(pct >= 100 ? 'budget.home.profileStopTitle' : 'budget.home.profileWarnTitle', v), body: t(pct >= 100 ? 'budget.home.profileStop' : 'budget.home.profileWarn', v), info: t(pct >= 100 ? 'budget.home.profileStopInfo' : 'budget.home.profileWarnInfo', v) })
  }
  if (lines.length === 0) return null
  const stop = lines.some((l) => l.stop)
  // §0: the raise lands on the field: the box's budget, or the profiles table (each profile has its own budget in Edit)
  const raise = me?.role === 'admin'
    ? <Button asChild size="sm" variant="primary"><Link to={lines.some((l) => l.key === 'box') ? '/settings/ai#ai-cap' : '/settings/ai#ai-profiles'}>{t('budget.home.raise')}</Link></Button>
    : <p className="text-meta text-muted">{t('budget.home.askAdmin')}</p>
  return (
    <div role={stop ? 'alert' : 'status'} className="mb-6 grid gap-2">
      {lines.map((l, i) => (
        <Notice key={l.key} tone={l.stop ? 'danger' : 'warn'} className="mb-0" title={l.title} info={l.info} actions={i === lines.length - 1 ? raise : undefined}>
          {l.body}
        </Notice>
      ))}
    </div>
  )
}
