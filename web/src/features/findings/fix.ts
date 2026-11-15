// D-545 (W-3, S-MIT-1): one missing update is one item, not one row per CVE, as top-tier scanners group by the fix (Defender's
// "Update Windows Server 2025" recommendation, Tenable's one plugin per cumulative update).
import { useTranslation } from 'react-i18next'
import { isOpen, riskRank } from './basis'
import type { FindingRow, PlanItem, RowFix } from './types'

export interface FixGroup { key: string; fix: RowFix; members: [FindingRow, ...FindingRow[]] }

/** The open rows that one update fixes together (two or more of the rows given) become groups; the rest stay rows. */
export function fixGroups(rows: FindingRow[]): { groups: FixGroup[]; rest: FindingRow[] } {
  const by = new Map<string, FindingRow[]>()
  for (const r of rows) if (r.fix && isOpen(r.status)) by.set(r.fix.group, [...(by.get(r.fix.group) ?? []), r])
  const groups: FixGroup[] = []
  for (const [key, list] of by) {
    const [first, ...others] = [...list].sort((a, b) => riskRank(b) - riskRank(a))
    if (first?.fix && others.length > 0) groups.push({ key, fix: first.fix, members: [first, ...others] })
  }
  const grouped = new Set(groups.flatMap((g) => g.members.map((m) => m.id)))
  groups.sort((a, b) => b.members.length - a.members.length || riskRank(b.members[0]) - riskRank(a.members[0]))
  return { groups, rest: rows.filter((r) => !grouped.has(r.id)) }
}

const build = (v: string) => v.replace(/^10\.0\./, '')

/** What to install, in one sentence ("Install the latest cumulative update for Windows Server 2025 (build 26100.7092 or later)"). */
export function useFixAction() {
  const { t } = useTranslation('findings')
  return (f: RowFix) => {
    const v = { software: f.software, version: f.version, fixed: f.windows ? build(f.fixed) : f.fixed, distro: f.distro }
    switch (f.kind) {
      case 'distro': return t(f.pro && f.distro ? 'fix.distroPro' : f.distro ? 'fix.distro' : 'fix.distroAny', v)
      case 'feature_update': return t('fix.featureUpdate', v)
      case 'esu': return t('fix.windowsEsu', v)
    }
    return t(f.windows ? 'fix.windowsFixed' : 'fix.fixed', v)
  }
}

/** Updates to plan (D-613): what to install for one item, as a sentence. */
export function usePlanAction() {
  const { t } = useTranslation('findings')
  return (i: PlanItem) => {
    const v = { software: i.software, version: i.version, fixed: i.kind === 'windows' || i.kind === 'esu' ? build(i.fixed) : i.fixed }
    if (i.kind === 'distro') return t(!i.fixed ? 'plan.action.distro' : i.pro ? 'plan.action.distroPro' : 'plan.action.distroFixed', v) // D-622
    if (i.kind === 'windows') return t('plan.action.windows', v)
    if (i.kind === 'esu') return t('fix.windowsEsu', v) // review r1 #5 of #804: never a plain "install the latest cumulative update"
    return t('plan.action.fixed', v)
  }
}
