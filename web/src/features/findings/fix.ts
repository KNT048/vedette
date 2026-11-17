// W-3, S-MIT-1: what to install, in words. The grouping by fix is the server's (findings.DeviceUpdates, GET /findings/to-fix):
// the page shows it as To fix, one action per update.
import { useTranslation } from 'react-i18next'
import type { PlanItem, RowFix } from './types'

const build = (v: string) => v.replace(/^10\.0\./, '')

/** What to install, in one sentence ("Install the latest cumulative update for Windows Server 2025 (from build 26100.1742 to 26100.7092 or
 *  later)"): a Windows build names the device's build, as every other upgrade names its version. */
export function useFixAction() {
  const { t } = useTranslation('findings')
  return (f: RowFix) => {
    const v = { software: f.software, version: f.windows ? build(f.version) : f.version, fixed: f.windows ? build(f.fixed) : f.fixed, distro: f.distro }
    switch (f.kind) {
      case 'distro': return t(f.pro && f.distro ? 'fix.distroPro' : f.distro ? 'fix.distro' : 'fix.distroAny', v)
      case 'feature_update': return t('fix.featureUpdate', v)
      case 'esu': return t('fix.windowsEsu', v)
    }
    return t(f.windows ? 'fix.windowsFixed' : 'fix.fixed', v)
  }
}

/** Updates to plan: what to install for one item, as a sentence. */
export function usePlanAction() {
  const { t } = useTranslation('findings')
  return (i: PlanItem) => {
    const win = i.kind === 'windows' || i.kind === 'esu'
    const v = { software: i.software, version: win ? build(i.version) : i.version, fixed: win ? build(i.fixed) : i.fixed }
    if (i.kind === 'distro') return t(!i.fixed ? 'plan.action.distro' : i.pro ? 'plan.action.distroPro' : 'plan.action.distroFixed', v)
    if (i.kind === 'windows') return t('plan.action.windows', v)
    if (i.kind === 'esu') return t('fix.windowsEsu', v) // #804: never a plain "install the latest cumulative update"
    return t('plan.action.fixed', v)
  }
}
