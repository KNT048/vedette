// W-3, S-MIT-1: what to install, in words. The grouping by fix is the server's (findings.DeviceUpdates, GET /findings/to-fix):
// the page shows it as To fix, one action per update.
import { useTranslation } from 'react-i18next'
import type { PlanItem, RowFix } from './types'

const build = (v: string) => v.replace(/^10\.0\./, '')
/** The KB number next to a Windows build ("; KB5131080"), as the box's sentence names it; "" when Microsoft's list has none. */
export const kbNote = (kb: string) => (kb ? `; ${kb}` : '')
/** What a recommended Windows update with no CVE says instead of a count: its CVEs are not analysed yet while it is young (nvd_lag),
 *  then that NVD lists none for the release yet. */
export const noCvesKey = (nvdLag: boolean) => (nvdLag ? 'plan.notAnalysed' : 'plan.noCves')

/** What to install, in one sentence ("Install the latest cumulative update for Windows Server 2025 (from build 26100.1742 to 26100.7092 or
 *  later)"): a Windows build names the device's build, as every other upgrade names its version. */
export function useFixAction() {
  const { t } = useTranslation('findings')
  return (f: RowFix) => {
    const v = { software: f.software, version: f.windows ? build(f.version) : f.version, fixed: f.windows ? build(f.fixed) : f.fixed, distro: f.distro, kb: '' }
    switch (f.kind) {
      case 'distro': return t(f.pro && f.distro ? 'fix.distroPro' : f.distro ? 'fix.distro' : 'fix.distroAny', v)
      case 'feature_update': return t('fix.featureUpdate', v)
      case 'esu': return t(v.version ? 'fix.windowsEsu' : 'fix.windowsEsuBuild', v)
    }
    if (f.windows) return t(v.version ? 'fix.windowsFixed' : 'fix.windowsFixedBuild', v) // as findings updateSentence: no build, no "from"
    return t('fix.fixed', v)
  }
}

/** Updates to plan: what to install for one item, as a sentence. */
export function usePlanAction() {
  const { t } = useTranslation('findings')
  return (i: PlanItem) => {
    const win = i.kind === 'windows' || i.kind === 'esu'
    const v = { software: i.software, version: win ? build(i.version) : i.version, fixed: win ? build(i.fixed) : i.fixed, kb: kbNote(i.kb), distro: i.distro }
    if (i.kind === 'distro') return t(!i.fixed ? (i.distro ? 'plan.action.distroNamed' : 'plan.action.distro') : i.pro ? 'plan.action.distroPro' : 'plan.action.distroFixed', v)
    if (i.kind === 'windows') return t(v.version ? 'plan.action.windows' : 'plan.action.windowsBuild', v)
    if (i.kind === 'esu') return t(v.version ? 'fix.windowsEsu' : 'fix.windowsEsuBuild', v) // #804: never a plain "install the latest cumulative update"
    return t('plan.action.fixed', v)
  }
}
