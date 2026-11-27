// "What to do" on a finding without a confirmed pack (S-MIT-1): the same four steps a confirmed pack has, from the data the box holds,
// in one section. 1 the fix: the release that fixes this device (the stored fix every list and the plan name, so the page never says
// "the release the advisory names" when the box knows it) with the vendor's links; 2 the workaround the vendor publishes, or plainly
// none; 3 firewall configuration: only a confirmed pack or the customer's own AI writes one, so without a pack the page says so, names
// the firewall Vedette knows (or lets the person add it right here) and offers "Ask my AI"; 4 how to check that it is fixed.
import { useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { InfoTip } from '@/components/common/InfoTip'
import { RequireModule } from '@/components/common/States'
import { Checkbox } from '@/components/ui/checkbox'
import { actsAs } from '@/lib/deviceTypes'
import { fmtDate } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useModuleEnabled } from '@/lib/modules'
import { useCve } from '@/features/feeds/api'
import type { CveBrief } from '@/features/feeds/types'
import { advisories } from './CveBrief'
import { AskAi, FixedInNote, nowParts } from './Recommendation'
import { useDeviceCards, useView } from './api'
import { PAGE_MAX } from './contract'
import { useWalls, WallPicker } from './firewall'
import { deviceName, isOpen } from './basis'
import { linkLabels } from './links'
import { overdue } from './accept'
import { softwareFor, useDeviceSoftware } from './rematch'
import { useFindingAgentGone } from './agentNow'
import type { FindingDetail, View } from './types'

const link = 'text-accent underline-offset-4 hover:underline'

/** The release that fixes this device as one sentence, or null when the box knows none (the caller then points to the advisory). */
export function storedFixText(t: TFunction<'findings'>, f: FindingDetail, view: View | undefined): string | null {
  const fix = view?.fix
  if (!fix?.version) return null
  const device = deviceName(f.asset, t('removedDevice'))
  const product = fix.product || f.kev?.display || t('rec.theSoftware')
  const version = f.known_version?.version ?? view?.software?.version ?? ''
  const o = { fixed: fix.version, product, device, version, kb: fix.ref ?? '' }
  switch (fix.kind) {
    case 'update': return t(version ? 'todo.fixUpdate' : 'todo.fixUpdateNoVersion', o)
    case 'distro_update': return fix.channel === 'ubuntu_pro' ? t('todo.fixDistroPro', o) : t(version ? 'todo.fixDistro' : 'todo.fixDistroNoVersion', o)
    case 'os_update': {
      const line = t(fix.ref ? 'todo.fixOsKb' : 'todo.fixOs', o)
      return fix.channel === 'esu' ? t('todo.fixOsEsu', { line }) : line
    }
    case 'feature_update': return t('todo.fixFeature', o)
    case 'restart': return t('todo.fixRestart', o)
  }
  return null
}

/**
 * Step 1's first line. The finding's own fixed_in (NVD's or the distribution's words for this device) when it names the same release
 * as the stored fix, or when the stored fix names none (end_listed, up_to, branches: they say why there is no plain release); else the
 * stored fix (a vendor's per-train fix such as ESXi's, a finding on no exploited list); else "none yet" or the advisory.
 */
function FixLine({ f, view, product, links }: { f: FindingDetail; view: View | undefined; product: string; links: boolean }) {
  const { t } = useTranslation('findings')
  const fi = f.fixed_in
  const stored = view?.fix
  const plan = usePlanFix(f)
  const same = !!fi && (!stored?.version || fi.fixed === stored.version || fi.distro_fixed === stored.version)
  // The plan names one release per software line of the device (the release that fixes every CVE of the line); it can be later than
  // this CVE's own fix, so the page says so instead of claiming the two are the same.
  const later = !!plan?.version && !!stored?.version && plan.version !== stored.version
  const planLine = later ? <p className="text-meta" data-testid="plan-fix">{t('todo.fixPlan', { product: plan!.product || product, device: deviceName(f.asset, t('removedDevice')), target: plan!.version })}</p> : null
  if (fi && same) return <>{<FixedInNote finding={f} />}{planLine}</>
  const text = storedFixText(t, f, view)
  if (text) {
    return (
      <div className="grid max-w-3xl gap-1" data-testid="stored-fix">
        <p className="text-sm font-medium">{text}</p>
        {planLine}
        <p className="text-caption text-muted">{t(plan && !later ? 'todo.fixSource' : 'todo.fixAdvisory')}</p>
      </div>
    )
  }
  if (stored?.kind === 'none_yet') return <p className="text-sm font-medium">{t(view?.verification.basis === 'package' ? 'todo.fixNoneYetDistro' : 'todo.fixNoneYet', { product: stored.product || product })}</p>
  if (fi) return <FixedInNote finding={f} />
  return <p className="text-sm">{links ? t('brief.fix') : t(f.kev ? 'rec.noVendorLink' : 'rec.noAdvisoryLink', { cve: f.cve, product })}</p>
}

/** The fix the plan (Findings › By device and By fix) names for the software line this finding is on: the fix of the device's block
 *  that holds the finding. Undefined while it loads or when the finding is in no block (closed). */
function usePlanFix(f: FindingDetail) {
  const device = f.asset?.id ?? ''
  const q = useDeviceCards({ device }, { offset: 0, limit: PAGE_MAX }, !!device && isOpen(f.status))
  const card = q.data?.items.find((c) => c.device.id === device)
  return card?.blocks.find((b) => b.findings.some((r) => r.id === f.id))?.fix
}

/** Step 1's fix line on its own, for a confirmed pack's patch step: the same sentence as without a pack. */
export function FixLineOf({ f }: { f: FindingDetail }) {
  const { t } = useTranslation('findings')
  const view = useView(f.id).data
  return <FixLine f={f} view={view} product={f.kev?.display || view?.fix.product || t('rec.theSoftware')} links />
}

function FirewallStep({ f }: { f: FindingDetail }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const w = useWalls(f)
  const name = w.chosen?.name
  return (
    <div className="grid gap-3" data-testid="firewall-step">
      <p className="max-w-3xl text-sm">{t('todo.fwNoPack', { cve: f.cve })}</p>
      <WallPicker f={f} w={w} />
      <AskAi finding={f} skill="mitigation-config" result={f.ai.config} label={t('rec.askAi')}
        hint={f.ai_available.config && can ? (name ? t('todo.fwAsk', { firewall: name }) : t('todo.fwAskAny')) : undefined} />
    </div>
  )
}

/** A list to tick while working; nothing is saved (as a confirmed pack's checklist). */
export function Checklist({ items }: { items: { key: string; node: ReactNode }[] }) {
  const { t } = useTranslation('findings')
  const [done, setDone] = useState<Set<string>>(new Set())
  return (
    <div className="grid gap-2">
      <p className="text-caption text-muted">{t('rec.checklistHint', { done: done.size, total: items.length })}</p>
      <ul className="grid gap-2">
        {items.map((it) => (
          <li key={it.key} className="flex items-start gap-2.5 text-sm">
            <Checkbox id={`chk-${it.key}`} className="mt-0.5" checked={done.has(it.key)} onCheckedChange={(v) => setDone((s) => { const n = new Set(s); if (v === true) n.add(it.key); else n.delete(it.key); return n })} />
            <label htmlFor={`chk-${it.key}`} className={done.has(it.key) ? 'text-muted line-through' : ''}>{it.node}</label>
          </li>
        ))}
      </ul>
    </div>
  )
}

function H3({ children, id }: { children: ReactNode; id: string }) {
  return <h3 id={id} className="text-sm font-semibold">{children}</h3>
}

/** The workaround the vendor publishes in the CVE record, else plainly none; what the exploited list asks comes under it. */
function Workaround({ b, f, restartOnly }: { b: CveBrief | undefined; f: FindingDetail; restartOnly: boolean }) {
  const { t } = useTranslation('findings')
  const k = f.kev
  return (
    <div className="grid gap-2">
      {b?.workaround
        ? <p className="max-w-3xl text-sm"><span className="font-medium">{t('todo.vendorWorkaround')}</span> <span lang="en" className="whitespace-pre-line">{b.workaround}</span></p>
        : <p className="text-sm">{restartOnly ? t('todo.restartNoWorkaround', { device: deviceName(f.asset, t('removedDevice')) }) : t('todo.noWorkaround')}</p>}
      {k?.required_action ? (
        <div className="grid gap-1">
          <p className="text-meta font-medium">{t('todo.cisaAsks', { source: k.source === 'vulncheck-kev' ? 'VulnCheck KEV' : 'CISA' })}</p>
          <blockquote lang="en" className="max-w-3xl border-l-2 border-rule pl-3 text-meta">{k.required_action}</blockquote>
        </div>
      ) : null}
    </div>
  )
}

/** The four steps without a confirmed pack. The firewall step needs the mitigation module; the rest is the finding's own data. */
export function FixGuide({ f }: { f: FindingDetail }) {
  const { t } = useTranslation('findings')
  const feedsOn = useModuleEnabled('feeds') !== false
  const q = useCve(feedsOn ? f.cve : '')
  const b = q.data
  const view = useView(f.id).data
  const sw = useDeviceSoftware(f.asset?.id)
  const rows = softwareFor(sw.data?.asset.software, f.cve)
  const agentGone = useFindingAgentGone(f)
  const urls = advisories(b, f, view)
  const labels = linkLabels(t, urls)
  const known = f.known_version?.software || view?.software?.name || view?.fix.product || null
  const product = f.kev?.display || b?.display || known || t('rec.theSoftware')
  const device = deviceName(f.asset, t('removedDevice'))
  const due = f.kev?.due_date
  const open = isOpen(f.status)
  const parts = nowParts(t, f, { product, updatable: open && rows.length > 0, manual: rows.find((r) => r.source === 'manual')?.display, agentGone })
  // the release the checklist asks for is the one step 1 names (FixLine's rule)
  const fi = f.fixed_in
  const fiNamesStored = !!fi && (!view?.fix.version || fi.fixed === view.fix.version || fi.distro_fixed === view.fix.version)
  const fixed = fi && fiNamesStored ? (fi.kind === 'fixed' ? fi.fixed : fi.distro_fixed || null) : view?.fix.version || null
  const workaround = !!b?.workaround
  // a restart only where the update is the device's own system: an OS build, a kernel, an appliance's firmware (never an app's update)
  const restart = ['os_update', 'feature_update'].includes(view?.fix.kind ?? '') || /kernel|linux-image/i.test(known ?? '') ||
    ['firewall', 'router', 'switch', 'nas', 'hypervisor', 'ap', 'printer', 'camera'].includes(actsAs(f.asset?.kind ?? ''))
  // the fixed kernel is installed already: the one step is the restart (the stored fix, or the distribution's word on this device)
  const restartOnly = view?.fix.kind === 'restart' || !!fi?.restart_into
  const checks: { key: string; node: ReactNode }[] = [
    ...(restartOnly ? [{ key: 'restart', node: t('todo.checkRestartNow', { device, product: known ?? product }) }] : []),
    { key: 'version', node: t(fixed ? 'todo.checkVersion' : 'todo.checkVersionAdvisory', { software: known ?? product, device, fixed }) },
    ...(restart && !restartOnly ? [{ key: 'restart', node: t('todo.checkRestart', { device }) }] : []),
    ...(workaround ? [{ key: 'workaround', node: t('todo.checkWorkaround') }] : []),
    { key: 'vedette', node: parts.verify },
  ]
  return (
    <div className="grid gap-5" data-testid="fix-guide">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-meta text-muted">
        <span className="font-medium text-ink">{t('rec.noPack')}</span>
        <span>{t('todo.source')}</span>
        <InfoTip topic={t('rec.noPack')}><p>{t('rec.noPackBodyInfo')}</p><p>{t('rec.noPackAi')}</p></InfoTip>
      </div>
      <section aria-labelledby="todo-fix" className="grid gap-2">
        <H3 id="todo-fix">{t('rec.patchTitle')}</H3>
        <FixLine f={f} view={view} product={product} links={urls.length > 0} />
        {parts.known ? <p className="max-w-3xl text-meta">{parts.known}</p> : null}
        {urls.length ? (
          <span className="flex flex-wrap gap-x-3 gap-y-0.5 text-sm">
            {urls.map((u, i) => <a key={u} className={`break-all ${link}`} href={u} target="_blank" rel="noopener noreferrer">{labels[i]}</a>)}
          </span>
        ) : null}
        {b?.solution ? <p className="max-w-3xl text-meta"><span className="font-medium">{t('todo.vendorSolution')}</span> <span lang="en" className="whitespace-pre-line">{b.solution}</span></p> : null}
        {due && open ? <p className="text-sm font-medium">{t(overdue(due) ? 'rec.dueDatePassed' : 'rec.dueDate', { date: fmtDate(due) })}</p> : null}
        {f.kev?.ransomware ? <p className="text-meta">{t('rec.ransomware')}</p> : null}
      </section>
      <section aria-labelledby="todo-workaround" className="grid gap-2 border-t border-rule pt-3">
        <H3 id="todo-workaround">{t('rec.workaroundTitle')}</H3>
        <Workaround b={b} f={f} restartOnly={restartOnly} />
      </section>
      <section aria-labelledby="todo-firewall" className="grid gap-2 border-t border-rule pt-3">
        <H3 id="todo-firewall">{t('rec.firewallTitle')}</H3>
        <RequireModule module="mitigation"><FirewallStep f={f} /></RequireModule>
      </section>
      <section aria-labelledby="todo-check" className="grid gap-2 border-t border-rule pt-3">
        <H3 id="todo-check">{t('todo.checkTitle')}</H3>
        <Checklist items={checks} />
      </section>
    </div>
  )
}
