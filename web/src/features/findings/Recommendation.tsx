import { useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { toast } from 'sonner'
import { CodeBlock } from '@/components/common/CodeBlock'
import { AiBlock } from '@/components/common/AiBlock'
import { Chip } from '@/components/common/StatusChip'
import { InfoTip } from '@/components/common/InfoTip'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Segmented } from '@/components/ui/segmented'
import { errMsg } from './errors'
import { fmtDate, fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useModuleEnabled } from '@/lib/modules'
import { useApplied, useAskAi } from './api'
import type { AiAnswer, AiResult, ApplyItem, CodeStep, FindingDetail, FirewallGuide, FirewallVendor } from './types'
import { AiAnswerKey } from './contract'

const ANSWER_ORDER = AiAnswerKey.options
import { hasIp, isOpen } from './basis'
import { useWalls, WallPicker } from './firewall'

function SideEffect({ text }: { text: string }) {
  const { t } = useTranslation('findings')
  return <p className="rounded-md border border-warn/50 bg-warn-soft px-3 py-2 text-meta"><span className="font-medium">{t('rec.sideEffect')}</span> {text}</p>
}

/** caution: a fixed warning shown on every block (the AI's config blocks, #897 r2); `check`: addresses to check, shown above the code. */
function Steps({ steps, caution }: { steps: CodeStep[]; caution?: string }) {
  const { t } = useTranslation('findings')
  return (
    <div className="grid gap-3">
      {steps.map((s, i) => (
        // the index too: an AI's titles can repeat (#897 r1 L4)
        <div key={`${i}:${s.title}`} className="grid gap-1.5">
          {caution ? <p className="rounded-md border border-warn/50 bg-warn-soft px-3 py-2 text-meta">{caution}</p> : null}
          {s.check?.length ? <p className="rounded-md border border-warn/50 bg-warn-soft px-3 py-2 text-meta"><span className="font-medium">{t('ai.checkAddresses')}</span> {s.check.join(', ')}</p> : null}
          {s.code ? <CodeBlock code={s.code} label={s.title} wrapOnPhone /> : <p className="text-meta font-medium">{s.title}</p>}
          {s.note ? <p className="text-meta text-muted">{s.note}</p> : null}
          {s.side_effect ? <SideEffect text={s.side_effect} /> : null}
        </div>
      ))}
    </div>
  )
}

function ApplyButton({ finding, item }: { finding: FindingDetail; item: ApplyItem }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const apply = useApplied(finding.id)
  const done = finding.applied.find((a) => a.item === item)
  if (done) return <p className="text-meta text-ok">{t('rec.appliedBy', { user: done.user, time: fmtDateTime(done.ts) })}</p>
  return (
    <div className="flex flex-wrap items-center gap-3">
      <Button size="sm" variant="primary" disabled={!can} busy={apply.isPending} busyLabel={t('common:busy.saving')} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}
        onClick={() => apply.mutate(item, { onSuccess: () => toast.success(t('rec.appliedToast')), onError: (e) => toast.error(errMsg(e)) })}>
        {t('rec.applied')}
      </Button>
      <span className="inline-flex items-center gap-1 text-caption text-muted">{t('rec.appliedHint')}<InfoTip>{t('rec.appliedHintInfo')}</InfoTip></span>
    </div>
  )
}

/** The fixed version for exactly this device, from an NVD version range or a CVE.org record: says only what the data gives, always names the source (`fixed_in.source`). */
export function FixedInNote({ finding }: { finding: FindingDetail }) {
  const { t } = useTranslation('findings')
  const f = finding.fixed_in
  if (!f) return null
  const device = finding.asset?.name || t('removedDevice')
  const product = finding.kev?.display || t('rec.theSoftware')
  let text: string
  let extra: string | null = f.distro ? t('rec.fixedIfDistro', { distro: f.distro, product }) : null
  let source = t('rec.fixedSource', { source: f.source })
  if (f.kind === 'distro' && f.distro_fixed) {
    // The distribution's own fixed package for this release
    text = f.restart_into
      ? t('rec.fixedDistroRestart', { fixed: f.distro_fixed, distro: f.distro, release: f.distro_release, device, product, version: f.version, installed: f.restart_into })
      : t('rec.fixedDistroIn', { fixed: f.distro_fixed, distro: f.distro, release: f.distro_release, device, product, version: f.version })
    extra = f.distro_pro ? t('rec.fixedDistroPro') : null
    source = t('rec.fixedSourceDistro', { source: f.source })
  } else if (f.kind === 'fixed') text = t('rec.fixedIn', { fixed: f.fixed, device, version: f.version })
  else if (f.kind === 'feature_update') text = t('rec.fixedFeatureUpdate', { fixed: f.fixed, device, version: f.version, branch: f.branches[0]?.branch ?? '' })
  else if (f.kind === 'esu') text = t('rec.fixedEsu', { fixed: f.fixed, device, version: f.version, branch: f.branches[0]?.branch ?? '' })
  else if (f.kind === 'up_to') text = t('rec.fixedUpTo', { fixed: f.fixed, device, version: f.version })
  else if (f.kind === 'end_listed') text = t('rec.fixedEndListed', { fixed: f.fixed, device, version: f.version }) // M2-4
  else if (f.kind === 'distro') {
    text = t(f.distro ? 'rec.fixedDistro' : 'rec.fixedDistroAny', { device, product, version: f.version, distro: f.distro })
    extra = f.fixed ? t(f.distro ? 'rec.fixedDistroBelow' : 'rec.fixedDistroBelowAny', { distro: f.distro, fixed: f.fixed }) : null
  } else {
    const list = f.branches.map((b) => (b.branch ? t('rec.fixedBranch', { branch: b.branch, fixed: b.fixed }) : t('rec.fixedBranchPlain', { fixed: b.fixed })))
    if (f.more > 0) list.push(t('rec.fixedMore', { count: f.more }))
    if (f.no_fix > 0) list.push(t('rec.fixedNoFix', { count: f.no_fix }))
    text = f.version ? t('rec.fixedUnreadable', { device, version: f.version, list: list.join(', ') }) : t('rec.fixedBranches', { device, list: list.join(', ') })
  }
  return (
    <div className="grid max-w-3xl gap-1" data-testid="fixed-in">
      <p className="text-sm font-medium">{text}</p>
      {extra ? <p className="text-meta">{extra}</p> : null}
      <p className="text-caption text-muted">{source}</p>
    </div>
  )
}

function H3({ children, id }: { children: ReactNode; id: string }) {
  return <h3 id={id} className="text-sm font-semibold">{children}</h3>
}

/** A device with no address in Vedette leaves <IP> (and <HOST> without a name) in the commands: say what to put there and where to add it. */
function NoAddress({ finding, text }: { finding: FindingDetail; text: string }) {
  const { t } = useTranslation('findings')
  const a = finding.asset
  if (!a || hasIp(a)) return null
  const ip = text.includes('<IP>')
  const host = text.includes('<HOST>')
  if (!ip && !host) return null
  return (
    <p className="rounded-md border border-warn/50 bg-warn-soft px-3 py-2 text-meta" data-testid="no-address">
      {t(ip && host ? 'rec.noAddressBoth' : ip ? 'rec.noAddressIp' : 'rec.noAddressHost', { device: a.name })}{' '}
      <Link to={`/devices/${encodeURIComponent(a.id)}`} className="text-accent underline underline-offset-4">{t('rec.addAddress')}</Link>
    </p>
  )
}

function Guide({ finding, g }: { finding: FindingDetail; g: FirewallGuide }) {
  const { t } = useTranslation('findings')
  return (
    <div className="grid gap-4">
      <p className="text-sm">{g.intro}</p>
      <NoAddress finding={finding} text={JSON.stringify(g)} />
      {g.plain ? <ol className="grid list-decimal gap-1 pl-5 text-sm">{g.plain.map((p) => <li key={p}>{p}</li>)}</ol> : null}
      <Steps steps={g.steps} />
      {g.alternative ? (
        <div className="grid gap-3 border-t border-rule pt-3">
          <p className="text-sm font-medium">{g.alternative.title}</p>
          <p className="text-meta text-muted">{g.alternative.intro}</p>
          <Steps steps={g.alternative.steps} />
        </div>
      ) : null}
      {g.verify.length ? <div className="grid gap-2 border-t border-rule pt-3"><p className="text-sm font-medium">{t('rec.verify')}</p><Steps steps={g.verify} /></div> : null}
      {g.undo.length ? <div className="grid gap-2 border-t border-rule pt-3"><p className="text-sm font-medium">{t('rec.undo')}</p><Steps steps={g.undo} /></div> : null}
      <ApplyButton finding={finding} item={g.vendor} />
    </div>
  )
}

/** A pack writes a network rule when one of its firewall guides has a command to paste; a pack for a local flaw writes none. */
const hasNetworkRule = (guides: FirewallGuide[]) => guides.some((g) => g.steps.length > 0 || (g.alternative?.steps.length ?? 0) > 0)

/** The pack's firewall step: the tab of the firewall in front of the device (the one rule of firewall.tsx), the others a click away. */
function Firewall({ finding }: { finding: FindingDetail }) {
  const { t } = useTranslation('findings')
  const guides = finding.pack!.firewall
  const w = useWalls(finding)
  const [picked, setPicked] = useState<FirewallVendor | null>(null) // null: follow the firewall chosen above
  if (!hasNetworkRule(guides)) {
    // a local flaw: no rule helps, whichever firewall it is; the pack says why and what helps instead
    const g = guides[0]
    return (
      <div className="grid gap-3" data-testid="no-firewall-rule">
        <p className="text-sm font-medium">{t('rec.fwNoRule')}</p>
        {g ? <p className="text-sm">{g.intro}</p> : null}
        {g?.plain ? <ol className="grid list-decimal gap-1 pl-5 text-sm">{g.plain.map((p) => <li key={p}>{p}</li>)}</ol> : null}
      </div>
    )
  }
  const has = (v: FirewallVendor | null | undefined): v is FirewallVendor => !!v && guides.some((x) => x.vendor === v)
  const yours: FirewallVendor | null = w.chosen ? (has(w.chosen.vendor) ? w.chosen.vendor : null) : null
  const fallback: FirewallVendor = has('generic') ? 'generic' : guides[0]!.vendor
  const vendor = picked ?? yours ?? fallback
  const g = guides.find((x) => x.vendor === vendor) ?? guides[0]
  if (!g || !w.settled) return null // the tab follows the firewall: never show one tab and switch to another a moment later
  const note = !w.ready ? null : !w.chosen ? null
    : yours ? t('fw.tabFor', { name: w.chosen.name, tab: guides.find((x) => x.vendor === yours)!.label })
    : t('fw.tabUnknown', { name: w.chosen.name })
  return (
    <div className="grid gap-3">
      <div className="flex items-center gap-1">
        <p className="text-meta text-muted">{t('rec.firewallHint')}</p>
        <InfoTip topic={t('rec.firewallTitle')}>{t('rec.firewallHintInfo')}</InfoTip>
      </div>
      <WallPicker f={finding} w={w} />
      {note ? <p className="text-meta text-muted">{note}</p> : null}
      <Segmented<FirewallVendor> label={t('rec.fwVendor')} value={vendor} onChange={setPicked} className="flex-wrap"
        options={guides.map((x) => ({ value: x.vendor, label: x.vendor === yours && w.chosen ? t('rec.fwYours', { name: x.label }) : x.label }))} />
      <Guide key={g.vendor} finding={finding} g={g} />
    </div>
  )
}

function Checklist({ items }: { items: string[] }) {
  const { t } = useTranslation('findings')
  const [done, setDone] = useState<Set<number>>(new Set())
  return (
    <div className="grid gap-2">
      <p className="text-caption text-muted">{t('rec.checklistHint', { done: done.size, total: items.length })}</p>
      <ul className="grid gap-2">
        {items.map((it, i) => (
          <li key={it} className="flex items-start gap-2.5 text-sm">
            <Checkbox id={`chk-${i}`} className="mt-0.5" checked={done.has(i)} onCheckedChange={(v) => setDone((s) => { const n = new Set(s); if (v === true) n.add(i); else n.delete(i); return n })} />
            <label htmlFor={`chk-${i}`} className={done.has(i) ? 'text-muted line-through' : ''}>{it}</label>
          </li>
        ))}
      </ul>
    </div>
  )
}

/** A confirmed Vedette recommendation: always says who confirmed it, on what date, and "drafted with AI". */
export function PackView({ finding, fix }: { finding: FindingDetail; fix?: ReactNode }) {
  const { t } = useTranslation('findings')
  const p = finding.pack!
  return (
    <div className="grid gap-4">
      {/* one status: who confirmed it and when, and that it was drafted with AI help (the AI label, inside the AI block's border) */}
      <AiBlock origin="project" citations={p.sources} status={
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <Chip tone="ok">{t('rec.confirmedChip')}</Chip>
          <span className="inline-flex items-center gap-1 text-meta text-ink">{t('rec.confirmedBy', { date: fmtDate(p.confirmed_at) })}<InfoTip topic={t('rec.confirmedChip')}>{t('rec.confirmedByInfo')}</InfoTip></span>
        </span>
      }>
        <section aria-labelledby="rec-patch" className="grid gap-2">
          <H3 id="rec-patch">{t('rec.patchTitle')}</H3>
          {fix ?? <FixedInNote finding={finding} />}
          <NoAddress finding={finding} text={JSON.stringify(p.patch)} />
          <p>{p.patch.summary}</p>
          <p className="text-meta"><span className="font-medium">{t('rec.fixedVersion')}</span> {p.patch.fixed}</p>
          <ol className="grid list-decimal gap-1 pl-5">{p.patch.steps.map((s) => <li key={s}>{s}</li>)}</ol>
          <SideEffect text={p.patch.side_effect} />
          <a className="w-fit text-accent underline underline-offset-4" href={p.patch.url} target="_blank" rel="noopener noreferrer">{t('rec.vendorAdvisory')}</a>
          <ApplyButton finding={finding} item="patch" />
        </section>
        <section aria-labelledby="rec-workaround" className="grid gap-2 border-t border-rule pt-3">
          <H3 id="rec-workaround">{t('rec.workaroundTitle')}</H3>
          <p>{p.workaround.summary}</p>
          <ol className="grid list-decimal gap-1 pl-5">{p.workaround.steps.map((s) => <li key={s}>{s}</li>)}</ol>
          <SideEffect text={p.workaround.side_effect} />
          <ApplyButton finding={finding} item="workaround" />
        </section>
        <section aria-labelledby="rec-firewall" className="grid gap-2 border-t border-rule pt-3">
          <H3 id="rec-firewall">{t('rec.firewallTitle')}</H3>
          <Firewall finding={finding} />
        </section>
        <section aria-labelledby="rec-checklist" className="grid gap-2 border-t border-rule pt-3">
          <H3 id="rec-checklist">{t('rec.checklistTitle')}</H3>
          <Checklist items={p.checklist} />
        </section>
      </AiBlock>
    </div>
  )
}

/**
 * "Ask my AI": four short answers in a fixed order, each under its own heading with the links it rests on. The headings are the
 * page's, never the AI's; an answer the AI left out is not shown (no paragraph about why something is absent).
 */
export function AiAnswers({ answers }: { answers: AiAnswer[] }) {
  const { t } = useTranslation('findings')
  const by = new Map(answers.map((a) => [a.key, a]))
  return (
    <div className="grid gap-3" data-testid="ai-answers">
      {ANSWER_ORDER.map((key) => {
        const a = by.get(key)
        if (!a) return null
        const links = a.links.filter((l) => /^https?:\/\//i.test(l.url))
        return (
          <section key={key} aria-labelledby={`ai-answer-${key}`} className="grid gap-1">
            <h4 id={`ai-answer-${key}`} className="text-sm font-semibold">{t(`ai.answer.${key}`)}</h4>
            <p className="whitespace-pre-line">{a.text}</p>
            {links.length ? (
              <ul className="flex flex-wrap gap-x-3 gap-y-0.5 text-meta">
                {links.map((l) => <li key={l.url}><a className="break-all text-accent underline underline-offset-4" href={l.url} target="_blank" rel="noopener noreferrer">{l.title}</a></li>)}
              </ul>
            ) : null}
          </section>
        )
      })}
    </div>
  )
}

/** The customer's AI result: always inside AiBlock origin="customer", never made to look like the project's recommendation. */
export function AiOutput({ r }: { r: AiResult }) {
  const { t } = useTranslation('findings')
  return (
    <AiBlock origin="customer" model={r.profile ? `${r.model} (${r.profile})` : r.model} tokens={r.tokens} citations={r.citations}>
      {r.answers?.length ? <AiAnswers answers={r.answers} /> : (
        <>
          {r.paragraphs.map((p) => <p key={p}>{p}</p>)}
          <ol className="grid list-decimal gap-1 pl-5">{r.steps.map((s) => <li key={s}>{s}</li>)}</ol>
        </>
      )}
      {/* M2-2: the config blocks to paste, each copyable, with what it is based on and its side effect */}
      {r.configs?.length ? <div className="grid gap-2"><p className="text-sm font-medium">{t('ai.configsTitle')}</p><Steps steps={r.configs} caution={t('ai.configCaution')} /></div> : null}
      {/* #897 r1 H1: when no configuration helps (a local flaw, no open port serves it), the AI says why instead of inventing rules */}
      {r.no_config_reason && !r.answers?.length ? <div className="grid gap-1"><p className="text-sm font-medium">{t(r.configs?.length ? 'ai.noteTitle' : 'ai.noConfigTitle')}</p><p>{r.no_config_reason}</p></div> : null}
      {r.shortened ? <p className="text-meta text-muted">{t('ai.shortened')}</p> : null}
    </AiBlock>
  )
}

export function AskAi({ finding, skill, result, label, hint }: { finding: FindingDetail; skill: AiResult['skill']; result: AiResult | null; label: string; hint?: string }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const ask = useAskAi(finding.id)
  const ready = skill === 'explain' ? finding.ai_available.explain : finding.ai_available.config
  const usable = can && ready
  const aiOn = useModuleEnabled('ai') !== false
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-3">
        <Button variant={result ? 'secondary' : 'primary'} disabled={!usable} busy={ask.isPending} busyLabel={t('ai.running')}
          aria-describedby={`ai-hint-${skill} ai-wait-${skill}`} onClick={() => ask.mutate(skill, { onError: (e) => toast.error(errMsg(e)) })}>
          {result ? t('ai.again', { label }) : label}
        </Button>
        <p id={`ai-hint-${skill}`} className="max-w-xl text-meta text-muted">
          {!ready
            // docs/UI.md §0: the exact place: the profiles of Settings › AI assistant, or Settings › Modules while the module is off
            ? <>{t('ai.unavailable')} <Link to={aiOn ? '/settings/ai#ai-profiles' : '/settings/modules'} className="text-accent underline underline-offset-4">{t(aiOn ? 'ai.openSettings' : 'ai.openModules')}</Link></>
            : !can ? t('common:needRole', { role: t('common:role.operator') }) : (hint ?? t('ai.privacy'))}
        </p>
        {ready && can && !hint ? <InfoTip>{t('ai.privacyInfo')}</InfoTip> : null}
      </div>
      {/* An AI answer takes 10–60 s; say so while it runs */}
      <BusyNote id={`ai-wait-${skill}`} busy={ask.isPending}>{t('ai.waiting')}</BusyNote>
      <div aria-live="polite">{result ? <AiOutput r={result} /> : null}</div>
    </div>
  )
}


/**
 * What the box knows about the version now, and how a new version reaches Vedette, for the steps of a finding without a pack. M2-3: a
 * version the box has (any source: agent, SNMP, LLDP, a scan, a person) is said, never asked for, and `verify` names how the new version
 * reaches Vedette. M2-5: the controls named are the page's own ("Mark as handled", then Patched or False positive; "I updated
 * <software>" for a typed row, "I updated it" otherwise). `agentGone`: no agent reports the device now (agentNow), so an agent's version
 * is its last list and no new one arrives by itself.
 */
export function nowParts(t: TFunction<'findings'>, finding: FindingDetail, o: { product: string; updatable: boolean; manual?: string; agentGone?: boolean }): { known: string; verify: ReactNode } {
  const device = finding.asset?.name || t('removedDevice')
  const known = finding.known_version
  const agentGone = o.agentGone ?? false
  // review r1 L4: the button is named as the page shows it, the typed row's own display
  let verify: ReactNode = o.updatable ? (o.manual ? t('rec.step3Manual', { device, software: o.manual }) : t('rec.step3', { device })) : t('rec.step3Mark')
  // How the new version reaches Vedette, by who gave the old one; a closed finding keeps the plain step (review r1 L6), and a typed
  // version keeps "I updated <software>"
  const via = isOpen(finding.status) && known?.source !== 'manual' ? known?.source : undefined
  if (via === 'agent') verify = t(agentGone ? 'rec.step3AgentGone' : 'rec.step3Agent', { device })
  else if (via === 'stated') verify = t('rec.step3Stated', { device })
  else if (via === 'scan') verify = t('rec.step3Scan', { device })
  else if (via === 'snmp') {
    // docs/UI.md §0: the exact place, the device page that has the button
    verify = finding.asset
      ? <>{t('rec.step3Snmp', { device })} <Link to={`/devices/${encodeURIComponent(finding.asset.id)}`} className="text-accent underline underline-offset-4">{t('evidence.openDevice')}</Link></>
      : t('rec.step3Snmp', { device })
  }
  const line = known
    ? t('rec.step1Known', { device, software: known.software, version: known.version, from: t(`rec.from.${known.source === 'agent' && agentGone ? 'agentLast' : known.source}`) })
    : t('rec.step1', { device, product: o.product })
  return { known: line, verify }
}
