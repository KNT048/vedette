import { useState, type ReactNode } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { CodeBlock } from '@/components/common/CodeBlock'
import { AiBlock } from '@/components/common/AiBlock'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Segmented } from '@/components/ui/segmented'
import { errMsg } from './errors'
import { fmtDate, fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useApplied, useAskAi } from './api'
import type { AiResult, ApplyItem, CodeStep, FindingDetail, FirewallGuide, FirewallVendor, KevInfo } from './types'
import { isOpen } from './basis'
import { softwareFor, useDeviceSoftware } from './rematch'

function SideEffect({ text }: { text: string }) {
  const { t } = useTranslation('findings')
  return <p className="rounded-md border border-dashed border-warn bg-warn-soft/60 px-3 py-2 text-[13px]"><span className="font-medium">{t('rec.sideEffect')}</span> {text}</p>
}

function Steps({ steps }: { steps: CodeStep[] }) {
  return (
    <div className="grid gap-3">
      {steps.map((s) => (
        <div key={s.title} className="grid gap-1.5">
          {s.code ? <CodeBlock code={s.code} label={s.title} wrapOnPhone /> : <p className="text-[13px] font-medium">{s.title}</p>}
          {s.note ? <p className="text-[13px] text-muted">{s.note}</p> : null}
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
  if (done) return <p className="text-[13px] text-ok">{t('rec.appliedBy', { user: done.user, time: fmtDateTime(done.ts) })}</p>
  return (
    <div className="flex flex-wrap items-center gap-3">
      <Button size="sm" variant="primary" disabled={!can || apply.isPending} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}
        onClick={() => apply.mutate(item, { onSuccess: () => toast.success(t('rec.appliedToast')), onError: (e) => toast.error(errMsg(e)) })}>
        {t('rec.applied')}
      </Button>
      <span className="text-[12px] text-muted">{t('rec.appliedHint')}</span>
    </div>
  )
}

/** Phiên bản vá cho đúng thiết bị này, từ khoảng phiên bản NVD hoặc bản ghi CVE.org (D-488, D-556): chỉ nói điều dữ liệu cho, luôn ghi đúng nguồn (`fixed_in.source`). */
export function FixedInNote({ finding }: { finding: FindingDetail }) {
  const { t } = useTranslation('findings')
  const f = finding.fixed_in
  if (!f) return null
  const device = finding.asset?.name || t('removedDevice')
  const product = finding.kev?.display || t('rec.theSoftware')
  let text: string
  let extra: string | null = f.distro ? t('rec.fixedIfDistro', { distro: f.distro, product }) : null
  if (f.kind === 'fixed') text = t('rec.fixedIn', { fixed: f.fixed, device, version: f.version })
  else if (f.kind === 'up_to') text = t('rec.fixedUpTo', { fixed: f.fixed, device, version: f.version })
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
      {extra ? <p className="text-[13px]">{extra}</p> : null}
      <p className="text-[12px] text-muted">{t('rec.fixedSource', { source: f.source })}</p>
    </div>
  )
}

function H3({ children, id }: { children: ReactNode; id: string }) {
  return <h3 id={id} className="text-sm font-semibold">{children}</h3>
}

function Guide({ finding, g }: { finding: FindingDetail; g: FirewallGuide }) {
  const { t } = useTranslation('findings')
  return (
    <div className="grid gap-4">
      <p className="text-sm">{g.intro}</p>
      {g.plain ? <ol className="grid list-decimal gap-1 pl-5 text-sm">{g.plain.map((p) => <li key={p}>{p}</li>)}</ol> : null}
      <Steps steps={g.steps} />
      {g.alternative ? (
        <div className="grid gap-3 border-t border-rule pt-3">
          <p className="text-sm font-medium">{g.alternative.title}</p>
          <p className="text-[13px] text-muted">{g.alternative.intro}</p>
          <Steps steps={g.alternative.steps} />
        </div>
      ) : null}
      {g.verify.length ? <div className="grid gap-2 border-t border-rule pt-3"><p className="text-sm font-medium">{t('rec.verify')}</p><Steps steps={g.verify} /></div> : null}
      {g.undo.length ? <div className="grid gap-2 border-t border-rule pt-3"><p className="text-sm font-medium">{t('rec.undo')}</p><Steps steps={g.undo} /></div> : null}
      <ApplyButton finding={finding} item={g.vendor} />
    </div>
  )
}

function Firewall({ finding }: { finding: FindingDetail }) {
  const { t } = useTranslation('findings')
  const guides = finding.pack!.firewall
  const first = guides.find((g) => g.detected)?.vendor ?? 'generic'
  const [vendor, setVendor] = useState<FirewallVendor>(first)
  const g = guides.find((x) => x.vendor === vendor) ?? guides[0]
  if (!g) return null
  const any = guides.some((x) => x.detected)
  return (
    <div className="grid gap-3">
      <p className="text-[13px] text-muted">{any ? t('rec.fwDetected') : t('rec.fwNone')}</p>
      <Segmented<FirewallVendor> label={t('rec.fwVendor')} value={vendor} onChange={setVendor} className="flex-wrap"
        options={guides.map((x) => ({ value: x.vendor, label: x.detected ? t('rec.fwDeclared', { name: x.label }) : x.label }))} />
      <Guide key={g.vendor} finding={finding} g={g} />
    </div>
  )
}

function Checklist({ items }: { items: string[] }) {
  const { t } = useTranslation('findings')
  const [done, setDone] = useState<Set<number>>(new Set())
  return (
    <div className="grid gap-2">
      <p className="text-[12px] text-muted">{t('rec.checklistHint', { done: done.size, total: items.length })}</p>
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

/** Khuyến nghị Vedette đã xác nhận (D-21): luôn nói rõ ai xác nhận, ngày nào, và "soạn với AI". */
export function PackView({ finding }: { finding: FindingDetail }) {
  const { t } = useTranslation('findings')
  const p = finding.pack!
  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <Chip tone="ok">{t('rec.confirmedChip')}</Chip>
        <span className="text-sm">{t('rec.confirmedBy', { by: p.confirmed_by, date: fmtDate(p.confirmed_at) })}</span>
      </div>
      <AiBlock origin="project" model={p.drafted_with} citations={p.sources}>
        <section aria-labelledby="rec-patch" className="grid gap-2">
          <H3 id="rec-patch">{t('rec.patchTitle')}</H3>
          <p>{p.patch.summary}</p>
          <FixedInNote finding={finding} />
          <p className="text-[13px]"><span className="font-medium">{t('rec.fixedVersion')}</span> {p.patch.fixed}</p>
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
          <p className="text-[13px] text-muted">{t('rec.firewallHint')}</p>
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

/** Kết quả AI của khách: luôn trong AiBlock origin="customer", không bao giờ giống khuyến nghị của dự án. */
export function AiOutput({ r }: { r: AiResult }) {
  return (
    <AiBlock origin="customer" model={r.profile ? `${r.model} (${r.profile})` : r.model} tokens={r.tokens} citations={r.citations}>
      {r.paragraphs.map((p) => <p key={p}>{p}</p>)}
      <ol className="grid list-decimal gap-1 pl-5">{r.steps.map((s) => <li key={s}>{s}</li>)}</ol>
    </AiBlock>
  )
}

export function AskAi({ finding, skill, result, label, hint }: { finding: FindingDetail; skill: AiResult['skill']; result: AiResult | null; label: string; hint?: string }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const ask = useAskAi(finding.id)
  const ready = skill === 'explain' ? finding.ai_available.explain : finding.ai_available.config
  const usable = can && ready
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-3">
        <Button variant={result ? 'secondary' : 'primary'} disabled={!usable || ask.isPending} aria-describedby={`ai-hint-${skill}`}
          onClick={() => ask.mutate(skill, { onError: (e) => toast.error(errMsg(e)) })}>
          {ask.isPending ? t('ai.running') : result ? t('ai.again', { label }) : label}
        </Button>
        <p id={`ai-hint-${skill}`} className="max-w-xl text-[13px] text-muted">
          {!ready
            ? <>{t('ai.unavailable')} <Link to="/settings/ai" className="text-accent underline underline-offset-4">{t('ai.openSettings')}</Link></>
            : !can ? t('common:needRole', { role: t('common:role.operator') }) : (hint ?? t('ai.privacy'))}
        </p>
      </div>
      <div aria-live="polite">{result ? <AiOutput r={result} /> : null}</div>
    </div>
  )
}

/** Liên kết trong ghi chú KEV: trang của CISA, NVD, còn lại coi là khuyến cáo của hãng (W1-31). */
function linkKind(u: string): 'cisa' | 'nvd' | 'vendor' {
  let host = ''
  try { host = new URL(u).hostname.toLowerCase() } catch { return 'vendor' }
  if (host === 'nvd.nist.gov') return 'nvd'
  if (host === 'cisa.gov' || host.endsWith('.cisa.gov')) return 'cisa'
  return 'vendor'
}
const hostOf = (u: string) => { try { return new URL(u).hostname.replace(/^www\./, '') } catch { return u } }

/**
 * Chưa có gói đã xác nhận (S-MIT-1, D-21, W1-31): nói hết điều hộp đang biết, không tự bịa biện pháp: yêu cầu và hạn của CISA,
 * khuyến cáo của hãng và NVD từ ghi chú KEV, các bước kiểm tra phiên bản, rồi "Hỏi AI của tôi". Hộp chưa có dữ liệu phiên bản
 * đã vá (cần feed mới, W1-29), nên trang nói thẳng chỗ lấy nó.
 */
export function NoPack({ finding }: { finding: FindingDetail }) {
  const { t } = useTranslation('findings')
  const k: KevInfo | null = finding.kev
  const vc = k?.source === 'vulncheck-kev'
  const vendor = k?.links.filter((u) => linkKind(u) === 'vendor') ?? []
  const other = k?.links.filter((u) => linkKind(u) !== 'vendor') ?? []
  const device = finding.asset?.name || t('removedDevice')
  const product = k?.display || t('rec.theSoftware')
  // D-499: step 3 points to "I updated" when the page shows it (the software the CVE was matched to is known).
  const sw = useDeviceSoftware(finding.asset?.id)
  const updatable = isOpen(finding.status) && softwareFor(sw.data?.asset.software, finding.cve).length > 0
  return (
    <div className="grid gap-5">
      <div className="rounded-md border border-dashed border-warn bg-warn-soft/60 px-4 py-3">
        <p className="font-medium">{t('rec.noPack')}</p>
        <p className="mt-1 max-w-3xl text-sm">{t('rec.noPackBody')}</p>
      </div>
      {k ? (
        <>
          <div className="grid gap-2">
            <h3 className="text-sm font-semibold">{t(vc ? 'rec.vulncheckTitle' : 'rec.cisaTitle')}</h3>
            <p className="text-[13px] text-muted">{t(vc ? 'rec.sourceHintVulnCheck' : 'rec.sourceHint', { date: fmtDate(k.date_added) })}</p>
            <blockquote lang="en" className="max-w-3xl border-l-2 border-rule pl-3 text-sm">{k.required_action}</blockquote>
            {k.due_date ? <p className="text-sm font-medium">{t('rec.dueDate', { date: fmtDate(k.due_date) })}</p> : null}
            {k.ransomware ? <p className="text-[13px]">{t('rec.ransomware')}</p> : null}
          </div>
          <div className="grid gap-2">
            <h3 className="text-sm font-semibold">{t('rec.fixTitle')}</h3>
            {finding.fixed_in ? <FixedInNote finding={finding} /> : <p className="max-w-3xl text-[13px] text-muted">{t('rec.noFixedVersion')}</p>}
            {vendor.length > 0 ? (
              <ul className="grid gap-1 text-sm">
                {vendor.map((u) => <li key={u}><a className="break-all text-accent underline underline-offset-4" href={u} target="_blank" rel="noopener noreferrer">{t('rec.vendorLink', { host: hostOf(u) })}</a></li>)}
              </ul>
            ) : <p className="text-sm">{t('rec.noVendorLink', { cve: finding.cve, product })}</p>}
            {other.length > 0 ? (
              <ul className="grid gap-1 text-[13px]">
                {other.map((u) => <li key={u}><a className="break-all text-accent underline underline-offset-4" href={u} target="_blank" rel="noopener noreferrer">{t(`rec.${linkKind(u)}Link`)}</a></li>)}
              </ul>
            ) : null}
          </div>
          <div className="grid gap-2">
            <h3 className="text-sm font-semibold">{t('rec.stepsTitle')}</h3>
            <ol className="grid max-w-3xl list-decimal gap-1 pl-5 text-sm">
              <li>{t('rec.step1', { device, product })}</li>
              <li>{k.due_date ? t('rec.step2Due', { date: fmtDate(k.due_date) }) : t('rec.step2')}</li>
              <li>{updatable ? t('rec.step3', { device }) : t('rec.step3Mark')}</li>
            </ol>
          </div>
        </>
      ) : <p className="text-sm text-muted">{t('rec.noKev')}</p>}
      <div className="grid gap-2">
        <h3 className="text-sm font-semibold">{t('rec.askTitle')}</h3>
        <AskAi finding={finding} skill="mitigation-config" result={finding.ai.config} label={t('rec.askAi')} />
      </div>
    </div>
  )
}
