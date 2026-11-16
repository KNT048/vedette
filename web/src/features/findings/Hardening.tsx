import { lazy, Suspense, useId, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { Plus } from 'lucide-react'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Chip } from '@/components/common/StatusChip'
import { InfoTip } from '@/components/common/InfoTip'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { useCan } from '@/lib/session'
import { ADMIN_NET_PLACEHOLDER } from './contract'
import type { CodeStep, FindingDetail, FirewallGuide, FirewallVendor } from './types'

// Like HomeDashboard: the Devices dialog loads only when someone opens it.
const AddDialog = lazy(() => import('@/features/inventory/AddDialog').then((m) => ({ default: m.AddDialog })))

const STORE_KEY = 'vedette.adminNetwork'
const UNSET = '<ADMIN-NETWORK>'

/** The admin network as the configs take it (a network, or one address made /32 or /128), or null when it is not one. */
export function adminNetwork(raw: string, v6: boolean): string | null {
  const s = raw.trim()
  const m = /^([^/]+)(?:\/(\d{1,3}))?$/.exec(s)
  if (!m) return null
  const [, addr, bits] = m
  if (!v6) {
    const parts = addr!.split('.')
    if (parts.length !== 4 || parts.some((p) => !/^\d{1,3}$/.test(p) || Number(p) > 255)) return null
    if (bits !== undefined && Number(bits) > 32) return null
    return `${addr}/${bits ?? '32'}`
  }
  if (!/^[0-9a-fA-F:]+$/.test(addr!) || !addr!.includes(':') || addr!.includes(':::') || addr!.split('::').length > 2 || addr!.split(':').length > 8) return null
  if (bits !== undefined && Number(bits) > 128) return null
  return `${addr!.toLowerCase()}/${bits ?? '128'}`
}

function remembered(): string | null {
  try { return localStorage.getItem(STORE_KEY) } catch { return null }
}
function remember(v: string) {
  try { localStorage.setItem(STORE_KEY, v) } catch { /* a private window: the field just starts from the example next time */ }
}

const fill = (s: CodeStep, net: string): CodeStep => ({ ...s, code: s.code.replaceAll(ADMIN_NET_PLACEHOLDER, net) })

function Steps({ steps, net }: { steps: CodeStep[]; net: string }) {
  const { t } = useTranslation('findings')
  return (
    <div className="grid gap-3">
      {steps.map((raw) => {
        const s = fill(raw, net)
        return (
          <div key={s.title} className="grid gap-1.5">
            {/* INV-4: the side effect is read before the command is copied. */}
            {s.side_effect ? <p className="rounded-md border border-warn/50 bg-warn-soft px-3 py-2 text-meta"><span className="font-medium">{t('rec.sideEffect')}</span> {s.side_effect}</p> : null}
            <CodeBlock code={s.code} label={s.title} wrapOnPhone />
            {s.note ? <p className="text-meta text-muted">{s.note}</p> : null}
          </div>
        )
      })}
    </div>
  )
}

function GuideView({ g, net }: { g: FirewallGuide; net: string }) {
  const { t } = useTranslation('findings')
  return (
    <div className="grid gap-4">
      <p className="max-w-3xl text-sm">{g.intro}</p>
      <Steps steps={g.steps} net={net} />
      {g.alternative ? (
        <div className="grid gap-3 border-t border-rule pt-3">
          <p className="text-sm font-medium">{g.alternative.title}</p>
          <p className="text-meta text-muted">{g.alternative.intro}</p>
          <Steps steps={g.alternative.steps} net={net} />
        </div>
      ) : null}
      {g.verify.length ? <div className="grid gap-2 border-t border-rule pt-3"><p className="text-sm font-medium">{t('rec.verify')}</p><Steps steps={g.verify} net={net} /></div> : null}
      {g.undo.length ? <div className="grid gap-2 border-t border-rule pt-3"><p className="text-sm font-medium">{t('rec.undo')}</p><Steps steps={g.undo} net={net} /></div> : null}
    </div>
  )
}

/** "General hardening" label: code-written, never a Vedette recommendation for the CVE (D-21, FORBID-2). */
export function GeneralLabel() {
  const { t } = useTranslation('findings')
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      <Chip tone="off">{t('hardening.chip')}</Chip>
      <InfoTip topic={t('hardening.title')}>{t('hardening.chipInfo')}</InfoTip>
    </span>
  )
}

/**
 * M2-1, mitigation INV-8: a ready firewall config that lets only the admin network reach the device, for the firewall listed in
 * Devices (FortiGate, MikroTik, else Linux nftables), with the admin network typed once here. "+ New" adds the firewall in place;
 * once it is in Devices its tab is selected. Vedette never runs any of it (FORBID-1).
 */
export function GeneralHardening({ finding }: { finding: FindingDetail }) {
  const { t } = useTranslation('findings')
  const h = finding.hardening
  const qc = useQueryClient()
  const canAdd = useCan('operator')
  const fieldId = useId()
  const v6 = h?.admin_example.includes(':') ?? false
  const [raw, setRaw] = useState(() => {
    const r = remembered()
    return r && adminNetwork(r, v6) ? r : h?.admin_example ?? ''
  })
  const [chosen, setChosen] = useState<FirewallVendor | null>(null)
  const [adding, setAdding] = useState(false)
  if (!h || h.firewall.length === 0) return null
  const net = adminNetwork(raw, v6)
  const example = raw.trim() === h.admin_example
  const detected = h.firewall.find((g) => g.detected)
  const vendor = chosen ?? detected?.vendor ?? 'generic'
  const g = h.firewall.find((x) => x.vendor === vendor) ?? h.firewall[0]!
  return (
    <section aria-labelledby="hardening-title" className="grid gap-4 border-t border-rule pt-4" data-testid="general-hardening">
      <div className="grid gap-1">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
          <h3 id="hardening-title" className="text-sm font-semibold">{t('hardening.title')}</h3>
          <GeneralLabel />
        </div>
        <p className="max-w-3xl text-meta text-muted">{t('hardening.body', { device: finding.asset?.name || t('removedDevice') })}</p>
      </div>
      <div className="grid max-w-md gap-1.5">
        <Field label={t('hardening.adminNet')} htmlFor={fieldId} hint={example ? undefined : t('hardening.adminNetHint')} info={t('hardening.adminNetInfo')}
          error={net ? undefined : t(v6 ? 'hardening.adminNetBad6' : 'hardening.adminNetBad')}>
          <Input id={fieldId} value={raw} inputMode="text" autoComplete="off" spellCheck={false} onChange={(e) => setRaw(e.target.value)}
            onBlur={() => { if (net && !example) remember(raw.trim()) }} />
        </Field>
        {example && net ? <p className="flex flex-wrap items-center gap-2 text-meta"><Chip tone="warn">{t('hardening.example')}</Chip>{t('hardening.exampleBody', { net: h.admin_example })}</p> : null}
      </div>
      <div className="grid gap-3">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-meta text-muted">
          <p>{detected ? t('hardening.fwListed', { name: detected.label }) : t('hardening.fwNone')}</p>
          {detected ? null : (
            <Button size="sm" disabled={!canAdd} title={canAdd ? undefined : t('common:needRole', { role: t('common:role.operator') })} onClick={() => setAdding(true)}>
              <Plus />{t('hardening.addFirewall')}
            </Button>
          )}
        </div>
        <Segmented<FirewallVendor> label={t('rec.fwVendor')} value={g.vendor} onChange={setChosen} className="flex-wrap"
          options={h.firewall.map((x) => ({ value: x.vendor, label: x.detected ? t('hardening.fwInDevices', { name: x.label }) : x.label }))} />
        <GuideView key={g.vendor} g={g} net={net ?? UNSET} />
      </div>
      {adding ? (
        <Suspense fallback={null}>
          {/* The firewall added here makes its guide "detected": the finding is read again and its tab is selected. */}
          <AddDialog open onOpenChange={(o) => {
            if (o) return
            setAdding(false)
            setChosen(null)
            void qc.invalidateQueries({ queryKey: ['findings', 'detail', finding.id] })
            void qc.invalidateQueries({ queryKey: ['inventory'] })
          }} />
        </Suspense>
      ) : null}
    </section>
  )
}

const hostOf = (u: string) => { try { return new URL(u).hostname.replace(/^www\./, '') } catch { return u } }
const isVendorLink = (u: string) => { const host = hostOf(u).toLowerCase(); return host !== 'nvd.nist.gov' && host !== 'cisa.gov' && !host.endsWith('.cisa.gov') }

/** M2-1: general "Have I been hit?" checks for the software family when no confirmed pack lists signs for the CVE (INV-8). */
export function GeneralChecks({ finding }: { finding: FindingDetail }) {
  const { t } = useTranslation('findings')
  const c = finding.hardening?.checks
  if (!c) return null
  const vendor = finding.kev?.links.filter(isVendorLink) ?? []
  return (
    <div className="grid gap-4" data-testid="general-checks">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <h3 className="text-sm font-semibold">{t('hardening.checksTitle', { family: finding.hardening!.family })}</h3>
        <GeneralLabel />
      </div>
      <p className="max-w-3xl text-sm">{c.summary}</p>
      {vendor.length > 0 ? (
        <ul className="grid gap-1 text-sm">
          {vendor.map((u) => <li key={u}><a className="break-all text-accent underline underline-offset-4" href={u} target="_blank" rel="noopener noreferrer">{t('rec.vendorLink', { host: hostOf(u) })}</a></li>)}
        </ul>
      ) : null}
      <ul className="grid gap-4">
        {c.indicators.map((i) => (
          <li key={i.title} className="grid gap-2">
            <p className="text-sm font-medium">{i.title}</p>
            <p className="max-w-3xl text-meta text-muted">{i.detail}</p>
            {i.commands?.map((cmd) => <CodeBlock key={cmd.label} code={cmd.code} label={cmd.label} wrapOnPhone />)}
          </li>
        ))}
      </ul>
      <div className="grid gap-1.5 border-t border-rule pt-3">
        <h3 className="text-sm font-semibold">{t('compromise.ifFound')}</h3>
        <ol className="grid list-decimal gap-1 pl-5 text-sm">{c.if_found.map((s) => <li key={s}>{s}</li>)}</ol>
      </div>
    </div>
  )
}
