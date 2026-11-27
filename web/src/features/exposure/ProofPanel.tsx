import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { RefreshCw } from 'lucide-react'
import { BusyNote } from '@/components/common/BusyNote'
import { CodeBlock } from '@/components/common/CodeBlock'
import { KeyValue, Panel } from '@/components/common/PageHeader'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { fmtDate, fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useVerifyNode } from './api'
import { InfoLine } from '@/components/common/InfoLine'
import { boxIp, proven } from './node'
import type { DnsProof, FileProof, TargetNode } from './types'
import { checkPause, secondsToWait, useCooldown } from './useCooldown'

const link = 'text-accent underline-offset-4 hover:underline'

/**
 * Ownership of one node. A domain proves itself with a DNS TXT record, unless a proven ancestor's record covers it; a public IP
 * typed in proves itself with a token file served on it or a reverse DNS name; the box's own IP is proved by the box going out
 * through it. The check of a domain or a typed IP is allowed once every 30 seconds per target: the button counts the pause down.
 */
export function ProofPanel({ node }: { node: TargetNode }) {
  const { t } = useTranslation('exposure')
  const can = useCan('operator')
  const verify = useVerifyNode()
  const cool = useCooldown()
  const p = node.proof
  const own = !boxIp(node)
  const ok = proven(node)
  function run() {
    if (own) cool.start(checkPause.seconds)
    verify.mutate(node.id, {
      onSuccess: (r) => (r.verified ? toast.success(t('verify.okToast', { value: node.value })) : toast.message(t('verify.failToast'))),
      onError: (e) => { const w = secondsToWait(e); if (w > 0) cool.start(w); toast.error(e instanceof Error ? e.message : String(e)) },
    })
  }
  const waiting = own && cool.left > 0
  const label = waiting ? t('verify.wait', { count: cool.left }) : own ? (ok ? t('verify.checkAgain') : t('verify.recheck')) : t('verify.ipRecheck')
  if (p.state === 'covered' && p.covered_by) {
    return (
      <Panel className="grid gap-2 p-4 text-sm">
        <p>{t('proof.coveredLine', { value: node.value })} <Link className={link} to={`/exposure/${encodeURIComponent(p.covered_by.id)}?tab=ownership`}>{p.covered_by.value}</Link></p>
        <p className="text-meta text-muted">{t('proof.coveredKeep', { parent: p.covered_by.value })}</p>
        {p.last_check ? <LastCheck check={p.last_check} own={own} /> : null}
      </Panel>
    )
  }
  return (
    <Panel className="grid gap-4 p-4">
      {p.dns ? <DnsSteps node={node} dns={p.dns} /> : p.file ? <FileSteps node={node} file={p.file} /> : <BoxIpState node={node} />}
      <div className="flex flex-wrap items-center gap-3">
        <Button variant={ok ? 'secondary' : 'primary'} onClick={run} disabled={!can || waiting} busy={verify.isPending} busyLabel={t('common:busy.checking')} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}>
          <RefreshCw />{label}
        </Button>
        {p.dns ? <span className="max-w-xl text-meta text-muted">{t('verify.recheckHint')}</span>
          : p.file ? <span className="max-w-xl text-meta text-muted">{t('verify.typed.recheckHint')}</span>
          : <InfoLine className="max-w-xl text-meta text-muted" topic={t('verify.ipRecheck')} info={t('verify.ipRecheckHintInfo')}>{t('verify.ipRecheckHint', { value: node.value })}</InfoLine>}
        {/* Verify again of the box's IP is a full check, 5 rounds of three public services; a DNS lookup is quick */}
        {own ? null : <BusyNote busy={verify.isPending} className="basis-full">{t('verify.ipWaiting')}</BusyNote>}
      </div>
      {p.last_check && p.state !== 'not_current' ? <LastCheck check={p.last_check} own={own} /> : null}
    </Panel>
  )
}

/** The last ownership check: found, or not found with what was asked (inside the 90 days of the last pass, a warning only). */
function LastCheck({ check, own }: { check: NonNullable<TargetNode['proof']['last_check']>; own: boolean }) {
  const { t } = useTranslation('exposure')
  return (
    <div role="status" className={`rounded-md border px-3 py-2 text-sm ${check.ok ? 'border-ok/40 bg-ok-soft' : 'border-warn/50 bg-warn-soft/60'}`}>
      <p className="mb-1 flex flex-wrap items-center gap-2"><Chip tone={check.ok ? 'ok' : 'warn'}>{own ? (check.ok ? t('verify.found') : t('verify.notFound')) : (check.ok ? t('verify.passed') : t('verify.failed'))}</Chip><span className="text-caption text-muted">{t('verify.checkedAt', { time: fmtDateTime(check.at) })}</span></p>
      <p>{check.message}</p>
    </div>
  )
}

/** A domain: proven (keep the record), or where its TXT record goes: the zone's apex, or the name that proves this target only. */
function DnsSteps({ node, dns }: { node: TargetNode; dns: DnsProof }) {
  const { t } = useTranslation('exposure')
  const p = node.proof
  if (p.state === 'proven') {
    return <>
      <InfoLine className="max-w-3xl text-sm" topic={t('verify.dnsTopic')} info={t('verify.doneDomainInfo')}>{t('verify.doneDomain', { time: fmtDateTime(p.verified_at) })}</InfoLine>
      <p className="max-w-3xl text-meta text-muted">{t('proof.coversNames', { value: node.value })} {t('verify.keepRecord')}</p>
    </>
  }
  const apex = dns.zone === node.value
  return (
    <>
      <InfoLine className="max-w-3xl text-sm" topic={t('verify.dnsTopic')} info={t('verify.dnsIntroInfo')}>{apex ? t('verify.dnsIntroZone', { zone: dns.zone }) : t('verify.dnsIntroSub', { zone: dns.zone, value: node.value })}</InfoLine>
      <KeyValue items={[
        { label: t('verify.dns.type'), value: 'TXT' },
        { label: t('verify.dns.name'), value: <span data-testid="proof-host">{dns.host === '@' ? t('verify.dns.nameZone', { zone: dns.zone }) : dns.host}</span> },
        { label: t('verify.dns.ttl'), value: t('verify.dns.ttlValue') },
      ]} />
      <CodeBlock code={dns.value} label={t('verify.dns.valueLabel')} />
      <InfoLine className="max-w-3xl text-meta text-muted" topic={t('verify.dns.valueLabel')} info={t('verify.dnsHintInfo')}>{t('verify.dnsHint')}</InfoLine>
      {!apex && dns.alt_host ? <div data-testid="proof-alt"><InfoLine className="max-w-3xl text-meta text-muted" topic={t('verify.dns.valueLabel')} info={t('verify.cnameHintInfo', { value: node.value, alt: dns.alt_host })}>{t('verify.cnameHint', { zone: dns.zone, alt: dns.alt_host })}</InfoLine></div> : null}
      {apex ? <p className="max-w-3xl text-meta text-muted">{t('proof.coversNames', { value: node.value })}</p> : null}
    </>
  )
}

/** A public IP typed in: proved (until when, next check), or where its proof goes: a token file on it, or a reverse DNS name. */
function FileSteps({ node, file }: { node: TargetNode; file: FileProof }) {
  const { t } = useTranslation('exposure')
  const p = node.proof
  if (p.state === 'proven') {
    return (
      <>
        <p className="max-w-3xl text-sm">{t('verify.typed.done', { value: node.value, by: t(`verify.typed.by.${p.method ?? 'ip_file'}`) })}</p>
        <KeyValue items={[
          { label: t('verify.typed.verifiedOn'), value: fmtDateTime(p.verified_at) },
          { label: t('verify.expiresOn'), value: <span data-testid="proof-expires">{fmtDate(p.expires_at)}</span> },
          { label: t('verify.typed.nextCheck'), value: <span data-testid="proof-next">{p.next_check_at ? fmtDateTime(p.next_check_at) : '—'}</span> },
        ]} />
        <p className="max-w-3xl text-meta text-muted">{t('verify.typed.keep')}</p>
      </>
    )
  }
  return (
    <>
      <InfoLine className="max-w-3xl text-sm" topic={t('verify.typed.topic')} info={t('verify.typed.introInfo')}>{p.state === 'expired' ? t('verify.typed.introExpired', { value: node.value }) : t('verify.typed.intro', { value: node.value })}</InfoLine>
      <h2 className="text-sm font-medium">{t('verify.typed.fileTitle')}</h2>
      <KeyValue items={[
        { label: t('verify.typed.path'), value: <span data-testid="proof-path">/.well-known/vedette-verify.txt</span> },
        { label: t('verify.typed.urls'), value: <span className="grid break-all">{file.urls.map((u) => <span key={u}>{u}</span>)}</span> },
      ]} />
      <CodeBlock code={file.content} label={t('verify.typed.contentLabel')} />
      <p className="max-w-3xl text-meta text-muted">{t('verify.typed.fileHint')}</p>
      <h2 className="text-sm font-medium">{t('verify.typed.ptrTitle')}</h2>
      <p className="max-w-3xl text-sm" data-testid="proof-ptr">{file.ptr_domains.length > 0 ? t('verify.typed.ptr', { value: node.value, domains: file.ptr_domains.join(', ') }) : t('verify.typed.ptrNone', { value: node.value })}</p>
      <p className="max-w-3xl text-meta text-muted">{t('verify.typed.aRecord')}</p>
    </>
  )
}

/** The box's own IP: valid while the box goes out through it (renewed each time it does), not in use now (still scannable), or expired
 *  after 90 days unseen. */
function BoxIpState({ node }: { node: TargetNode }) {
  const { t } = useTranslation('exposure')
  const p = node.proof
  const days = p.expires_at ? Math.max(0, Math.ceil((Date.parse(p.expires_at) - Date.now()) / 864e5)) : null
  const state = p.state === 'expired' ? <Chip tone="danger">{t('proof.state.expired')}</Chip>
    : p.state === 'not_current' ? <Chip tone="warn">{t('verify.pausedChip')}</Chip>
    : days !== null && days <= 5 ? <Chip tone="warn">{t('status.expiresIn', { count: days })}</Chip> : <Chip tone="ok">{t('verify.valid')}</Chip>
  return (
    <>
      {p.state === 'not_current' ? <InfoLine className="max-w-3xl text-sm text-warn" topic={t('verify.pausedChip')} info={t('verify.pausedInfo')}>{t('verify.paused', { time: fmtDateTime(p.verified_at) })}</InfoLine>
        : p.state === 'expired' ? <InfoLine className="max-w-3xl text-sm text-danger" topic={t('proof.state.expired')} info={t('verify.ipExpiredInfo')}>{t('verify.ipExpired')}</InfoLine> : null}
      {p.replaced ? <p className="max-w-3xl text-sm text-warn" data-testid="proof-replaced">{t('verify.replaced', { ip: p.replaced.by, date: fmtDate(p.replaced.at) })}</p> : null}
      <KeyValue items={[
        { label: t('verify.ipStatus'), value: state },
        { label: t('verify.verifiedOn'), value: fmtDateTime(p.verified_at) },
        { label: t('verify.expiresOn'), value: fmtDate(p.expires_at) },
      ]} />
    </>
  )
}
