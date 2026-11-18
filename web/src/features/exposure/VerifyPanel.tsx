import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { RefreshCw } from 'lucide-react'
import { Panel, KeyValue } from '@/components/common/PageHeader'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { BusyNote } from '@/components/common/BusyNote'
import { useCan } from '@/lib/session'
import { useVerify } from './api'
import { checkPause, secondsToWait, useCooldown } from './useCooldown'
import { InfoLine } from './InfoLine'
import type { Target } from './types'
import { fmtDate, fmtDateTime } from '@/lib/format'

/**
 * Step 1: prove ownership.
 * Domain: a DNS TXT record (like other providers). Vedette re-checks it right before every scan.
 * IP the box found: only the public IP this box really uses to reach the Internet; the box renews it for 30 days each time it sees it (auto-detect, or Verify again here).
 * IP a person typed in: a token file served on it, or a reverse DNS name under a domain of this box; the proof lasts 30 days and the box checks it again by itself.
 * The check of a domain or a typed IP is allowed once every 30 seconds per target: the button counts the pause down.
 */
export function VerifyPanel({ target }: { target: Target }) {
  const { t } = useTranslation('exposure')
  const can = useCan('operator')
  const verify = useVerify()
  const check = target.last_check
  const domain = target.kind === 'domain'
  const typed = target.kind === 'ip' && target.origin === 'person'
  const cool = useCooldown()
  const verified = target.status !== 'unverified'
  // The box was just checked and no longer goes out through this IP: the green result of an earlier check would say the opposite, so it is not shown.
  const paused = target.blocked_reason === 'ip_not_current'
  // The Name to type in the domain's zone (@ for the zone itself, "git" for git.example.com), the dedicated name for a CNAME,
  // and a verified parent that covers this name already.
  const proof = target.proof

  function run() {
    if (domain || typed) cool.start(checkPause.seconds) // one check per 30 seconds per target
    verify.mutate(target.id, {
      onSuccess: (r) => (r.verified ? toast.success(t('verify.okToast', { value: target.value })) : toast.message(t('verify.failToast'))),
      onError: (e) => { const w = secondsToWait(e); if (w > 0) cool.start(w); toast.error(e instanceof Error ? e.message : String(e)) },
    })
  }
  const waiting = (domain || typed) && cool.left > 0
  const label = waiting ? t('verify.wait', { count: cool.left }) : domain || typed ? (verified ? t('verify.checkAgain') : t('verify.recheck')) : t('verify.ipRecheck')
  const recheck = (
    <div className="flex flex-wrap items-center gap-3">
      <Button variant={verified && target.blocked_reason !== 'txt_missing' && target.blocked_reason !== 'proof_missing' && !paused && target.validity !== 'expired' ? 'secondary' : 'primary'} onClick={run} disabled={!can || waiting} busy={verify.isPending} busyLabel={t('common:busy.checking')} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}>
        <RefreshCw />{label}
      </Button>
      {domain ? <span className="max-w-xl text-meta text-muted">{t('verify.recheckHint')}</span>
        : typed ? <span className="max-w-xl text-meta text-muted">{t('verify.typed.recheckHint')}</span>
        : <InfoLine className="max-w-xl text-meta text-muted" topic={t('verify.ipRecheck')} info={t('verify.ipRecheckHintInfo')}>{t('verify.ipRecheckHint', { value: target.value })}</InfoLine>}
      {/* Verify again of an IP is a full check, 5 rounds of three public services (5 s each at most); a DNS lookup is quick */}
      {domain || typed ? null : <BusyNote busy={verify.isPending} className="basis-full">{t('verify.ipWaiting')}</BusyNote>}
    </div>
  )

  return (
    <Panel className="grid gap-4 p-4">
      {domain ? (
        <>
          {verified ? (
            <>
              <p className="max-w-3xl text-sm">{t('verify.doneDomain', { time: fmtDateTime(target.verified_at) })}</p>
            </>
          ) : <InfoLine className="max-w-3xl text-sm" topic={t('verify.dnsTopic')} info={t('verify.dnsIntroInfo')}>{!proof ? t('verify.dnsIntro', { value: target.value }) : proof.zone === target.value ? t('verify.dnsIntroZone', { zone: proof.zone }) : t('verify.dnsIntroSub', { zone: proof.zone, value: target.value })}</InfoLine>}
          {proof?.covered_by && (!verified || target.blocked_reason === 'txt_missing') ? <p className="max-w-3xl text-sm" data-testid="proof-covered">{t('verify.coveredBy', { parent: proof.covered_by, value: target.value })}</p> : null}
          {!verified || target.blocked_reason === 'txt_missing' ? (
            <>
              <KeyValue items={[
                { label: t('verify.dns.type'), value: 'TXT' },
                { label: t('verify.dns.name'), value: <span data-testid="proof-host">{!proof ? t('verify.dns.nameValue', { value: target.value }) : t('verify.dns.nameZone', { zone: proof.zone })}</span> },
                { label: t('verify.dns.ttl'), value: t('verify.dns.ttlValue') },
              ]} />
              <CodeBlock code={`vedette-verify=${target.token}`} label={t('verify.dns.valueLabel')} />
              <InfoLine className="max-w-3xl text-meta text-muted" topic={t('verify.dns.valueLabel')} info={t('verify.dnsHintInfo')}>{t('verify.dnsHint')}</InfoLine>
              {/* The zone apex is the main path for every target; the dedicated name is the alternative for a subdomain */}
              {proof && proof.zone !== target.value && proof.alt_host ? <p className="max-w-3xl text-meta text-muted" data-testid="proof-cname">{t('verify.cnameHint', { zone: proof.zone, value: target.value, alt: proof.alt_host })}</p> : null}
              {/* review r1 L4 of #960: a delegated sub-zone takes the record at its own @ (prove accepts any parent name) */}
              {proof && proof.zone !== target.value ? <p className="max-w-3xl text-meta text-muted" data-testid="proof-delegated">{t('verify.delegatedHint', { zone: proof.zone, value: target.value })}</p> : null}
            </>
          ) : <p className="max-w-3xl text-meta text-muted">{t('verify.keepRecord')}</p>}
        </>
      ) : typed ? <TypedIpProof target={target} /> : (
        <>
          {/* The "verified because the box reaches the Internet through it" fact is said once, in the step description above. */}
          <KeyValue items={[
            { label: t('verify.ipStatus'), value: target.validity === 'expired' ? <Chip tone="danger">{t('status.expired')}</Chip> : paused ? <Chip tone="warn">{t('verify.pausedChip')}</Chip> : target.validity === 'expiring' ? <Chip tone="warn">{t('status.expiresIn', { count: Math.max(0, Math.ceil((Date.parse(target.expires_at ?? '') - Date.now()) / 864e5)) })}</Chip> : <Chip tone="ok">{t('verify.valid')}</Chip> },
            { label: t('verify.verifiedOn'), value: fmtDateTime(target.verified_at) },
            { label: t('verify.expiresOn'), value: fmtDate(target.expires_at) },
          ]} />
        </>
      )}
      {recheck}
      {check && !paused ? (
        <div role="status" className={`rounded-md border px-3 py-2 text-sm ${check.ok ? 'border-ok/40 bg-ok-soft' : 'border-warn/50 bg-warn-soft/60'}`}>
          <p className="mb-1 flex flex-wrap items-center gap-2"><Chip tone={check.ok ? 'ok' : 'warn'}>{domain || typed ? (check.ok ? t('verify.found') : t('verify.notFound')) : (check.ok ? t('verify.passed') : t('verify.failed'))}</Chip><span className="text-caption text-muted">{t('verify.checkedAt', { time: fmtDateTime(check.at) })}</span></p>
          <p>{check.message}</p>
        </div>
      ) : null}
    </Panel>
  )
}

/** A public IP typed in: where the proof goes (a token file on the IP, or a reverse DNS name), and once proved, how long it holds and when the box checks it again. */
function TypedIpProof({ target }: { target: Target }) {
  const { t } = useTranslation('exposure')
  const hint = target.ip_proof
  const proved = target.status === 'verified' && target.blocked_reason !== 'proof_missing'
  const expired = target.status === 'expired'
  return (
    <>
      {proved ? (
        <>
          <p className="max-w-3xl text-sm">{t('verify.typed.done', { value: target.value, by: t(`verify.typed.by.${target.method ?? 'ip_file'}`) })}</p>
          <KeyValue items={[
            { label: t('verify.typed.verifiedOn'), value: fmtDateTime(target.verified_at) },
            { label: t('verify.expiresOn'), value: <span data-testid="proof-expires">{fmtDate(target.expires_at)}</span> },
            { label: t('verify.typed.nextCheck'), value: <span data-testid="proof-next">{target.next_check_at ? fmtDateTime(target.next_check_at) : '-'}</span> },
          ]} />
          <p className="max-w-3xl text-meta text-muted">{t('verify.typed.keep')}</p>
        </>
      ) : (
        <>
          <InfoLine className="max-w-3xl text-sm" topic={t('verify.typed.topic')} info={t('verify.typed.introInfo')}>{expired ? t('verify.typed.introExpired', { value: target.value }) : t('verify.typed.intro', { value: target.value })}</InfoLine>
          {hint ? (
            <>
              <h3 className="text-sm font-medium">{t('verify.typed.fileTitle')}</h3>
              <KeyValue items={[
                { label: t('verify.typed.path'), value: <span data-testid="proof-path">{hint.path}</span> },
                { label: t('verify.typed.urls'), value: <span className="grid break-all">{hint.urls.map((u) => <span key={u}>{u}</span>)}</span> },
              ]} />
              <CodeBlock code={hint.content} label={t('verify.typed.contentLabel')} />
              <p className="max-w-3xl text-meta text-muted">{t('verify.typed.fileHint')}</p>
              <h3 className="text-sm font-medium">{t('verify.typed.ptrTitle')}</h3>
              <p className="max-w-3xl text-sm" data-testid="proof-ptr">{hint.ptr_domains.length > 0 ? t('verify.typed.ptr', { value: target.value, domains: hint.ptr_domains.join(', ') }) : t('verify.typed.ptrNone', { value: target.value })}</p>
              <p className="max-w-3xl text-meta text-muted">{t('verify.typed.aRecord')}</p>
            </>
          ) : null}
        </>
      )}
    </>
  )
}
