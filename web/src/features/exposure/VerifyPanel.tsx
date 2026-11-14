import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { RefreshCw } from 'lucide-react'
import { Notice, Panel, KeyValue } from '@/components/common/PageHeader'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { dateText, dateTimeText } from './dates'
import { useCan } from '@/lib/session'
import { useVerify } from './api'
import type { Target } from './types'

/**
 * Step 1: prove ownership.
 * Domain: a DNS TXT record (like other providers). Vedette re-checks it right before every scan.
 * IP: only the public IP this box really uses to reach the Internet; the box renews it for 30 days each time it sees it (auto-detect, or Verify again here).
 */
export function VerifyPanel({ target }: { target: Target }) {
  const { t } = useTranslation('exposure')
  const can = useCan('operator')
  const verify = useVerify()
  const check = target.last_check
  const domain = target.kind === 'domain'
  const verified = target.status !== 'unverified'
  // The box was just checked and no longer goes out through this IP: the green result of an earlier check would say the opposite, so it is not shown.
  const paused = target.blocked_reason === 'ip_not_current'

  function run() {
    verify.mutate(target.id, {
      onSuccess: (r) => (r.verified ? toast.success(t('verify.okToast', { value: target.value })) : toast.message(t('verify.failToast'))),
      onError: (e) => toast.error(e instanceof Error ? e.message : String(e)),
    })
  }
  const label = domain ? (verified ? t('verify.checkAgain') : t('verify.recheck')) : t('verify.ipRecheck')
  const recheck = (
    <div className="flex flex-wrap items-center gap-3">
      <Button variant={verified && target.blocked_reason !== 'txt_missing' && !paused && target.validity !== 'expired' ? 'secondary' : 'primary'} onClick={run} disabled={!can || verify.isPending} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}>
        <RefreshCw className={verify.isPending ? 'animate-spin motion-reduce:animate-none' : undefined} />{verify.isPending ? t('verify.checking') : label}
      </Button>
      <span className="max-w-xl text-[13px] text-muted">{domain ? t('verify.recheckHint') : t('verify.ipRecheckHint', { value: target.value })}</span>
    </div>
  )

  return (
    <Panel className="grid gap-4 p-4">
      {domain ? (
        <>
          {verified ? (
            <>
              <p className="max-w-3xl text-sm">{t('verify.doneDomain', { time: dateTimeText(target.verified_at) })}</p>
              {target.blocked_reason === 'txt_missing' ? <Notice tone="warn" role="alert" className="mb-0!" title={t('verify.txtMissing')} /> : null}
            </>
          ) : <p className="max-w-3xl text-sm">{t('verify.dnsIntro', { value: target.value })}</p>}
          {!verified || target.blocked_reason === 'txt_missing' ? (
            <>
              <KeyValue items={[
                { label: t('verify.dns.type'), value: 'TXT' },
                { label: t('verify.dns.name'), value: t('verify.dns.nameValue', { value: target.value }) },
                { label: t('verify.dns.ttl'), value: t('verify.dns.ttlValue') },
              ]} />
              <CodeBlock code={`vedette-verify=${target.token}`} label={t('verify.dns.valueLabel')} />
              <p className="max-w-3xl text-[13px] text-muted">{t('verify.dnsHint')}</p>
            </>
          ) : <p className="max-w-3xl text-[13px] text-muted">{t('verify.keepRecord')}</p>}
        </>
      ) : (
        <>
          {/* The "verified because the box reaches the Internet through it" fact is said once, in the step description above. */}
          <KeyValue items={[
            { label: t('verify.ipStatus'), value: target.validity === 'expired' ? <Chip tone="danger">{t('status.expired')}</Chip> : paused ? <Chip tone="warn">{t('verify.pausedChip')}</Chip> : target.validity === 'expiring' ? <Chip tone="warn">{t('status.expiresIn', { count: Math.max(0, Math.ceil((Date.parse(target.expires_at ?? '') - Date.now()) / 864e5)) })}</Chip> : <Chip tone="ok">{t('verify.valid')}</Chip> },
            { label: t('verify.verifiedOn'), value: dateTimeText(target.verified_at) },
            { label: t('verify.expiresOn'), value: dateText(target.expires_at) },
          ]} />
          {target.validity === 'expired' ? <Notice tone="danger" role="alert" className="mb-0!" title={t('verify.ipExpired')} /> : null}
          {paused ? <Notice tone="warn" role="alert" className="mb-0!" title={t('verify.paused', { time: dateTimeText(target.verified_at) })} /> : null}
        </>
      )}
      {recheck}
      {check && !paused ? (
        <div role="status" className={`rounded-md border px-3 py-2 text-sm ${check.ok ? 'border-ok/40 bg-ok-soft' : 'border-warn/50 bg-warn-soft/60'}`}>
          <p className="mb-1 flex flex-wrap items-center gap-2"><Chip tone={check.ok ? 'ok' : 'warn'}>{domain ? (check.ok ? t('verify.found') : t('verify.notFound')) : (check.ok ? t('verify.passed') : t('verify.failed'))}</Chip><span className="text-[12px] text-muted">{t('verify.checkedAt', { time: dateTimeText(check.at) })}</span></p>
          <p>{check.message}</p>
        </div>
      ) : null}
    </Panel>
  )
}
