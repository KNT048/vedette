import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { RefreshCw } from 'lucide-react'
import { Panel, KeyValue } from '@/components/common/PageHeader'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { fmtDate, fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useVerify } from './api'
import type { Target } from './types'

/**
 * Step 1: prove ownership.
 * Domain: a DNS TXT record (like other providers). Vedette re-checks it right before every scan.
 * IP: only the public IP this box really uses to reach the Internet; it is verified for 90 days and re-verified here.
 */
export function VerifyPanel({ target }: { target: Target }) {
  const { t } = useTranslation('exposure')
  const can = useCan('operator')
  const verify = useVerify()
  const check = target.last_check
  const domain = target.kind === 'domain'
  const verified = target.status !== 'unverified'

  function run() {
    verify.mutate(target.id, {
      onSuccess: (r) => (r.verified ? toast.success(t('verify.okToast', { value: target.value })) : toast.message(t('verify.failToast'))),
      onError: (e) => toast.error(e instanceof Error ? e.message : String(e)),
    })
  }
  const label = domain ? (verified ? t('verify.checkAgain') : t('verify.recheck')) : t('verify.ipRecheck')
  const recheck = (
    <div className="flex flex-wrap items-center gap-3">
      <Button variant={verified && target.blocked_reason !== 'txt_missing' && target.validity !== 'expired' ? 'secondary' : 'primary'} onClick={run} disabled={!can || verify.isPending} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}>
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
              <p className="max-w-3xl text-sm">{t('verify.doneDomain', { time: fmtDateTime(target.verified_at) })}</p>
              {target.blocked_reason === 'txt_missing' ? <p role="alert" className="max-w-3xl rounded-md border border-warn/50 bg-warn-soft/60 px-3 py-2 text-sm">{t('verify.txtMissing')}</p> : null}
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
          <p className="max-w-3xl text-sm">{t('verify.ipIntro', { value: target.value })}</p>
          <KeyValue items={[
            { label: t('verify.ipStatus'), value: target.validity === 'expired' ? <Chip tone="danger">{t('status.expired')}</Chip> : target.validity === 'expiring' ? <Chip tone="warn">{t('status.expiresIn', { count: Math.max(0, Math.ceil((Date.parse(target.expires_at ?? '') - Date.now()) / 864e5)) })}</Chip> : <Chip tone="ok">{t('verify.valid')}</Chip> },
            { label: t('verify.verifiedOn'), value: fmtDateTime(target.verified_at) },
            { label: t('verify.expiresOn'), value: fmtDate(target.expires_at) },
          ]} />
          {target.validity === 'expired' ? <p role="alert" className="max-w-3xl rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{t('verify.ipExpired')}</p> : null}
        </>
      )}
      {recheck}
      {check ? (
        <div role="status" className={`rounded-md border px-3 py-2 text-sm ${check.ok ? 'border-ok/40 bg-ok-soft' : 'border-warn/50 bg-warn-soft/60'}`}>
          <p className="mb-1 flex flex-wrap items-center gap-2"><Chip tone={check.ok ? 'ok' : 'warn'}>{domain ? (check.ok ? t('verify.found') : t('verify.notFound')) : (check.ok ? t('verify.passed') : t('verify.failed'))}</Chip><span className="text-[12px] text-muted">{t('verify.checkedAt', { time: fmtDateTime(check.at) })}</span></p>
          <p>{check.message}</p>
        </div>
      ) : null}
    </Panel>
  )
}
