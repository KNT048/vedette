import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Notice, Panel } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/input'
import { useCan } from '@/lib/session'
import { useAcceptTerms, useRevokeTerms } from './api'
import { dateTimeText } from './dates'
import type { Target } from './types'

/**
 * FULL-1 (S-EXP-2, D-566): the testing terms of a verified target, one screen. Accepted once, every scan of the target is a deep scan;
 * the one extra tick, off by default, adds the disruptive checks. The text is the backend's (terms_notice), one paragraph per line: the
 * opening sentence, what the tools may send, then the risk. Admin only; withdrawing is always possible.
 */
export function TermsPanel({ target }: { target: Target }) {
  const { t } = useTranslation('exposure')
  const can = useCan('admin')
  const accept = useAcceptTerms(target.id)
  const revoke = useRevokeTerms(target.id)
  const n = target.terms_notice
  const a = target.terms
  const [disruptive, setDisruptive] = useState(target.full_scan && a ? a.disruptive : false)
  const lines = n.text.split('\n')
  const verified = target.status === 'verified'
  const changed = !target.full_scan || a?.disruptive !== disruptive
  const locked = !can ? t('common:needRole', { role: t('common:role.admin') }) : !verified ? t('terms.needVerified') : undefined
  const onError = (e: unknown) => toast.error(e instanceof Error ? e.message : String(e))
  return (
    <Panel className="grid max-w-3xl gap-3 p-4 text-sm">
      <p role="status" className="font-medium">
        {target.full_scan && a ? t('terms.accepted', { by: a.by, time: dateTimeText(a.at) }) + ' ' + t(a.disruptive ? 'terms.withDisruptive' : 'terms.withoutDisruptive')
          : a ? t('terms.changed') : t('terms.none')}
      </p>
      <div className="grid gap-2 rounded-md border border-line p-3" aria-label={t('terms.textLabel')} role="group">
        <p>{lines[0]}</p>
        <ul className="grid list-disc gap-1.5 pl-5">{lines.slice(1, -1).map((l) => <li key={l}>{l}</li>)}</ul>
        <p>{lines[lines.length - 1]}</p>
      </div>
      {target.terms_warning ? <Notice tone="warn" role="alert" className="mb-0" title={target.terms_warning} />
        : target.kind === 'ip' ? <p className="text-[13px] text-muted">{t('terms.cgnatLimit')}</p> : null}
      <div className="flex items-start gap-2">
        <Checkbox id={`terms-disruptive-${target.id}`} className="mt-0.5" checked={disruptive} disabled={!!locked || !!target.terms_warning} onCheckedChange={(v) => setDisruptive(v === true)} />
        <Label htmlFor={`terms-disruptive-${target.id}`} className="font-normal">{n.disruptive}</Label>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="primary" disabled={!!locked || !changed || accept.isPending} title={locked}
          onClick={() => accept.mutate({ version: n.version, disruptive }, { onSuccess: () => toast.success(t('terms.toastAccepted')), onError })}>
          {t(target.full_scan ? 'terms.acceptChange' : 'terms.accept')}
        </Button>
        {a ? (
          <Button disabled={!can || revoke.isPending} title={!can ? locked : undefined}
            onClick={() => revoke.mutate(undefined, { onSuccess: () => { setDisruptive(false); toast.success(t('terms.toastWithdrawn')) }, onError })}>
            {t('terms.withdraw')}
          </Button>
        ) : null}
      </div>
      {locked ? <p className="text-[13px] text-muted">{locked}</p> : <p className="text-[13px] text-muted">{t('terms.who')} {t('terms.stops')}</p>}
    </Panel>
  )
}
