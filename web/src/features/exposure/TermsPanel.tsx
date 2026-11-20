import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Notice, Panel } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/input'
import { useCan } from '@/lib/session'
import { useAcceptTerms, useRevokeTerms } from './api'
import { InfoLine } from './InfoLine'
import { proven } from './node'
import type { TargetNode } from './types'
import { fmtDateTime } from '@/lib/format'

/**
 * S-EXP-2: the testing terms of a verified target, one screen. Accepted once, every scan of the target is a deep scan;
 * the one extra tick, off by default, adds the disruptive checks. The text is the backend's (terms_notice), one paragraph per line: the
 * opening sentence, what the tools may send, then the risk. Admin only; withdrawing is always possible.
 */
export function TermsPanel({ node: target }: { node: TargetNode }) {
  const { t } = useTranslation('exposure')
  const can = useCan('admin')
  const accept = useAcceptTerms(target.id)
  const revoke = useRevokeTerms(target.id)
  const n = target.terms_notice
  const a = target.terms
  const [disruptive, setDisruptive] = useState(target.deep && a ? a.disruptive : false)
  const lines = n.text.split('\n')
  const verified = proven(target)
  const changed = !target.deep || a?.disruptive !== disruptive
  const locked = !can ? t('common:needRole', { role: t('common:role.admin') }) : !verified ? t('terms.needVerified') : undefined
  const onError = (e: unknown) => toast.error(e instanceof Error ? e.message : String(e))
  const text = (
    <div className="grid gap-2 rounded-md border border-line p-3" aria-label={t('terms.textLabel')} role="group">
      <p>{lines[0]}</p>
      <ul className="grid list-disc gap-1.5 pl-5">{lines.slice(1, -1).map((l) => <li key={l}>{l}</li>)}</ul>
      <p>{lines[lines.length - 1]}</p>
    </div>
  )
  return (
    <Panel className="grid max-w-3xl gap-3 p-4 text-sm">
      <p role="status" className="font-medium">
        {target.deep && a ? t('terms.accepted', { by: a.by, time: fmtDateTime(a.at) }) + ' ' + t(a.disruptive ? 'terms.withDisruptive' : 'terms.withoutDisruptive')
          : a ? t('terms.changed') : t('terms.none')}
      </p>
      {/* accepted and current: the text they accepted is one click away; otherwise it is what the person reads before accepting */}
      {target.deep && a ? <details><summary className="cursor-pointer text-meta font-medium text-accent">{t('terms.read')}</summary><div className="mt-2">{text}</div></details> : text}
      {target.terms_warning ? <Notice tone="warn" role="alert" className="mb-0" title={target.terms_warning} />
        : target.kind === 'ip' ? <InfoLine className="text-meta text-muted" topic={t('terms.cgnatTopic')} info={t('terms.cgnatLimitInfo')}>{t('terms.cgnatLimit')}</InfoLine> : null}
      <div className="flex items-start gap-2">
        <Checkbox id={`terms-disruptive-${target.id}`} className="mt-0.5" checked={disruptive} disabled={!!locked || !!target.terms_warning} onCheckedChange={(v) => setDisruptive(v === true)} />
        <Label htmlFor={`terms-disruptive-${target.id}`} className="font-normal">{n.disruptive}</Label>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="primary" disabled={!!locked || !changed || revoke.isPending} busy={accept.isPending} busyLabel={t('common:busy.saving')} title={locked}
          onClick={() => accept.mutate({ version: n.version, disruptive }, { onSuccess: () => toast.success(t('terms.toastAccepted')), onError })}>
          {t(target.deep ? 'terms.acceptChange' : 'terms.accept')}
        </Button>
        {a ? (
          <Button disabled={!can || accept.isPending} busy={revoke.isPending} busyLabel={t('terms.withdrawing')} title={!can ? locked : undefined}
            onClick={() => revoke.mutate(undefined, { onSuccess: () => { setDisruptive(false); toast.success(t('terms.toastWithdrawn')) }, onError })}>
            {t('terms.withdraw')}
          </Button>
        ) : null}
      </div>
      {locked ? <p className="text-meta text-muted">{locked}</p> : null}
    </Panel>
  )
}
