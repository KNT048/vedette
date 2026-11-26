import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Notice, Panel } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { useCan } from '@/lib/session'
import { useAcceptTerms, useRevokeTerms } from './api'
import { InfoLine } from '@/components/common/InfoLine'
import { boxIp, termsAcceptable } from './node'
import type { TargetNode } from './types'
import { fmtDateTime } from '@/lib/format'

/** One paragraph per line: the opening sentence, what the tools may send (the disruptive checks among them), then the risk. */
function TermsText({ text, label }: { text: string; label: string }) {
  const lines = text.split('\n')
  return (
    <div className="grid gap-2 rounded-md border border-line p-3" aria-label={label} role="group">
      <p>{lines[0]}</p>
      {lines.length > 2 ? <ul className="grid list-disc gap-1.5 pl-5">{lines.slice(1, -1).map((l) => <li key={l}>{l}</li>)}</ul> : null}
      {lines.length > 1 ? <p>{lines[lines.length - 1]}</p> : null}
    </div>
  )
}

/** What the accepted terms do about the disruptive checks. Behind carrier-grade NAT (refused) they never run on the box's own IP and
 *  cannot be accepted, so the line points to the warning instead of offering to accept again. */
function disruptiveKey(included: boolean, refused: boolean) {
  if (refused) return included ? 'terms.disruptiveHeldShared' : 'terms.withoutDisruptiveShared'
  return included ? 'terms.withDisruptive' : 'terms.withoutDisruptive'
}

/**
 * S-EXP-2: the testing terms of a verified target, one screen and one button. Accepted once, every scan of the target is a deep scan
 * and a scan a person starts also runs the disruptive checks (scheduled scans never do). The text is the backend's (terms_notice).
 * An acceptance of the earlier terms made without their disruptive tick stays valid (deep scan only) and the panel offers to accept
 * the terms again to include them. Admin only; withdrawing is always possible.
 */
export function TermsPanel({ node: target }: { node: TargetNode }) {
  const { t } = useTranslation('exposure')
  const can = useCan('admin')
  const accept = useAcceptTerms(target.id)
  const revoke = useRevokeTerms(target.id)
  const n = target.terms_notice
  const a = target.terms
  const done = target.deep && !!a?.disruptive
  // the box's own IP behind carrier-grade NAT: the terms are refused (a typed IP's warning is advice; it can be accepted)
  const refused = !!target.terms_warning && boxIp(target)
  const locked = !can ? t('common:needRole', { role: t('common:role.admin') }) : !termsAcceptable(target) ? t('terms.needVerified') : undefined
  const onError = (e: unknown) => toast.error(e instanceof Error ? e.message : String(e))
  return (
    <Panel className="grid max-w-3xl gap-3 p-4 text-sm">
      <p role="status" className="font-medium">
        {target.deep && a ? t('terms.accepted', { by: a.by, time: fmtDateTime(a.at) }) + ' ' + t(disruptiveKey(a.disruptive, refused))
          : a ? t('terms.changed') : t('terms.none')}
      </p>
      {/* accepted in full: the text they accepted is one click away; otherwise the current terms are what the person reads before accepting */}
      {done && a ? <details><summary className="cursor-pointer text-meta font-medium text-accent">{t('terms.read')}</summary><div className="mt-2"><TermsText text={a.text} label={t('terms.textLabel')} /></div></details>
        : <TermsText text={n.text} label={t('terms.textLabel')} />}
      {target.terms_warning ? <Notice tone="warn" role="alert" className="mb-0" title={target.terms_warning} />
        : target.kind === 'ip' ? <InfoLine className="text-meta text-muted" topic={t('terms.cgnatTopic')} info={t('terms.cgnatLimitInfo')}>{t('terms.cgnatLimit')}</InfoLine> : null}
      <div className="flex flex-wrap items-center gap-3">
        {!done && !refused ? (
          <Button variant="primary" disabled={!!locked || revoke.isPending} busy={accept.isPending} busyLabel={t('common:busy.saving')} title={locked}
            onClick={() => accept.mutate({ version: n.version }, { onSuccess: () => toast.success(t('terms.toastAccepted')), onError })}>
            {t('terms.accept')}
          </Button>
        ) : null}
        {a ? (
          <Button disabled={!can || accept.isPending} busy={revoke.isPending} busyLabel={t('terms.withdrawing')} title={!can ? locked : undefined}
            onClick={() => revoke.mutate(undefined, { onSuccess: () => toast.success(t('terms.toastWithdrawn')), onError })}>
            {t('terms.withdraw')}
          </Button>
        ) : null}
      </div>
      {locked ? <p className="text-meta text-muted">{locked}</p> : null}
    </Panel>
  )
}
