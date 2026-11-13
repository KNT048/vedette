import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Chip } from '@/components/common/StatusChip'
import { ErrorState, Loading } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { useCan } from '@/lib/session'
import { errText, useIncidentPanel, useRequestFromIncident } from './api'
import { RiskChip } from './parts'
import type { IncidentOption } from './types'

const link = 'text-accent underline underline-offset-4'

/** Respond on an incident (D-509, S-RESP-3): the incident's source and only what can really be asked for it. Asking creates a
 * request that waits for approval like any other; nothing here changes a device. */
export function IncidentRespond({ id }: { id: string }) {
  const { t } = useTranslation('response')
  const q = useIncidentPanel(id)
  const [sent, setSent] = useState<string | null>(null)
  if (q.isPending) return <Loading />
  if (q.error) return <div className="mb-6"><ErrorState error={q.error} onRetry={() => void q.refetch()} /></div>
  const { incident, source, options } = q.data
  const ready = options.some((o) => o.ready || o.requested)
  return (
    <section aria-labelledby="incident-respond" className="mb-6 grid gap-3 rounded-md border border-rule bg-surface p-4">
      <div className="grid gap-1">
        <h2 id="incident-respond" className="text-base font-semibold">{t('incident.heading')}</h2>
        <p className="text-sm"><Link className={link} to={`/incidents/${encodeURIComponent(incident.id)}`}>{incident.title}</Link></p>
      </div>
      {!source ? (
        <p className="text-sm text-muted">{t('incident.noSource')} <Link className={link} to="/response?tab=rules">{t('incident.toRules')}</Link></p>
      ) : (
        <>
          <p className="flex flex-wrap items-center gap-2 text-sm">
            <span>{t('incident.source')}: <span className="font-medium">{source.ip}</span>{source.device ? <> ({source.asset_id ? <Link className={link} to={`/devices/${encodeURIComponent(source.asset_id)}`}>{source.device}</Link> : source.device})</> : null}</span>
            <Chip tone={source.scope === 'lan' ? 'warn' : 'danger'}>{t(`incident.scope.${source.scope}`)}</Chip>
          </p>
          {sent ? (
            <p role="status" className="rounded-md border border-rule bg-paper px-3 py-2 text-sm">{t('incident.sent', { title: sent })} <Link className={link} to="/response?tab=requests">{t('incident.toRequests')}</Link></p>
          ) : null}
          {options.length ? <ul className="grid gap-2">{options.map((o) => <OptionRow key={o.action_id} id={incident.id} o={o} onSent={setSent} />)}</ul> : null}
          {source.scope === 'lan' && !ready ? (
            <div className="grid gap-1.5 rounded-md border border-dashed border-rule bg-paper px-3 py-2 text-sm">
              <p className="font-medium">{t('incident.lanNothing')}</p>
              <ol className="ml-5 grid list-decimal gap-1">
                <li>{t('incident.doNow')} {incident.action}</li>
                <li>{t('incident.letVedette')} <Link className={link} to="/settings/connections">{t('incident.toConnections')}</Link>{t('incident.thenCatalog')} <Link className={link} to="/settings/response">{t('incident.toCatalog')}</Link>{t('incident.thenRule')} <Link className={link} to="/response?tab=rules">{t('incident.toRules')}</Link></li>
              </ol>
            </div>
          ) : null}
          {source.scope === 'lan' ? <p className="text-[13px] text-muted">{t('incident.noBlocklist', { ip: source.ip })}</p> : null}
        </>
      )}
    </section>
  )
}

function OptionRow({ id, o, onSent }: { id: string; o: IncidentOption; onSent: (title: string) => void }) {
  const { t } = useTranslation('response')
  const can = useCan('operator')
  const ask = useRequestFromIncident()
  return (
    <li className="grid gap-1.5 rounded-md border border-rule bg-paper p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="grid gap-0.5">
          <p className="text-sm font-medium">{o.title}</p>
          <p className="flex flex-wrap items-center gap-2 text-[13px] text-muted">
            <span>{o.device ? (o.connection ? t('incident.on', { connection: o.connection }) : t('incident.noConnection')) : t('action.viaBox')}</span>
            <RiskChip risk={o.risk} />
            <span>{t('incident.undo', { hours: Math.round(o.ttl_min / 60) })}</span>
          </p>
        </div>
        {o.requested ? <Link className={`text-[13px] ${link}`} to="/response?tab=requests">{t('incident.requested')}</Link>
          : <Button size="sm" disabled={!can || !o.ready || ask.isPending} title={!can ? t('common:needRole', { role: t('common:role.operator') }) : undefined}
              onClick={() => ask.mutate({ id, action_id: o.action_id }, { onSuccess: (a) => { onSent(a.title); toast.success(t('incident.sentToast')) }, onError: (e) => toast.error(errText(e)) })}>{t('incident.ask')}</Button>}
      </div>
      {o.why && !o.requested ? <p className="text-[13px] text-muted">{o.why}</p> : null}
    </li>
  )
}
