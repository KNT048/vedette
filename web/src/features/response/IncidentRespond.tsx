import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Chip } from '@/components/common/StatusChip'
import { Notice, PageHeader } from '@/components/common/PageHeader'
import { Card } from '@/components/common/Card'
import { ErrorState, Loading, ModuleOff } from '@/components/common/States'
import { InfoTip } from '@/components/common/InfoTip'
import { useIncident } from '@/features/notify/api'
import { Button } from '@/components/ui/button'
import { useCan } from '@/lib/session'
import { errText, useIncidentPanel, useRequestFromIncident } from './api'
import { RiskChip } from './parts'
import type { IncidentOption } from './types'

const link = 'text-accent underline underline-offset-4'

/** Respond on an incident (S-RESP-3): the incident's source and only what can really be asked for it. Asking creates a
 * request that waits for approval like any other; nothing here changes a device. */
export function IncidentRespond({ id }: { id: string }) {
  const { t } = useTranslation('response')
  const q = useIncidentPanel(id)
  const admin = useCan('admin') // Settings, Connections and the Actions tab are the administrator's (#875 r1)
  const [sent, setSent] = useState<string | null>(null)
  if (q.isPending) return <Loading />
  if (q.error) return <div className="mb-6"><ErrorState error={q.error} onRetry={() => void q.refetch()} /></div>
  const { incident, source, options, note } = q.data
  const ready = options.some((o) => o.ready || o.requested)
  return (
    <Card id="incident-respond" title={t('incident.heading')} className="mb-5">
      <div className="grid gap-3">
        <p className="text-sm"><Link className={link} to={`/incidents/${encodeURIComponent(incident.id)}`}>{incident.title}</Link></p>
      {!source ? (
        <p className="text-sm text-muted">{t('incident.noSource')} <Link className={link} to="/response?tab=rules">{t('incident.toRules')}</Link></p>
      ) : (
        <>
          <p className="flex flex-wrap items-center gap-2 text-sm">
            <span>{t('incident.source')}: <span className="font-medium">{source.ip}</span>{source.device ? <> ({source.asset_id ? <Link className={link} to={`/devices/${encodeURIComponent(source.asset_id)}`}>{source.device}</Link> : source.device})</> : null}</span>
            <Chip tone={source.scope === 'lan' ? 'warn' : 'danger'}>{t(`incident.scope.${source.scope}`)}</Chip>
          </p>
          {note ? <Notice tone="off" role="note" className="mb-0" title={note} /> : null}
          {sent ? (
            <Notice tone="accent" role="status" className="mb-0" title={<>{t('incident.sent', { title: sent })} <Link className={link} to="/response?tab=requests">{t('incident.toRequests')}</Link></>} />
          ) : null}
          {options.length ? <ul className="grid gap-2">{options.map((o) => <OptionRow key={o.action_id} id={incident.id} o={o} onSent={setSent} />)}</ul> : null}
          {source.scope === 'lan' && !ready && !note ? (
            <Notice tone="off" className="mb-0" title={t('incident.lanNothing')}>
              <ol className="ml-5 grid list-decimal gap-1 text-ink">
                <li>{t('incident.doNow')} {incident.action}</li>
                {admin ? <li>{t('incident.letVedette')} <Link className={link} to="/settings/connections#connections-add">{t('incident.toConnections')}</Link>{t('incident.thenCatalog')} <Link className={link} to="/response?tab=actions#catalog">{t('incident.toCatalog')}</Link>{t('incident.thenRule')} <Link className={link} to="/response?tab=rules">{t('incident.toRules')}</Link></li> : <li>{t('incident.askAdmin')}</li>}
              </ol>
            </Notice>
          ) : null}
          {source.scope === 'lan' ? <p className="text-meta text-muted">{t('incident.noBlocklist', { ip: source.ip })}</p> : null}
        </>
      )}
      </div>
    </Card>
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
          <p className="flex flex-wrap items-center gap-2 text-meta text-muted">
            <span>{o.device ? (o.connection ? t('incident.on', { connection: o.connection }) : t('incident.noConnection')) : t('action.viaBox')}</span>
            <RiskChip risk={o.risk} />
            <span>{t('incident.undo', { hours: Math.round(o.ttl_min / 60) })}</span>
          </p>
        </div>
        {o.requested ? <Link className={`text-meta ${link}`} to="/response?tab=requests">{t('incident.requested')}</Link>
          : <Button size="sm" disabled={!can || !o.ready} busy={ask.isPending} busyLabel={t('common:busy.sending')} title={!can ? t('common:needRole', { role: t('common:role.operator') }) : undefined}
              onClick={() => ask.mutate({ id, action_id: o.action_id }, { onSuccess: (a) => { onSent(a.title); toast.success(t('incident.sentToast')) }, onError: (e) => toast.error(errText(e)) })}>{t('incident.ask')}</Button>}
      </div>
      {o.why && !o.requested ? <p className="text-meta text-muted">{o.why}</p> : null}
    </li>
  )
}

/** Respond on an incident while the response module is off (the default, S-RESP-3): nothing can be asked for, but what to
 * do by hand still stands, read from the incident itself (notify), and the way to let Vedette help next time. */
export function IncidentRespondOff({ id }: { id: string }) {
  const { t } = useTranslation('response')
  const q = useIncident(id)
  return (
    <>
      <PageHeader title={t('common:shell.response')} stories={['S-RESP-3']} />
      <Card id="incident-respond" title={t('incident.heading')} className="mb-5">
        <div className="grid gap-3">
        {q.isPending ? <Loading /> : q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} /> : (
          <>
            <p className="text-sm"><Link className={link} to={`/incidents/${encodeURIComponent(q.data.incident.id)}`}>{q.data.incident.title}</Link></p>
            <Notice tone="off" className="mb-0" title={t('incident.offNothing')}>
              <ol className="ml-5 grid list-decimal gap-1 text-ink">
                <li>{t('incident.doNow')} {q.data.incident.action}</li>
                <li><span className="inline-flex items-center gap-1">{t('incident.offNext')}<InfoTip topic={t('incident.offNextTopic')}>{t('incident.offNextInfo')}</InfoTip></span></li>
              </ol>
            </Notice>
          </>
        )}
        </div>
      </Card>
      <ModuleOff module="response" />
    </>
  )
}
