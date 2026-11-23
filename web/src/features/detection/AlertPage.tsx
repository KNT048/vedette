import { Link, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { PageHeader, Section, KeyValue } from '@/components/common/PageHeader'
import { Card } from '@/components/common/Card'
import { Breadcrumbs } from '@/components/common/Breadcrumbs'
import { ErrorState, Loading } from '@/components/common/States'
import { fmtDateTime, fmtNumber } from '@/lib/format'
import { useAlert } from './api'
import { AlertLine, DeviceLink, severityText } from './parts'
import type { Alert } from './types'

const link = 'text-accent underline-offset-4 hover:underline'

export default function AlertPage() {
  const { t } = useTranslation('detection')
  const { id = '' } = useParams()
  const alert = useAlert(id)
  const crumbs = [{ label: t('common:shell.detection'), to: '/detection' }]
  if (alert.error) return <><Breadcrumbs items={crumbs} /><ErrorState error={alert.error} onRetry={() => void alert.refetch()} /></>
  if (alert.isPending) return <><Breadcrumbs items={crumbs} /><Loading /></>
  return <Body a={alert.data} crumbs={crumbs} />
}

function Body({ a, crumbs }: { a: Alert; crumbs: { label: string; to: string }[] }) {
  const { t } = useTranslation('detection')
  const findingOf = (cve: string) => a.findings.filter((f) => f.cve === cve)
  return (
    <>
      <PageHeader breadcrumbs={crumbs} title={a.signature} meta={`${severityText(t, a.severity)}, ${t('alert.meta', { count: a.count, time: fmtDateTime(a.last_seen) })}`} stories={['S-IDS-1']} />
      <Section id="facts" title={t('alert.facts')}>
        <Card>
          <KeyValue items={[
            { label: t('alert.flow'), value: <AlertLine a={a} /> },
            { label: t('alert.attacked'), value: a.dst_device ? <DeviceLink device={a.dst_device} ip={a.dst_ip} /> : <span className="text-muted">{t('alert.notInInventory', { ip: a.dst_ip })}</span> },
            { label: t('alert.source'), value: a.src_device ? <DeviceLink device={a.src_device} ip={a.src_ip} /> : <span>{t('alert.outside', { ip: a.src_ip })}</span> },
            { label: t('alert.rule'), value: a.sid === null ? t('alert.noSid') : String(a.sid) },
            { label: t('alert.category'), value: a.category || <span className="text-muted">{t('alert.noCategory')}</span> },
            { label: t('alert.priority'), value: String(a.priority) },
            { label: t('alert.events'), value: fmtNumber(a.count) },
            { label: t('alert.first'), value: fmtDateTime(a.first_seen) },
            { label: t('alert.last'), value: fmtDateTime(a.last_seen) },
            { label: t('alert.seenBy'), value: t(`seenBy.${a.source}`, { defaultValue: t('seenBy.other') }) },
          ]} />
        </Card>
      </Section>
      <Section id="cves" title={t('alert.cves')}>
        {a.cves.length === 0 ? <p className="text-meta text-muted">{t('alert.noCve')}</p> : (
          <Card flush>
            <ul className="divide-y divide-rule">
              {a.cves.map((cve) => {
                const fs = findingOf(cve)
                return (
                  <li key={cve} className="grid gap-0.5 px-4 py-3">
                    <p className="font-medium">{cve}</p>
                    {fs.length ? fs.map((f) => (
                      <p key={f.id} className="text-meta"><Link to={`/findings/${f.id}`} className={link}>{t('alert.finding', { device: f.device.name })}</Link>{`, ${t(`findingStatus.${f.status}`)}`}</p>
                    )) : <p className="text-meta text-muted">{a.dst_device ? t('alert.notAffected', { device: a.dst_device.name }) : t('alert.noDevice')}</p>}
                  </li>
                )
              })}
            </ul>
          </Card>
        )}
      </Section>
      <Section id="handling" title={t('alert.handling')}>
        {a.incident
          ? <p className="text-meta">{t('alert.incidentIs', { status: t(`incidentStatus.${a.incident.status}`) })}{' '}<Link to={`/incidents/${a.incident.id}`} className={link}>{t('alert.openIncident')}</Link></p>
          : <p className="text-meta text-muted">{t('alert.noIncident')}</p>}
      </Section>
    </>
  )
}
