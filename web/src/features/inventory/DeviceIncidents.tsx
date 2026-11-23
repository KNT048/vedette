// The device page's open incidents: what Vedette raised about this device (a trap it touched, an intrusion attempt against it, a
// connection to a known-bad address, an unknown device), whether or not a finding matched. Read from the incidents list of the
// notify module (GET /notify/incidents, every open incident with the devices it names); nothing shows while the module is off or
// the device has none open.
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { Section } from '@/components/common/PageHeader'
import { SeverityBadge } from '@/components/common/status'
import { api } from '@/lib/api'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { IncidentStatusChip, kindKey } from '@/features/notify/shared'
import type { Incident, IncidentsResponse } from '@/features/notify/types'

const link = 'text-accent underline-offset-4 hover:underline'
const rank = (i: Incident) => ['info', 'low', 'medium', 'high', 'critical'].indexOf(i.severity)

/** The open incidents (new or acknowledged) that name device `id`, the most severe first, then the one seen last. */
export function openIncidentsOf(list: Incident[], id: string): Incident[] {
  return list.filter((i) => i.status !== 'resolved' && i.devices.some((d) => d.id === id))
    .sort((a, b) => rank(b) - rank(a) || Date.parse(b.last_seen) - Date.parse(a.last_seen))
}

export function DeviceIncidents({ id }: { id: string }) {
  const { t } = useTranslation(['inventory', 'notify'])
  const on = useModuleEnabled('notify') === true
  // the Incidents page's own read (same key): opening one page after the other reads once
  const q = useQuery({ queryKey: ['notify', 'incidents'], queryFn: () => api.get<IncidentsResponse>('/notify/incidents'), enabled: on, retry: false })
  const open = on && q.data ? openIncidentsOf(q.data.incidents, id) : []
  if (!open.length) return null
  return (
    <Section id="incidents" title={t('incidents.title', { count: open.length })} info={t('incidents.info')}
      actions={<Link to="/incidents" className={`text-meta ${link}`}>{t('incidents.all')}</Link>}>
      <ul className="grid gap-1.5" aria-label={t('incidents.title', { count: open.length })}>
        {open.map((i) => (
          <li key={i.id} className="flex min-w-0 flex-wrap items-center justify-between gap-x-4 gap-y-1 rounded-md border border-rule bg-surface px-3 py-2.5">
            <span className="grid min-w-0 gap-0.5">
              <Link to={`/incidents/${encodeURIComponent(i.id)}`} className={`font-medium [overflow-wrap:anywhere] ${link}`}>{i.title}</Link>
              <span className="text-caption text-muted">{t(`notify:${kindKey(i)}`)}</span>
            </span>
            <span className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={i.severity} />
              <IncidentStatusChip status={i.status} />
              <time className="text-caption text-muted" dateTime={i.last_seen} title={fmtDateTime(i.last_seen)}>{t('incidents.seen', { when: fmtRelative(i.last_seen) })}</time>
            </span>
          </li>
        ))}
      </ul>
    </Section>
  )
}
