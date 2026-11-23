import { Link, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { PageHeader, Section, KeyValue } from '@/components/common/PageHeader'
import { Breadcrumbs, type Crumb } from '@/components/common/Breadcrumbs'
import { Card } from '@/components/common/Card'
import { ErrorState, Loading, RequireModule } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { CodeBlock } from '@/components/common/CodeBlock'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { fmtDateTime, fmtTime } from '@/lib/format'
import { useHit } from './api'
import { hitName } from './hitName'
import { RespondLink } from './hitParts'
import { notOffered } from '@/lib/v1'
import type { HitDetail, HitEvent } from './types'
import { kindLabel } from '@/lib/deviceTypes'
import { NotAddedChip } from '@/features/findings/NotAdded'

export default function HitPage() {
  const { t } = useTranslation('honeypot')
  const { id = '' } = useParams()
  const hit = useHit(id)
  const respond = !notOffered('response') // Respond starts a new action: none while this build does not offer the response module, even on a box that has it on
  // UI.md §3: the parent above the title, also while the hit loads or fails, so the way back is always there.
  const crumbs = [{ label: t('common:shell.honeypot'), to: '/honeypot' }]
  return (
    <RequireModule module="honeypot" page>
      {hit.error ? <><Breadcrumbs items={crumbs} /><ErrorState error={hit.error} onRetry={() => void hit.refetch()} /></>
        : hit.isPending ? <><Breadcrumbs items={crumbs} /><Loading /></>
        : <HitBody h={hit.data} crumbs={crumbs} respond={respond} />}
    </RequireModule>
  )
}

function HitBody({ h, crumbs, respond }: { h: HitDetail; crumbs: Crumb[]; respond: boolean }) {
  const { t } = useTranslation('honeypot')
  const service = hitName(t, h)
  const src = h.src_name ?? h.src_ip
  const columns: ColumnDef<HitEvent>[] = [
    { id: 'ts', header: t('hit.col.time'), accessorFn: (r) => r.ts, cell: ({ row }) => <span className="whitespace-nowrap tabular-nums">{fmtTime(row.original.ts, true)}</span> },
    { id: 'source', header: t('hit.col.source'), accessorFn: (r) => t(`eventSource.${r.source}`) },
    { id: 'text', header: t('hit.col.text'), enableSorting: false, cell: ({ row }) => <span>{row.original.text}{row.original.mark ? <span className="ml-2"><Chip tone="warn">{t('hit.markTrap')}</Chip></span> : null}</span> },
  ]
  return (
    <>
      <PageHeader breadcrumbs={crumbs} stories={['S-HP-1', 'S-HP-2']}
        title={h.is_test ? t('hit.titleTest', { service, time: fmtDateTime(h.ts) }) : t(`hit.title_${h.kind}`, { service, time: fmtDateTime(h.ts), src })}
        meta={h.is_test ? <Chip tone="off">{t('hits.test')}</Chip> : t(`hit.meta_${h.kind}`, { ip: h.trap_ip })} />
      <Section id="facts" title={t('hit.facts')}>
        <Card>
          <KeyValue items={[
            { label: t('hit.service'), value: h.port ? `${service}, ${t('hit.port', { port: h.port })}` : service },
            { label: t('hit.trap'), value: h.kind === 'service' ? `${h.trap_hostname} (${h.trap_ip})` : `${h.trap_hostname}: ${h.trap_ip}` },
            { label: t('hit.srcIp'), value: h.src_ip },
            { label: t('hit.srcDevice'), value: h.asset && h.src_name
              ? <span className="flex flex-wrap items-center gap-2"><Link className="text-accent underline-offset-4 hover:underline" to={`/devices/${h.asset.id}`}>{h.src_name}</Link><span className="text-meta text-muted">{kindLabel(h.asset.kind)}</span><NotAddedChip asset={h.asset} /></span>
              : <span className="text-muted">{h.is_test ? t('hits.deviceBox') : t('hit.noDevice')}</span> },
          ]} />
        </Card>
      </Section>
      <Section id="session" title={t('hit.session')} description={t('hit.sessionHint')}>
        <CodeBlock code={h.excerpt} label={t('hit.sessionLabel')} />
      </Section>
      <Section id="events" title={t('hit.events', { minutes: h.window_minutes })} description={t('hit.eventsHint')} info={t('hit.eventsHintInfo')}>
        <DataTable urlKey="honeypot-hit-events" caption={t('hit.eventsCaption')} data={h.events} columns={columns} pageSize={20} rowTone={(r) => (r.mark ? 'warn' : undefined)} initialSort={[{ id: 'ts', desc: false }]} />
      </Section>
      {h.is_test ? null : (
        // Respond is the next step done in the response module: it sits with the steps, not in the header
        <Section id="next" title={t('hit.next')} actions={respond ? <RespondLink h={h} /> : undefined}>
          <ol className="grid max-w-3xl list-decimal gap-2 pl-5 text-sm">
            <li>{t('hit.next1', { src })}</li>
            <li>{t('hit.next2')}</li>
            <li>{t('hit.next3')}</li>
          </ol>
        </Section>
      )}
    </>
  )
}
