import { Link, useParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ArrowLeft } from 'lucide-react'
import { PageHeader, Section, KeyValue, Panel } from '@/components/common/PageHeader'
import { QueryState, RequireModule } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { CodeBlock } from '@/components/common/CodeBlock'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { fmtDateTime } from '@/lib/format'
import { useHit } from './api'
import { hitName } from './hitName'
import { RespondLink } from './hitParts'
import type { HitEvent } from './types'

export default function HitPage() {
  const { t, i18n } = useTranslation('honeypot')
  const { id = '' } = useParams()
  const hit = useHit(id)
  return (
    <RequireModule module="honeypot">
      <Link to="/honeypot" className="mb-3 inline-flex items-center gap-1 text-[13px] text-muted hover:text-ink"><ArrowLeft className="size-3.5" />{t('hit.back')}</Link>
      <QueryState query={hit}>
        {(h) => {
          const service = hitName(t, h)
          const src = h.src_name ?? h.src_ip
          const columns: ColumnDef<HitEvent>[] = [
            { id: 'ts', header: t('hit.col.time'), accessorFn: (r) => r.ts, cell: ({ row }) => <span className="whitespace-nowrap tabular-nums">{new Intl.DateTimeFormat(i18n.language === 'en' ? 'en-GB' : 'vi-VN', { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date(row.original.ts))}</span> },
            { id: 'source', header: t('hit.col.source'), accessorFn: (r) => t(`eventSource.${r.source}`) },
            { id: 'text', header: t('hit.col.text'), enableSorting: false, cell: ({ row }) => <span>{row.original.text}{row.original.mark ? <span className="ml-2"><Chip tone="warn">{t('hit.markTrap')}</Chip></span> : null}</span> },
          ]
          return (
            <>
              <PageHeader stories={['S-HP-1', 'S-HP-2']}
                title={h.is_test ? t('hit.titleTest', { service, time: fmtDateTime(h.ts) }) : t(`hit.title_${h.kind}`, { service, time: fmtDateTime(h.ts), src })}
                meta={h.is_test ? <Chip tone="off">{t('hits.test')}</Chip> : t(`hit.meta_${h.kind}`, { ip: h.trap_ip })}
                actions={h.is_test ? undefined : <RespondLink h={h} />} />
              <Section id="facts" title={t('hit.facts')}>
                <Panel className="p-4">
                  <KeyValue items={[
                    { label: t('hit.service'), value: h.port ? `${service}, ${t('hit.port', { port: h.port })}` : service },
                    { label: t('hit.trap'), value: h.kind === 'service' ? `${h.trap_hostname} (${h.trap_ip})` : `${h.trap_hostname}: ${h.trap_ip}` },
                    { label: t('hit.srcIp'), value: h.src_ip },
                    { label: t('hit.srcDevice'), value: h.asset && h.src_name
                      ? <span className="flex flex-wrap items-center gap-2"><Link className="text-accent underline-offset-4 hover:underline" to={`/devices/${h.asset.id}`}>{h.src_name}</Link><span className="text-[13px] text-muted">{t(`kind.${h.asset.kind}`, { defaultValue: h.asset.kind })}</span>{h.asset.approved ? null : <Chip tone="warn">{t('hit.unapproved')}</Chip>}</span>
                      : <span className="text-muted">{h.is_test ? t('hits.deviceBox') : t('hit.noDevice')}</span> },
                  ]} />
                </Panel>
              </Section>
              <Section id="session" title={t('hit.session')} description={t('hit.sessionHint')}>
                <CodeBlock code={h.excerpt} label={t('hit.sessionLabel')} />
              </Section>
              <Section id="events" title={t('hit.events', { minutes: h.window_minutes })} description={t('hit.eventsHint')}>
                <DataTable caption={t('hit.eventsCaption')} data={h.events} columns={columns} pageSize={20} rowTone={(r) => (r.mark ? 'warn' : undefined)} initialSort={[{ id: 'ts', desc: false }]} />
              </Section>
              {h.is_test ? null : (
                <Section id="next" title={t('hit.next')}>
                  <ol className="grid max-w-3xl list-decimal gap-2 pl-5 text-sm">
                    <li>{t('hit.next1', { src })}</li>
                    <li>{t('hit.next2')}</li>
                    <li>{t('hit.next3')}</li>
                  </ol>
                </Section>
              )}
            </>
          )
        }}
      </QueryState>
    </RequireModule>
  )
}
