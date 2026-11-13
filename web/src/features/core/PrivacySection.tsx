import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Chip } from '@/components/common/StatusChip'
import { QueryState } from '@/components/common/States'
import { Switch } from '@/components/ui/switch'
import { useFeedSources, hostOf } from '@/features/feeds/api'
import { useInstallKind, useModuleEnabled } from '@/lib/modules'
import { usePrivacy, useSavePrivacy } from './api'
import { errMsg, ReadOnlyNote, useGate } from './parts'
import type { PrivacyFlow, PrivacyState } from './types'

// Flow 1 names the hosts of the custom feeds on the box, read from the same list as Settings → Feeds → "Where this box connects". Only mounted when the feeds module is on.
function CustomFeedHosts() {
  const { t } = useTranslation('core')
  const { data } = useFeedSources()
  if (!data) return null
  const hosts = [...new Set(data.items.filter((f) => !f.builtin && f.enabled).map((f) => hostOf(f.url)))]
  return <span className="mt-1 block">{hosts.length ? t('privacy.flow.1.custom', { hosts: hosts.join(', ') }) : t('privacy.flow.1.customNone')}</span>
}

// Mười hai luồng dữ liệu rời hộp, đúng như PRIVACY.md. Thêm luồng mới = sửa PRIVACY.md + bảng này cùng commit (rule legal.md).
function Body({ d }: { d: PrivacyState }) {
  const { t } = useTranslation('core')
  const gate = useGate('admin')
  const feedsOn = useModuleEnabled('feeds')
  // S-CORE-4 (walk 4): a container-only install has no vedette-host, apt, scan image build or chrony; flows 6 and 10 then
  // read as the container-only rows of PRIVACY.md (D-381). undefined while GET /modules loads: the appliance text.
  const container = useInstallKind() === 'container'
  const txt = (id: number, part: 'what' | 'to' | 'control') => t(container && (id === 6 || id === 10) ? `privacy.flow.${id}.container.${part}` : `privacy.flow.${id}.${part}`)
  // A flow with an "items" list (flow 3, one item per AI job, D-407) shows its lead sentence and then the list, as PRIVACY.md does.
  const whatCell = (f: PrivacyFlow) => {
    const items = t(`privacy.flow.${f.id}.items`, { returnObjects: true, defaultValue: null }) as unknown
    return <>{txt(f.id, 'what')}{Array.isArray(items) ? <ul className="mt-1 grid list-disc gap-1 pl-4">{items.map((i: string) => <li key={i}>{i}</li>)}</ul> : null}</>
  }
  const toCell = (f: PrivacyFlow) => <>{txt(f.id, 'to')}{f.id === 1 && feedsOn ? <CustomFeedHosts /> : null}</>
  const save = useSavePrivacy()
  async function set(v: { update_check?: boolean }) {
    try { await save.mutateAsync(v); toast.success(t('common:saved')) } catch (e) { toast.error(errMsg(e, t)) }
  }  // Flow 2 is never sent (D-82, D-153): ignore the state the API reports for it.
  const stateChip = (f: PrivacyFlow) => (f.id === 2 ? <Chip tone="off">{t('privacy.state.notSent')}</Chip> : f.state === 'on' ? <Chip tone="ok">{t('privacy.state.on')}</Chip> : f.state === 'off' ? <Chip tone="off">{t('privacy.state.off')}</Chip> : <Chip tone="off">{t('privacy.state.conditional')}</Chip>)
  const control = (f: PrivacyFlow) => {
      if (f.id === 6) return (
        <div className="flex items-center gap-2">
          <Switch checked={d.update_check} disabled={gate.disabled || save.isPending} title={gate.title} aria-label={t('privacy.flow.6.switch')} onCheckedChange={(v) => void set({ update_check: v })} />
          <span className="max-w-[220px] text-[13px] text-muted">{txt(6, 'control')}</span>
        </div>
      )
      return (
        <span className="block max-w-[240px] text-[13px] text-muted">
          {txt(f.id, 'control')}{' '}
          {f.id === 3 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/ai">{t('privacy.flow.3.link')}</Link> : null}
          {f.id === 5 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/channels">{t('privacy.flow.5.link')}</Link> : null}
          {f.id === 7 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/siem">{t('privacy.flow.7.link')}</Link> : null}
          {f.id === 8 || f.id === 9 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/modules">{t(`privacy.flow.${f.id}.link`)}</Link> : null}
          {f.id === 12 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/connections">{t('privacy.flow.12.link')}</Link> : null}
          {f.id === 13 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/mcp">{t('privacy.flow.13.link')}</Link> : null}
          {f.id === 11 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/modules">{t('privacy.flow.11.link')}</Link> : null}
          {f.id === 10 && !container ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/network">{t('privacy.flow.10.link')}</Link> : null}
          {f.id === 1 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/feeds">{t('privacy.flow.1.link')}</Link> : null}
        </span>
      )
  }
  const columns: ColumnDef<PrivacyFlow>[] = [
    { id: 'flow', header: t('privacy.col.flow'), accessorFn: (f) => f.id, cell: ({ row }) => <span className="font-medium">{row.original.id}. {t(`privacy.flow.${row.original.id}.name`)}</span> },
    { id: 'what', header: t('privacy.col.what'), enableSorting: false, accessorFn: (f) => f.id, cell: ({ row }) => <div className="max-w-sm text-[13px]">{whatCell(row.original)}</div> },
    { id: 'to', header: t('privacy.col.to'), enableSorting: false, accessorFn: (f) => f.id, cell: ({ row }) => <span className="block max-w-[200px] text-[13px]">{toCell(row.original)}</span> },
    { id: 'state', header: t('privacy.col.state'), accessorFn: (f) => f.state, cell: ({ row }) => stateChip(row.original) },
    { id: 'control', header: t('privacy.col.control'), enableSorting: false, accessorFn: (f) => f.id, cell: ({ row }) => control(row.original) },
  ]
  return (
    <>
      <ReadOnlyNote role="admin" />
      <Section title={t('privacy.flows')} description={t('privacy.flowsDesc')}>
        <DataTable data={d.flows} columns={columns} caption={t('privacy.flows')} pageSize={15} mobileRow={(f) => (
          <div className="grid gap-1.5">
            <div className="flex flex-wrap items-center justify-between gap-2"><span className="font-medium">{f.id}. {t(`privacy.flow.${f.id}.name`)}</span>{stateChip(f)}</div>
            <div className="text-[13px]">{whatCell(f)}</div>
            <p className="text-[13px] text-muted"><span className="font-medium text-ink">{t('privacy.col.to')}: </span>{toCell(f)}</p>
            <div className="text-[13px] text-muted"><span className="font-medium text-ink">{t('privacy.col.control')}: </span>{control(f)}</div>
          </div>
        )} />
      </Section>

      <Section title={t('privacy.bugNote.title')}>
        <p className="max-w-3xl text-sm">{t('privacy.bugNote.body')}</p>
      </Section>

      <Section id="telemetry" title={t('privacy.telemetry.title')} stories={['S-CORE-4']}>
        <p className="max-w-3xl text-sm">{t('privacy.telemetry.statement')}</p>
      </Section>

      <Section title={t('privacy.cookie.title')}>
        <p className="max-w-3xl text-sm">{t('privacy.cookie.body')}</p>
      </Section>
    </>
  )
}

export default function PrivacySection() {
  const { t } = useTranslation('core')
  const q = usePrivacy()
  return (
    <>
      <PageHeader title={t('privacy.title')} meta={t('privacy.meta')} stories={['S-CORE-4']} />
      <QueryState query={q}>{(d) => <Body d={d} />}</QueryState>
    </>
  )
}
