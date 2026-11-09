import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { PageHeader, Section, KeyValue } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Chip } from '@/components/common/StatusChip'
import { QueryState } from '@/components/common/States'
import { Switch } from '@/components/ui/switch'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { usePrivacy, useSavePrivacy } from './api'
import { errMsg, ReadOnlyNote, useGate } from './parts'
import type { PrivacyFlow, PrivacyState } from './types'

// Mười luồng dữ liệu rời hộp, đúng như PRIVACY.md. Thêm luồng mới = sửa PRIVACY.md + bảng này cùng commit (rule legal.md).
function Body({ d }: { d: PrivacyState }) {
  const { t } = useTranslation('core')
  const gate = useGate('admin')
  const save = useSavePrivacy()
  async function set(v: { telemetry?: boolean; update_check?: boolean }) {
    try { await save.mutateAsync(v); toast.success(t('common:saved')) } catch (e) { toast.error(errMsg(e, t)) }
  }
  const stateChip = (f: PrivacyFlow) => (f.state === 'on' ? <Chip tone="ok">{t('privacy.state.on')}</Chip> : f.state === 'off' ? <Chip tone="off">{t('privacy.state.off')}</Chip> : <Chip tone="off">{t('privacy.state.conditional')}</Chip>)
  const columns: ColumnDef<PrivacyFlow>[] = [
    { id: 'flow', header: t('privacy.col.flow'), accessorFn: (f) => f.id, cell: ({ row }) => <span className="font-medium">{row.original.id}. {t(`privacy.flow.${row.original.id}.name`)}</span> },
    { id: 'what', header: t('privacy.col.what'), enableSorting: false, accessorFn: (f) => f.id, cell: ({ row }) => <span className="block max-w-sm text-[13px]">{t(`privacy.flow.${row.original.id}.what`)}</span> },
    { id: 'to', header: t('privacy.col.to'), enableSorting: false, accessorFn: (f) => f.id, cell: ({ row }) => <span className="block max-w-[200px] text-[13px]">{t(`privacy.flow.${row.original.id}.to`)}</span> },
    { id: 'state', header: t('privacy.col.state'), accessorFn: (f) => f.state, cell: ({ row }) => stateChip(row.original) },
    { id: 'control', header: t('privacy.col.control'), enableSorting: false, accessorFn: (f) => f.id, cell: ({ row }) => {
      const f = row.original
      if (f.id === 2) return <a className="text-[13px] text-accent underline-offset-4 hover:underline" href="#telemetry">{t('privacy.flow.2.control')}</a>
      if (f.id === 6) return (
        <div className="flex items-center gap-2">
          <Switch checked={d.update_check} disabled={gate.disabled || save.isPending} title={gate.title} aria-label={t('privacy.flow.6.switch')} onCheckedChange={(v) => void set({ update_check: v })} />
          <span className="max-w-[220px] text-[13px] text-muted">{t('privacy.flow.6.control')}</span>
        </div>
      )
      return (
        <span className="block max-w-[240px] text-[13px] text-muted">
          {t(`privacy.flow.${f.id}.control`)}{' '}
          {f.id === 3 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/ai">{t('privacy.flow.3.link')}</Link> : null}
          {f.id === 5 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/channels">{t('privacy.flow.5.link')}</Link> : null}
          {f.id === 7 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/siem">{t('privacy.flow.7.link')}</Link> : null}
          {f.id === 8 || f.id === 9 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/modules">{t(`privacy.flow.${f.id}.link`)}</Link> : null}
          {f.id === 10 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/network">{t('privacy.flow.10.link')}</Link> : null}
          {f.id === 1 ? <Link className="text-accent underline-offset-4 hover:underline" to="/settings/feeds">{t('privacy.flow.1.link')}</Link> : null}
        </span>
      )
    } },
  ]
  const tel = d.telemetry
  return (
    <>
      <ReadOnlyNote role="admin" />
      <Section title={t('privacy.flows')} description={t('privacy.flowsDesc')}>
        <DataTable data={d.flows} columns={columns} caption={t('privacy.flows')} pageSize={10} />
      </Section>

      <Section title={t('privacy.bugNote.title')}>
        <p className="max-w-3xl text-sm">{t('privacy.bugNote.body')}</p>
      </Section>

      <Section id="telemetry" title={t('privacy.telemetry.title')} description={t('privacy.telemetry.desc')} stories={['S-CORE-4']}>
        <div className="mb-4 flex flex-wrap items-center gap-3 rounded-md border border-rule bg-surface px-4 py-3">
          <Switch id="telemetry-switch" checked={tel.enabled} disabled={gate.disabled || save.isPending} title={gate.title} aria-label={t('privacy.telemetry.switch')} onCheckedChange={(v) => void set({ telemetry: v })} />
          <label htmlFor="telemetry-switch" className="text-sm font-medium">{t('privacy.telemetry.switch')}</label>
          <span className="text-[13px] text-muted">{tel.enabled ? t('privacy.telemetry.on') : t('privacy.telemetry.off')}</span>
        </div>
        <KeyValue items={[
          { label: t('privacy.telemetry.lastSent'), value: tel.last_sent ? `${fmtRelative(tel.last_sent)} (${fmtDateTime(tel.last_sent)})` : t('privacy.telemetry.never') },
          { label: t('privacy.telemetry.where'), value: t('privacy.telemetry.whereValue') },
          { label: t('privacy.telemetry.keep'), value: t('privacy.telemetry.keepValue') },
        ]} />
        <div className="mt-4 grid gap-2">
          <p className="text-sm font-medium">{tel.enabled ? t('privacy.telemetry.payloadOn') : t('privacy.telemetry.payloadOff')}</p>
          <CodeBlock label={t('privacy.telemetry.payloadLabel')} code={JSON.stringify(tel.payload, null, 2)} />
          <p className="text-[13px] text-muted">{t('privacy.telemetry.notSent')}</p>
        </div>
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
      <PageHeader title={q.data ? (q.data.telemetry.enabled ? t('privacy.titleOn') : t('privacy.titleOff')) : t('settings.privacy')} meta={t('privacy.meta')} stories={['S-CORE-4']} />
      <QueryState query={q}>{(d) => <Body d={d} />}</QueryState>
    </>
  )
}
