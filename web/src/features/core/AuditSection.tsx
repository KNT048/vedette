import { useDeferredValue, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Download } from 'lucide-react'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Field, Input, Select } from '@/components/ui/input'
import { download } from '@/lib/api'
import { fmtDateTime } from '@/lib/format'
import { auditExportPath, useAudit } from './api'
import { errMsg } from './parts'
import type { AuditQuery, AuditRow } from './types'

/** The Who option "Not the system": sends actor=people (D-416). No user value can be it: user values never hold a NUL. */
const PEOPLE = '\u0000people'
/** Device (a-…) and finding (f-…) ids in a target or detail (D-416). */
const ID_RE = /\b[af]-[a-z0-9]+\b/g

/** A target or detail with the ids the box could name replaced by their names; the text as stored stays below it, smaller (D-416). */
function Named({ text, names }: { text: string; names: Record<string, string> }) {
  const shown = text.replace(ID_RE, (id) => names[id] ?? id)
  if (shown === text) return <>{text}</>
  return <div className="grid"><span>{shown}</span><span className="break-all font-mono text-[11.5px] text-muted">{text}</span></div>
}

export default function AuditSection() {
  const { t } = useTranslation('core')
  const [f, setF] = useState<AuditQuery>({ q: '', user: '', group: '', from: '', to: '', actor: '' })
  const deferred = useDeferredValue(f)
  const q = useAudit(deferred)
  const set = (patch: Partial<AuditQuery>) => setF({ ...f, ...patch })
  const filtered = Object.values(f).some(Boolean)

  async function exportCsv() {
    try { await download(auditExportPath(f), 'vedette-audit.csv') } catch (e) { toast.error(errMsg(e, t)) }
  }

  const names = q.data?.names ?? {}
  const named = (s: string) => s.replace(ID_RE, (id) => names[id] ?? id)
  const columns: ColumnDef<AuditRow>[] = [
    { id: 'ts', header: t('audit.col.time'), accessorFn: (r) => r.ts, cell: ({ row }) => <span className="whitespace-nowrap">{fmtDateTime(row.original.ts)}</span> },
    { id: 'user', header: t('audit.col.user'), accessorFn: (r) => r.user },
    { id: 'action', header: t('audit.col.action'), accessorFn: (r) => r.action, cell: ({ row }) => (
      <div className="grid"><span>{t(`audit.action.${row.original.action}`, { defaultValue: row.original.action })}</span><span className="font-mono text-[11.5px] text-muted">{row.original.action}</span></div>
    ) },
    { id: 'target', header: t('audit.col.target'), accessorFn: (r) => named(r.target), cell: ({ row }) => <Named text={row.original.target} names={names} /> },
    { id: 'detail', header: t('audit.col.detail'), accessorFn: (r) => named(r.detail ?? ''), cell: ({ row }) => (row.original.detail ? <Named text={row.original.detail} names={names} /> : <span className="text-muted">–</span>) },
  ]

  return (
    <>
      <PageHeader title={q.data ? t('audit.title', { count: q.data.total }) : t('settings.audit')} meta={t('audit.meta')} stories={['S-CORE-3']} actions={<Button onClick={() => void exportCsv()}><Download />{t('audit.export')}</Button>} />
      <div className="mb-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Field label={t('audit.filter.text')} htmlFor="au-q"><Input id="au-q" value={f.q} onChange={(e) => set({ q: e.target.value })} /></Field>
        <Field label={t('audit.filter.user')} htmlFor="au-user">
          <Select id="au-user" value={f.actor === 'people' ? PEOPLE : f.user} onChange={(e) => set(e.target.value === PEOPLE ? { actor: 'people', user: '' } : { actor: '', user: e.target.value })}>
            <option value="">{t('audit.filter.any')}</option>
            <option value={PEOPLE}>{t('audit.filter.people')}</option>
            {q.data?.users.length ? <optgroup label={t('audit.filter.users')}>{q.data.users.map((u) => <option key={u} value={u}>{u}</option>)}</optgroup> : null}
          </Select>
        </Field>
        <Field label={t('audit.filter.group')} htmlFor="au-group">
          <Select id="au-group" value={f.group} onChange={(e) => set({ group: e.target.value })}><option value="">{t('audit.filter.any')}</option>{q.data?.groups.map((g) => <option key={g} value={g}>{t(`audit.group.${g}`, { defaultValue: g })}</option>)}</Select>
        </Field>
        <Field label={t('audit.filter.from')} htmlFor="au-from"><Input id="au-from" type="date" value={f.from} onChange={(e) => set({ from: e.target.value })} /></Field>
        <Field label={t('audit.filter.to')} htmlFor="au-to"><Input id="au-to" type="date" value={f.to} onChange={(e) => set({ to: e.target.value })} /></Field>
      </div>
      <QueryState query={q}>
        {(d) => (
          <>
            {d.total > d.items.length ? <p className="mb-2 text-[13px] text-muted">{t('audit.truncated', { shown: d.items.length, total: d.total })}</p> : null}
            <DataTable data={d.items} columns={columns} caption={t('audit.caption')} pageSize={25}
              mobileRow={(r) => (
                <div className="grid gap-0.5 text-[13px]">
                  <span className="font-medium">{t(`audit.action.${r.action}`, { defaultValue: r.action })}</span>
                  <span className="break-words">{named(r.target)}{r.detail ? `: ${named(r.detail)}` : ''}</span>
                  <span className="text-[12px] text-muted">{fmtDateTime(r.ts)}, {r.user}</span>
                </div>
              )}
              empty={<EmptyState title={filtered ? t('audit.emptyFiltered') : t('audit.empty')} />} />
          </>
        )}
      </QueryState>
    </>
  )
}
