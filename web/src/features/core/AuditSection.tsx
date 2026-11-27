import { useDeferredValue, useState } from 'react'
import { useTranslation } from 'react-i18next'
import type { TFunction } from 'i18next'
import { toast } from 'sonner'
import { Download } from 'lucide-react'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { useListParams } from '@/components/common/listParams'
import { QueryState } from '@/components/common/States'
import { DownloadButton } from '@/components/common/DownloadButton'
import { Button } from '@/components/ui/button'
import { Input, Select } from '@/components/ui/input'
import { fmtDateTime } from '@/lib/format'
import { auditExportPath, useAudit } from './api'
import { errMsg } from './parts'
import type { AuditQuery, AuditRow } from './types'
import { ListSummary, ListToolbar } from '@/components/common/ListParts'

/** Rows of a page of the audit log by default. */
const AUDIT_PAGE = 50

/** The Who option "Not the system": sends actor=people. No user value can be it: user values never hold a NUL. */
const PEOPLE = '\u0000people'
/** An action in words: its label, else (an action written before its label existed) its kind's name and what was done, in words —
 *  never the stored code, which stays in the CSV export and in the cell's tooltip. */
export function actionLabel(t: TFunction<'core'>, action: string): string {
  const dot = action.indexOf('.')
  const group = dot > 0 ? action.slice(0, dot) : action
  const what = (dot > 0 ? action.slice(dot + 1) : '').replace(/[._-]+/g, ' ').trim()
  const fallback = t('audit.actionFallback', { group: t(`audit.group.${group}`, { defaultValue: group }), what })
  return t(`audit.action.${action}`, { defaultValue: fallback })
}

/** An action code as the box stores it (core.general, findings.question_answered). */
const ACTION_CODE = /^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)+$/
/** The box searches the stored codes; the screen shows labels. The codes whose label holds the search text go with it, so a search
 *  for "synced" finds the lines shown as "Software list synced". At most 400 (the box's limit; there are about 330 labels). */
export function actionsLabelled(labels: unknown, q: string): string {
  const needle = q.trim().toLowerCase()
  if (needle.length < 2 || !labels || typeof labels !== 'object') return ''
  const out: string[] = []
  const walk = (o: Record<string, unknown>, path: string) => {
    for (const [k, v] of Object.entries(o)) {
      const code = path ? `${path}.${k}` : k
      if (v && typeof v === 'object') walk(v as Record<string, unknown>, code)
      else if (typeof v === 'string' && v.toLowerCase().includes(needle) && ACTION_CODE.test(code)) out.push(code)
    }
  }
  walk(labels as Record<string, unknown>, '')
  return out.slice(0, 400).join(',')
}

/** Device (a-…) and finding (f-…) ids in a target or detail. */
const ID_RE = /\b[af]-[a-z0-9]{1,64}\b/g // the same as auditIDRE in modules/core/handlers_audit.go

/** A target or detail with the ids the box could name replaced by their names; the text as stored stays below it, smaller. */
function Named({ text, names }: { text: string; names: Record<string, string> }) {
  const shown = text.replace(ID_RE, (id) => names[id] ?? id)
  if (shown === text) return <>{text}</>
  return <div className="grid"><span>{shown}</span><span className="break-all font-mono text-caption text-muted">{text}</span></div>
}

export default function AuditSection() {
  const { t, i18n } = useTranslation('core')
  // The box pages the log (offset, limit) and searches it (q): the text and the page are in the URL (audit.q, audit.page, audit.size)
  const list = useListParams('audit')
  const [other, setOther] = useState<Omit<AuditQuery, 'q'>>({ user: '', group: '', from: '', to: '', actor: '' })
  const actions = actionsLabelled((i18n.getResourceBundle(i18n.resolvedLanguage ?? 'en', 'core') as { audit?: { action?: unknown } } | undefined)?.audit?.action, list.q)
  const f: AuditQuery = { ...other, q: list.q, actions }
  const deferred = useDeferredValue(other)
  const size = list.size ?? AUDIT_PAGE
  const q = useAudit({ ...deferred, q: list.q, actions }, { offset: list.page * size, limit: size })
  const set = (patch: Partial<Omit<AuditQuery, 'q'>>) => { setOther({ ...other, ...patch }); if (list.page) list.set({ page: 0 }) }
  const filtered = Object.entries(f).some(([k, v]) => k !== 'actions' && !!v)
  const clear = () => { setOther({ user: '', group: '', from: '', to: '', actor: '' }); list.set({ q: '', page: 0 }) }


  const names = q.data?.names ?? {}
  const named = (s: string) => s.replace(ID_RE, (id) => names[id] ?? id)
  const columns: ColumnDef<AuditRow>[] = [
    { id: 'ts', header: t('audit.col.time'), accessorFn: (r) => r.ts, cell: ({ row }) => <span className="whitespace-nowrap">{fmtDateTime(row.original.ts)}</span> },
    { id: 'user', header: t('audit.col.user'), accessorFn: (r) => r.user },
    { id: 'action', header: t('audit.col.action'), accessorFn: (r) => actionLabel(t, r.action), cell: ({ row }) => (
      <span title={row.original.action}>{actionLabel(t, row.original.action)}</span>
    ) },
    { id: 'target', header: t('audit.col.target'), accessorFn: (r) => named(r.target), cell: ({ row }) => <Named text={row.original.target} names={names} /> },
    { id: 'detail', header: t('audit.col.detail'), accessorFn: (r) => named(r.detail ?? ''), cell: ({ row }) => (row.original.detail ? <Named text={row.original.detail} names={names} /> : <span className="text-muted">–</span>) },
  ]

  return (
    <>
      <PageHeader title={t('settings.audit')} meta={t('audit.meta')} info={t('audit.metaInfo')} stories={['S-CORE-3']} />
      <ListToolbar className="mb-3" label={t('audit.filter.label')} search={{ value: list.q, onChange: (v) => list.set({ q: v, page: 0 }), label: t('audit.filter.text') }}>
        <Select className="w-full sm:w-auto" aria-label={t('audit.filter.user')} value={f.actor === 'people' ? PEOPLE : f.user} onChange={(e) => set(e.target.value === PEOPLE ? { actor: 'people', user: '' } : { actor: '', user: e.target.value })}>
          <option value="">{t('audit.filter.anyUser')}</option>
          <option value={PEOPLE}>{t('audit.filter.people')}</option>
          {q.data?.users.length ? <optgroup label={t('audit.filter.users')}>{q.data.users.map((u) => <option key={u} value={u}>{u}</option>)}</optgroup> : null}
        </Select>
        <Select className="w-full sm:w-auto" aria-label={t('audit.filter.group')} value={f.group} onChange={(e) => set({ group: e.target.value })}><option value="">{t('audit.filter.anyGroup')}</option>{q.data?.groups.map((g) => <option key={g} value={g}>{t(`audit.group.${g}`, { defaultValue: g })}</option>)}</Select>
        <label className="flex items-center gap-1.5 text-meta text-muted">{t('audit.filter.from')}<Input className="w-auto" type="date" value={f.from} onChange={(e) => set({ from: e.target.value })} /></label>
        <label className="flex items-center gap-1.5 text-meta text-muted">{t('audit.filter.to')}<Input className="w-auto" type="date" value={f.to} onChange={(e) => set({ to: e.target.value })} /></label>
      </ListToolbar>
      {/* the count of the lines that match (the cut-off said in it) and Export CSV of them */}
      <ListSummary id="audit" className="mb-2"
        actions={<DownloadButton variant="ghost" path={auditExportPath(f)} filename="vedette-audit.csv" onError={(e) => toast.error(errMsg(e, t))}><Download />{t('audit.export')}</DownloadButton>}>
        {q.data ? t('audit.count', { count: q.data.total }) : ''}
      </ListSummary>
      <QueryState query={q}>
        {(d) => (
          <>
            <DataTable urlKey="audit" data={d.items} columns={columns} caption={t('audit.caption')} pageSize={AUDIT_PAGE} server={{ total: d.total, list }}
              mobileRow={(r) => (
                <div className="grid gap-0.5 text-meta">
                  <span className="font-medium">{actionLabel(t, r.action)}</span>
                  <span className="break-words">{named(r.target)}{r.detail ? `: ${named(r.detail)}` : ''}</span>
                  <span className="text-caption text-muted">{fmtDateTime(r.ts)}, {r.user}</span>
                </div>
              )}
              empty={t('audit.empty')} filtered={filtered} onClearFilters={clear}
              emptyFiltered={<span className="inline-flex flex-wrap items-center justify-center gap-x-2 gap-y-1">{t('audit.emptyFiltered')}<Button size="sm" variant="link" onClick={clear}>{t('common:table.clearFilters')}</Button></span>} />
          </>
        )}
      </QueryState>
    </>
  )
}
