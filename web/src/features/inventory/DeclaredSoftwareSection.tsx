import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Pencil, Plus, Trash2 } from 'lucide-react'
import { Section } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, ModuleOff, QueryState, RequireModule } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { fmtDateTime, fmtRelative, rawProductLine } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { useCan } from '@/lib/session'
import { AddDeviceDialog } from './AddDeviceDialog'
import { useDeviceAction, useDevices } from './api'
import { DeleteDialog } from './DeleteDialog'
import { errMsg } from './kinds'
import { declaredSoftwareOnly } from './nameOf'
import type { DeviceRow } from './types'
import { VersionDialog } from './VersionDialog'

// Settings › Declared software (#849): products someone said they run with no device and no address (the weekly "I have this", a CSV
// row with only a product, Add with no IP). They are not devices, so they left the Devices list, but they still feed Findings: each one
// is matched against exploited vulnerabilities by its product (D-515, D-598). Same API as Devices: GET /inventory/devices, rows where
// declaredSoftwareOnly holds; add = POST /inventory/devices with only a product; remove = DELETE the row; version = PATCH its software.

type Row = { d: DeviceRow; sw: DeviceRow['software'][number] | undefined }

function Remove({ r, onDone }: { r: Row; onDone: () => void }) {
  const { t } = useTranslation('inventory')
  const act = useDeviceAction(r.d.id)
  const name = r.sw?.display ?? r.d.id
  return (
    <DeleteDialog open onOpenChange={(o) => { if (!o) onDone() }} name={name} findings={r.d.findings_count} pending={act.remove.isPending}
      onConfirm={() => act.remove.mutate(undefined, { onSuccess: () => { toast.success(t('declaredPage.removed', { name })); onDone() }, onError: (e) => toast.error(errMsg(e)) })} />
  )
}

function Body() {
  const { t } = useTranslation('inventory')
  const q = useDevices()
  const can = useCan('operator')
  const findingsOn = useModuleEnabled('findings')
  const [adding, setAdding] = useState(false)
  const [editing, setEditing] = useState<Row | null>(null)
  const [removing, setRemoving] = useState<Row | null>(null)
  const rows = useMemo<Row[]>(() => (q.data?.items ?? []).filter(declaredSoftwareOnly).map((d) => ({ d, sw: d.software[0] })), [q.data])
  const needRole = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const columns: ColumnDef<Row>[] = [
    { id: 'name', header: t('declaredPage.col.product'), accessorFn: (r) => r.sw?.display ?? '', cell: ({ row }) => {
      const { d, sw } = row.original
      const raw = sw ? rawProductLine(sw.display, sw.vendor, sw.product) : null
      return (
        <div className="grid">
          <Link to={`/devices/${d.id}`} className="font-medium text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">{sw?.display ?? t('declaredPage.noProduct')}</Link>
          {raw ? <span className="text-[12px] text-muted">{raw}</span> : null}
        </div>
      )
    } },
    { id: 'version', header: t('software.version'), accessorFn: (r) => r.sw?.version ?? '', cell: ({ row }) => row.original.sw?.version || <span className="text-muted">{t('software.noVersion')}</span> },
    ...(findingsOn ? [{ id: 'findings', header: t('declaredPage.col.findings'), accessorFn: (r: Row) => r.d.findings_count, cell: ({ row }: { row: { original: Row } }) => (row.original.d.findings_count
      ? <Link to={`/findings?device=${encodeURIComponent(row.original.d.id)}`} className="tabular-nums text-accent underline-offset-4 hover:underline">{t('declaredPage.findings', { count: row.original.d.findings_count })}</Link>
      : <span className="text-muted">{t('declaredPage.noFindings')}</span>) } satisfies ColumnDef<Row>] : []),
    { id: 'added', header: t('declaredPage.col.added'), accessorFn: (r) => new Date(r.d.first_seen).getTime(), cell: ({ row }) => <time className="whitespace-nowrap text-[13px] text-muted" dateTime={row.original.d.first_seen} title={fmtDateTime(row.original.d.first_seen)}>{fmtRelative(row.original.d.first_seen)}</time> },
    { id: 'actions', header: () => <span className="sr-only">{t('declaredPage.col.actions')}</span>, enableSorting: false, cell: ({ row }) => {
      const r = row.original
      const name = r.sw?.display ?? ''
      return (
        <span className="flex justify-end gap-1">
          {r.sw ? <Button size="icon" variant="ghost" aria-label={t('declaredPage.editVersion', { name })} title={needRole ?? t('declaredPage.editVersion', { name })} disabled={!can} onClick={() => setEditing(r)}><Pencil /></Button> : null}
          <Button size="icon" variant="ghost" aria-label={t('declaredPage.remove', { name })} title={needRole ?? t('declaredPage.remove', { name })} disabled={!can} onClick={() => setRemoving(r)}><Trash2 /></Button>
        </span>
      )
    } },
  ]
  return (
    <Section id="declared-software" title={t('declaredPage.title')} description={t('declaredPage.description')} info={<><p>{t('declaredPage.info')}</p><p>{t('declaredPage.info2')}</p></>} stories={['S-INV-2']}
      actions={<Button variant="primary" disabled={!can} title={needRole} onClick={() => setAdding(true)}><Plus />{t('declaredPage.add')}</Button>}>
      <QueryState query={q}>
        {() => (rows.length ? (
          <DataTable caption={t('declaredPage.caption')} data={rows} columns={columns} initialSort={[{ id: 'name', desc: false }]}
            filterPlaceholder={rows.length > 10 ? t('declaredPage.search') : undefined}
            mobileRow={(r) => (
              <div className="grid gap-1">
                <div className="flex items-start justify-between gap-2">
                  <Link to={`/devices/${r.d.id}`} className="min-w-0 font-medium text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">{r.sw?.display ?? t('declaredPage.noProduct')}</Link>
                  <span className="flex shrink-0 gap-1">
                    {r.sw ? <Button size="icon" variant="ghost" aria-label={t('declaredPage.editVersion', { name: r.sw.display })} disabled={!can} onClick={() => setEditing(r)}><Pencil /></Button> : null}
                    <Button size="icon" variant="ghost" aria-label={t('declaredPage.remove', { name: r.sw?.display ?? '' })} disabled={!can} onClick={() => setRemoving(r)}><Trash2 /></Button>
                  </span>
                </div>
                <span className="flex flex-wrap gap-x-3 text-[13px] text-muted">
                  <span>{r.sw?.version || t('software.noVersion')}</span>
                  {findingsOn ? <span>{r.d.findings_count ? t('declaredPage.findings', { count: r.d.findings_count }) : t('declaredPage.noFindings')}</span> : null}
                </span>
              </div>
            )} />
        ) : (
          <EmptyState title={t('declaredPage.empty')} info={t('declaredPage.emptyInfo')}
            action={<Button variant="primary" disabled={!can} title={needRole} onClick={() => setAdding(true)}><Plus />{t('declaredPage.add')}</Button>}>
            {t('declaredPage.emptyBody')}
          </EmptyState>
        ))}
      </QueryState>
      <AddDeviceDialog open={adding} onOpenChange={setAdding} declared />
      {editing?.sw ? <VersionDialog key={editing.d.id} sw={editing.sw} assetId={editing.d.id} onClose={() => setEditing(null)} /> : null}
      {removing ? <Remove key={removing.d.id} r={removing} onDone={() => setRemoving(null)} /> : null}
    </Section>
  )
}

export default function DeclaredSoftwareSection() {
  const { t } = useTranslation('inventory')
  return (
    <RequireModule module="inventory" fallback={<ModuleOff module="inventory">{t('off.body')}</ModuleOff>}>
      <Body />
    </RequireModule>
  )
}
