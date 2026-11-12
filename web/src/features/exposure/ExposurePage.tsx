import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Plus } from 'lucide-react'
import { PageHeader, Section, Panel } from '@/components/common/PageHeader'
import { EmptyState, QueryState, RequireModule, SampleDataNote } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter, DialogTrigger } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/input'
import { fmtRelative } from '@/lib/format'
import { useCan } from '@/lib/session'
import { BoxIpPanel } from './BoxIpPanel'
import { OwnerChip } from './OwnerChip'
import { useAddTarget, useTargets } from './api'
import type { Target } from './types'

export default function ExposurePage() {
  const { t } = useTranslation('exposure')
  const q = useTargets()
  // Đọc rõ các trường query ở đây để react-query theo dõi đúng khi chuyển sang lỗi.
  const { data, error, isPending, refetch } = q
  const items = data?.items
  const scanned = items?.filter((x) => x.latest) ?? []
  const admin = scanned.reduce((n, x) => n + (x.latest?.admin_panels ?? 0), 0)
  const certs = scanned.reduce((n, x) => n + (x.latest?.certs_expiring ?? 0), 0)
  const pending = items?.filter((x) => !x.scannable).length ?? 0
  const title = !items ? t('titleLoading')
    : items.length === 0 ? t('title.none')
    : scanned.length === 0 ? (pending > 0 ? t('title.pending', { count: pending }) : t('title.ready', { count: items.length }))
    : admin > 0 ? t('title.admin', { count: admin })
    : pending > 0 ? t('title.cleanPartial', { count: pending })
    : t('title.clean')
  return (
    <RequireModule module="exposure">
      <PageHeader title={title} stories={['S-EXP-1']} actions={<AddTarget />}
        meta={<span className="flex flex-wrap items-center gap-2"><SampleDataNote />{certs > 0 ? `${t('meta.certs', { count: certs })} ` : null}{t('meta.rule')}</span>} />
      <QueryState query={{ data, error, isPending, refetch }}>
        {(d) => (
          <>
            <Section id="targets" title={t('targets.title')} description={t('targets.description')}>
              <TargetsTable items={d.items.filter((x) => x.kind === 'domain')} />
            </Section>
            <BoxIpPanel items={d.items.filter((x) => x.kind === 'ip')} settings={d.box_ip} ignored={d.ignored} />
          </>
        )}
      </QueryState>
      <Panel className="max-w-3xl p-4 text-[13px] text-muted">{t('rule')}</Panel>
    </RequireModule>
  )
}

function TargetsTable({ items }: { items: Target[] }) {
  const { t } = useTranslation('exposure')
  const columns: ColumnDef<Target>[] = [
    { id: 'value', header: t('targets.col.target'), accessorFn: (r) => r.value, cell: ({ row }) => (
      <span className="grid"><Link className="font-medium text-accent underline-offset-4 hover:underline" to={`/exposure/${row.original.id}`}>{row.original.value}</Link><span className="text-[12px] text-muted">{t(`kind.${row.original.kind}`)}</span></span>
    ) },
    { id: 'owner', header: t('targets.col.owner'), accessorFn: (r) => r.status, cell: ({ row }) => <OwnerChip target={row.original} /> },
    { id: 'commit', header: t('targets.col.commit'), accessorFn: (r) => (r.commitment ? 1 : 0), cell: ({ row }) => (row.original.commitment ? <Chip tone="ok">{t('status.commitYes')}</Chip> : <Chip tone="off">{t('status.commitNo')}</Chip>) },
    { id: 'scan', header: t('targets.col.scan'), accessorFn: (r) => r.last_scan_at ?? '', cell: ({ row }) => {
      const r = row.original
      return r.blocked_reason ? <span className="text-[13px] text-warn">{t(`blocked.${r.blocked_reason}`)}</span> : <span className="grid"><span>{r.last_scan_at ? fmtRelative(r.last_scan_at) : t('targets.neverScanned')}</span><span className="text-[12px] text-muted">{t('targets.ready')}</span></span>
    } },
    { id: 'latest', header: t('targets.col.latest'), enableSorting: false, cell: ({ row }) => {
      const c = row.original.latest
      return c ? <span className="text-[13px]">{t('targets.latest', { admin: c.admin_panels, ports: c.ports, certs: c.certs_expiring })}</span> : <span className="text-[13px] text-muted">{t('targets.noResult')}</span>
    } },
  ]
  return <DataTable caption={t('targets.caption')} data={items} columns={columns} pageSize={20}
    mobileRow={(r) => (
      <div className="grid gap-1.5">
        <Link className="break-all font-medium text-accent underline-offset-4 hover:underline" to={`/exposure/${r.id}`}>{r.value}</Link>
        <div className="flex flex-wrap items-center gap-2">
          <OwnerChip target={r} />
          {r.commitment ? <Chip tone="ok">{t('status.commitYes')}</Chip> : <Chip tone="off">{t('status.commitNo')}</Chip>}
        </div>
        <p className="text-[13px] text-muted">{r.blocked_reason ? t(`blocked.${r.blocked_reason}`) : r.last_scan_at ? fmtRelative(r.last_scan_at) : t('targets.neverScanned')}</p>
        {r.latest ? <p className="text-[13px]">{t('targets.latest', { admin: r.latest.admin_panels, ports: r.latest.ports, certs: r.latest.certs_expiring })}</p> : null}
      </div>
    )}
    empty={<EmptyState title={t('targets.emptyTitle')}>{t('targets.emptyBody')}</EmptyState>} />
}

function AddTarget() {
  const { t } = useTranslation('exposure')
  const can = useCan('admin')
  const add = useAddTarget()
  const nav = useNavigate()
  const [open, setOpen] = useState(false)
  const [value, setValue] = useState('')
  const [error, setError] = useState<string | null>(null)
  // Cancel, Esc and X all drop the draft and its error, so the next opening never shows an error for text that is gone.
  const toggle = (o: boolean) => { setOpen(o); if (!o) { setError(null); setValue('') } }
  function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    if (!value.trim()) return setError(t('add.empty'))
    add.mutate(value.trim(), {
      onSuccess: (tg) => { toast.success(t('add.toast', { value: tg.value })); setOpen(false); setValue(''); void nav(`/exposure/${tg.id}`) },
      onError: (er) => setError(er instanceof Error ? er.message : String(er)),
    })
  }
  return (
    <Dialog open={open} onOpenChange={toggle}>
      <DialogTrigger asChild>
        <Button variant="primary" disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.admin') })}><Plus />{t('add.button')}</Button>
      </DialogTrigger>
      <DialogContent title={t('add.title')} description={t('add.description')}>
        <form onSubmit={submit} noValidate className="grid gap-4">
          <Field label={t('add.label')} htmlFor="ex-new" hint={t('add.hint')} error={error ?? undefined}>
            <Input id="ex-new" value={value} onChange={(e) => setValue(e.target.value)} autoFocus autoComplete="off" spellCheck={false} aria-invalid={error ? true : undefined} aria-describedby={error ? 'ex-new-error' : 'ex-new-hint'} />
          </Field>
          <DialogFooter>
            <Button onClick={() => toggle(false)}>{t('common:cancel')}</Button>
            <Button type="submit" variant="primary" disabled={add.isPending}>{t('add.submit')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
