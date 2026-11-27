import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Pencil } from 'lucide-react'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { useCan } from '@/lib/session'
import { useEditNode, useRows } from './api'
import { MAX_SELECTED } from './contract'
import { Seen } from './NodeParts'
import type { Address, Host, TargetNode } from './types'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))
const link = 'text-accent underline-offset-4 hover:underline'

/**
 * The names found under a domain target, each with its addresses, where it was found and when first and last seen. A name that
 * is its own target says so and links there (this target skips it). With the scope "the names I choose", the names are picked here.
 */
export function NamesPanel({ node, onEdit }: { node: TargetNode; onEdit: () => void }) {
  const q = useRows(node.id, 'hosts')
  const addresses = useRows(node.id, 'addresses')
  return <QueryState query={q}>{(d) => <NamesTable node={node} hosts={d.items} addresses={addresses.data?.items ?? []} onEdit={onEdit} />}</QueryState>
}

function NamesTable({ node, hosts, addresses, onEdit }: { node: TargetNode; hosts: Host[]; addresses: Address[]; onEdit: () => void }) {
  const { t } = useTranslation('exposure')
  const admin = useCan('admin')
  const edit = useEditNode(node.id)
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set())
  const [adding, setAdding] = useState(true)
  const choosing = node.scope_mode === 'selected'
  const pickable = choosing && admin
  // The target's own name is always scanned and a name that is its own target is scanned there: neither is chosen here.
  const free = hosts.filter((h) => !h.child && h.name !== node.value)
  const picked = free.filter((h) => selected.has(h.id)).map((h) => h.id)
  const toggle = (id: string, on: boolean) => setSelected((s) => { const n = new Set(s); if (on) n.add(id); else n.delete(id); return n })
  const chosen = free.filter((h) => h.selected).map((h) => h.id)
  // One scan reads at most 300 names with the target's own: a choice beyond that is refused, so the page says so before sending it.
  const withPicked = [...new Set([...chosen, ...picked])].length
  const tooMany = withPicked > MAX_SELECTED
  // The choice is replaced as a whole: the names chosen now, with the picked ones added or taken out.
  const save = (on: boolean) => {
    setAdding(on)
    const next = on ? [...new Set([...chosen, ...picked])] : chosen.filter((id) => !picked.includes(id))
    edit.mutate({ selected: next }, {
      onSuccess: () => { toast.success(t(on ? 'names.chosenToast' : 'names.unchosenToast', { count: picked.length })); setSelected(new Set()) },
      onError: (e) => toast.error(errMsg(e)),
    })
  }
  const ips = (h: Host) => addresses.filter((a) => a.host_id === h.id)
  const scanned = (h: Host) => (h.child ? 'child' : h.name === node.value || node.scope_mode === 'all' ? 'yes' : node.scope_mode === 'self' ? 'no' : h.selected ? 'yes' : 'no')
  const columns: ColumnDef<Host>[] = [
    ...(pickable ? [{ id: 'select', enableSorting: false, header: () => (
      <Checkbox checked={free.length > 0 && picked.length === free.length ? true : picked.length > 0 ? 'indeterminate' : false}
        onCheckedChange={(v) => setSelected(v === true ? new Set(free.map((h) => h.id)) : new Set())} aria-label={t('names.selectAll', { count: free.length })} />
    ), cell: ({ row }) => (!free.includes(row.original) ? null
      : <Checkbox checked={selected.has(row.original.id)} onCheckedChange={(v) => toggle(row.original.id, v === true)} aria-label={t('names.select', { name: row.original.name })} />) } satisfies ColumnDef<Host>] : []),
    { id: 'name', header: t('names.col.name'), accessorFn: (h) => h.name, cell: ({ row }) => (
      <span className="grid gap-0.5">
        <span className="font-medium [overflow-wrap:anywhere]">{row.original.name}</span>
        {row.original.cname ? <span className="text-caption text-muted [overflow-wrap:anywhere]">{t('names.cname', { target: row.original.cname })}</span> : null}
      </span>
    ) },
    { id: 'addresses', header: t('names.col.addresses'), enableSorting: false, cell: ({ row }) => <Addresses list={ips(row.original)} /> },
    { id: 'source', header: t('names.col.source'), accessorFn: (h) => h.source, cell: ({ row }) => <span className="text-meta">{t(`names.source.${row.original.source}`)}</span> },
    { id: 'scanned', header: t('names.col.scanned'), accessorFn: scanned, cell: ({ row }) => <Scanned h={row.original} state={scanned(row.original)} /> },
    { id: 'seen', header: t('names.col.seen'), accessorFn: (h) => h.last_seen, cell: ({ row }) => <Seen i={row.original} /> },
  ]
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-3">
        <p className="text-sm">{t(`scope.line.${node.scope_mode ?? 'all'}`, { value: node.value, count: chosen.length })}</p>
        <Button size="sm" onClick={onEdit} disabled={!admin} title={admin ? undefined : t('common:needRole', { role: t('common:role.admin') })}><Pencil />{t('names.changeScope')}</Button>
      </div>
      {picked.length ? (
        <div role="region" aria-label={t('names.selection')} className="flex flex-wrap items-center gap-2">
          <span className="text-meta font-medium">{t('names.selected', { count: picked.length })}</span>
          {/* empty-guard: the bar shows only with a selection */}
          <Button size="sm" variant="primary" disabled={(edit.isPending && !adding) || tooMany} aria-describedby={tooMany ? 'ex-names-too-many' : undefined} busy={edit.isPending && adding} busyLabel={t('common:busy.saving')} onClick={() => save(true)}>{t('names.choose', { count: picked.length })}</Button>
          {/* empty-guard: the bar shows only with a selection */}
          <Button size="sm" disabled={edit.isPending && adding} busy={edit.isPending && !adding} busyLabel={t('common:busy.saving')} onClick={() => save(false)}>{t('names.unchoose', { count: picked.length })}</Button>
          <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>{t('issues.clearSelection')}</Button>
          {tooMany ? <p id="ex-names-too-many" className="w-full text-meta text-warn">{t('names.tooMany', { max: MAX_SELECTED, count: withPicked })}</p> : null}
        </div>
      ) : null}
      <DataTable urlKey="exposure-names" caption={t('names.caption', { value: node.value })} data={hosts} columns={columns} pageSize={50} fillColumn="name" initialSort={[{ id: 'name', desc: false }]}
        mobileRow={(h) => (
          <div className="grid gap-1.5">
            <div className="flex items-start gap-2">
              {pickable && free.includes(h) ? <Checkbox checked={selected.has(h.id)} onCheckedChange={(v) => toggle(h.id, v === true)} aria-label={t('names.select', { name: h.name })} /> : null}
              <span className="font-medium [overflow-wrap:anywhere]">{h.name}</span>
            </div>
            <Addresses list={ips(h)} />
            <Scanned h={h} state={scanned(h)} />
            <Seen i={h} />
          </div>
        )}
        empty={<EmptyState title={t('names.emptyTitle')}>{node.last_scan ? null : t('names.emptyNever')}</EmptyState>} />
    </div>
  )
}

/** The addresses of a name with their kind: this box's own, private (never dialed), or any other public address. */
function Addresses({ list }: { list: Address[] }) {
  const { t } = useTranslation('exposure')
  if (!list.length) return <span className="text-meta text-muted">{t('names.noAddress')}</span>
  return (
    <span className="grid gap-1">
      {list.map((a) => (
        <span key={a.ip} className="flex flex-wrap items-center gap-1.5">
          <span className="font-mono text-meta">{a.ip}</span>
          {a.class !== 'public' ? <Chip tone="off">{t(`names.class.${a.class}`)}</Chip> : null}
        </span>
      ))}
    </span>
  )
}

/** Whether this target scans the name: yes, not in its scope, or scanned as its own target (a link there). */
function Scanned({ h, state }: { h: Host; state: 'child' | 'yes' | 'no' }) {
  const { t } = useTranslation('exposure')
  if (state === 'child' && h.child) return <span className="text-meta">{t('names.ownTarget')} <Link className={link} to={`/exposure/${encodeURIComponent(h.child.id)}`}>{h.child.value}</Link></span>
  return <span className={state === 'yes' ? 'text-meta' : 'text-meta text-muted'}>{t(`names.scanned.${state}`)}</span>
}
