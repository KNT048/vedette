// By fix: the plan. One numbered step per fix across devices ("1. Update OpenSSH 9.6 → 10.6: 3 devices, 61 findings"), in the order
// to do them (the most urgent first, then the fix that clears the most findings), opening to the devices it applies to. Mark as
// handled… acts on one device at a time, on the CVEs the person keeps ticked (all by default). As Defender's security
// recommendations and Tenable's remediation view group by the fix and rank it (GET /findings/fixes).
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { ChevronDown } from 'lucide-react'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { ListSearch } from '@/components/common/Pager'
import { useListParams } from '@/components/common/listParams'
import { EmptyState, QueryState } from '@/components/common/States'
import { StatusBadge } from '@/components/common/status'
import { Button } from '@/components/ui/button'
import { useCan } from '@/lib/session'
import { usePossibleSame } from '@/features/inventory/api'
import { useDeviceCards, useFixCards } from './api'
import { PAGE_DEFAULT, PAGE_MAX } from './contract'
import { errMsg } from './errors'
import { HandleDialog, type HandleRow } from './HandleDialog'
import { DeviceLine, FixLink, SeverityLine, useFixTitle } from './parts'
import { StatusFilter } from './StatusFilter'
import type { DeviceRef, FixCard, FixDevice, SoftwareRef } from './types'

type Want = { device: DeviceRef; fix: string; software: string | null }
type Handling = { device: DeviceRef; rows: HandleRow[]; fix: string; software: string | null; complete: boolean }

/** Reads the device's CVEs of the fix (its block in By device, under the same search and filter), then opens the dialog with them. */
function LoadRows({ want, q, status, onRows, onFail }: { want: Want; q: string; status: string; onRows: (h: Handling) => void; onFail: () => void }) {
  const { t } = useTranslation('findings')
  const r = useDeviceCards({ device: want.device.id, q, status }, { offset: 0, limit: 1 })
  const block = r.data?.items[0]?.blocks.find((b) => b.fix.key === want.fix && (b.software?.id ?? null) === want.software)
  useEffect(() => {
    if (block) onRows({ device: want.device, fix: want.fix, software: want.software, complete: !q && !status, rows: block.findings.map((f) => ({ id: f.id, cve: f.cve, severity: f.severity, status: f.status })) })
    else if (r.isError || r.data) { toast.error(r.isError ? errMsg(r.error) : t('byFix.gone', { device: want.device.name })); onFail() }
  }, [block, r.isError, r.data, r.error, want, q, status, onRows, onFail, t])
  return null
}

function DeviceRow({ d, fixTitle, same, busy, onHandle }: { d: FixDevice; fixTitle: string; same: Ref[]; busy: boolean; onHandle: () => void }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  return (
    <li className="flex flex-wrap items-center justify-between gap-2 py-2">
      <div className="grid gap-0.5">
        <DeviceLine device={d.device} badge={false} />
        <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
          {d.software?.version ? <span className="text-meta text-muted">{t('byFix.installed', { software: d.software.name, version: d.software.version })}</span> : null}
          <StatusBadge code={d.status} />
          {d.findings > 0 ? <Link to={`/findings?tab=device&device=${encodeURIComponent(d.device.id)}`} className="text-meta text-accent underline-offset-4 hover:underline">{t('byFix.findings', { count: d.findings })}</Link> : null}
          <SeverityLine counts={d.severity} />
        </span>
        {d.others.length ? (
          <span className="text-meta text-muted">
            {t('byFix.otherSteps', { count: d.others.length, product: d.others[0]!.product, fixes: listOf(d.others.map((o) => o.version ?? t(o.kind === 'none_yet' ? 'byFix.otherNoneYet' : 'byFix.otherAdvisory'))) })}
          </span>
        ) : null}
        {same.length ? (
          <Link to={`/devices/${encodeURIComponent(d.device.id)}#possible-same`} className="w-fit text-meta text-accent underline-offset-4 hover:underline">
            {t('byFix.sameAs', { names: listOf(same.map((x) => x.name)) })}
          </Link>
        ) : null}
      </div>
      <Button size="sm" disabled={!can} busy={busy} busyLabel={t('common:busy.working')} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })}
        aria-label={t('byFix.handleOf', { fix: fixTitle, device: d.device.name })} onClick={onHandle}>{t('byDevice.handleOne')}</Button>
    </li>
  )
}

const listOf = (xs: string[]) => new Intl.ListFormat('en', { type: 'conjunction' }).format(xs)

/** The version the card's devices run now, when they all run one ("from" of "Update nginx 1.30.5 → 1.31.9"); null otherwise. */
function sharedFrom(card: FixCard): SoftwareRef | null {
  const vs = [...new Set(card.items.map((d) => d.software?.version ?? null))]
  const first = card.items[0]?.software
  return vs.length === 1 && vs[0] && first ? first : null
}

type Ref = { id: string; name: string }
/** For each device of the card, the other devices of the same card that may be the same machine (GET /inventory/possible-same). */
type Same = Map<string, Ref[]>
function sameIn(card: FixCard, pairs: { a: Ref; b: Ref }[]): Same {
  const ids = new Set(card.items.map((d) => d.device.id))
  const out: Same = new Map()
  const add = (id: string, other: Ref) => out.set(id, [...(out.get(id) ?? []), other])
  for (const p of pairs) {
    if (p.a.id !== p.b.id && ids.has(p.a.id) && ids.has(p.b.id)) { add(p.a.id, p.b); add(p.b.id, p.a) }
  }
  return out
}

/** How many machines the card's devices may be, joining the devices that may be the same machine. */
function machines(card: FixCard, same: Same): number {
  const parent = new Map<string, string>()
  const find = (x: string): string => { const p = parent.get(x); return p === undefined || p === x ? x : find(p) }
  for (const [id, others] of same) for (const o of others) { const a = find(id), b = find(o.id); if (a !== b) parent.set(a, b) }
  return new Set(card.items.map((d) => find(d.device.id))).size
}

function FixCardView({ card, rank, same, loading, onHandle }: { card: FixCard; rank: number; same: Same; loading: Want | null; onHandle: (w: Want) => void }) {
  const { t } = useTranslation('findings')
  const from = sharedFrom(card)
  const title = useFixTitle()(card.fix, from)
  const [open, setOpen] = useState(false)
  const panel = `fix-${card.fix.key.replace(/[^\w-]/g, '_')}`
  const n = machines(card, same)
  const devices = t('byDevice.devices', { count: card.devices }) // "1 device", "3 devices"
  const nowOn = !from && card.fix.kind === 'update' ? [...new Set(card.items.map((d) => d.software?.version).filter((v): v is string => !!v))] : []
  return (
    <article aria-label={t('byFix.step', { n: rank, fix: title })} className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-2 gap-y-2 py-1">
      <span aria-hidden className="w-5 pt-1.5 text-right text-sm font-semibold text-muted tabular-nums" data-rank={rank}>{rank}</span>
      <div className="grid min-w-0 gap-2">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        {/* empty-guard: a fix card exists only for a fix with open findings (at least one) */}
        <Button variant="ghost" size="sm" aria-expanded={open} aria-controls={panel} onClick={() => setOpen((o) => !o)}
          className="-ml-2 h-auto min-h-8 justify-start gap-1.5 whitespace-normal py-1 text-left">
          <ChevronDown aria-hidden className={open ? '' : '-rotate-90'} />
          <span className="text-sm font-semibold [overflow-wrap:anywhere]">{title}</span>
          <span className="font-normal text-muted">{t('byFix.counts', { count: card.findings, devices })}</span>
          {/* devices that may be one machine say so instead of counting it twice without a word */}
          {n < card.devices ? <span className="font-normal text-muted">{t('byFix.machines', { count: n })}</span> : null}
        </Button>
        <StatusBadge code={card.status} />
        {card.findings > 1 ? <span className="text-meta text-muted">{t('byDevice.cause', { cve: card.cause })}</span> : null}
        <SeverityLine counts={card.severity} />
        <FixLink fix={card.fix} cve={card.cause} />
        {nowOn.length ? <span className="w-full text-meta text-muted">{t('byFix.nowOn', { versions: listOf(nowOn) })}</span> : null}
      </div>
      {open ? (
        <ul id={panel} aria-label={t('byFix.devicesOf', { fix: title })} className="ml-6 grid divide-y divide-rule border-l border-rule pl-3">
          {card.items.map((d) => (
            <DeviceRow key={`${d.device.id}/${d.software?.id ?? ''}`} d={d} fixTitle={title} same={same.get(d.device.id) ?? []} busy={loading?.device.id === d.device.id && loading.fix === card.fix.key && loading.software === (d.software?.id ?? null)}
              onHandle={() => onHandle({ device: d.device, fix: card.fix.key, software: d.software?.id ?? null })} />
          ))}
        </ul>
      ) : null}
      </div>
    </article>
  )
}

export function ByFix({ status }: { status: string }) {
  const { t } = useTranslation('findings')
  const raw = useListParams('by-fix')
  const list = useMemo(() => ({ ...raw, size: raw.size === undefined ? undefined : Math.min(raw.size, PAGE_MAX) }), [raw])
  const size = list.size ?? PAGE_DEFAULT
  const q = useFixCards({ q: raw.q, status }, { offset: list.page * size, limit: size })
  const [want, setWant] = useState<Want | null>(null)
  const [handling, setHandling] = useState<Handling | null>(null)
  const filtered = !!(raw.q || status)
  const pairs = usePossibleSame().data?.items // decoration only: without it (module off, no right) no device says "possibly the same"
  const offset = list.page * size
  const gotRows = useMemo(() => (h: Handling) => { setWant(null); setHandling(h) }, [])
  const failed = useMemo(() => () => setWant(null), [])
  const columns: ColumnDef<FixCard>[] = [
    { id: 'fix', header: t('byFix.col'), cell: ({ row: { original: c, index } }) => <FixCardView card={c} rank={offset + index + 1} same={sameIn(c, pairs ?? [])} loading={want} onHandle={setWant} /> },
  ]
  return (
    <div className="grid gap-3">
      <StatusFilter />
      <ListSearch value={raw.q} onChange={(v) => raw.set({ q: v, page: 0 })} label={t('byFix.search')} />
      <QueryState query={q}>
        {(d) => d.total === 0 && !filtered ? <EmptyState art="no-findings" title={t('byDevice.empty')}>{t('byDevice.emptyBody')}</EmptyState> : (
          <>
            <div className="grid gap-0.5">
              <p role="status" className="text-sm" data-count="fix">{t('byFix.summary', { count: d.findings, fixes: t('byFix.fixes', { count: d.total }) })}</p>
              {d.total > 1 ? <p className="text-meta text-muted">{t('byFix.order')}</p> : null}
            </div>
            <DataTable urlKey="by-fix" caption={t('byFix.caption')} data={d.items} columns={columns} pageSize={PAGE_DEFAULT}
              server={{ total: d.total, list, max: PAGE_MAX }} filtered={filtered} onClearFilters={() => raw.set({ q: '', page: 0 })} resetPageOn={status}
              mobileRow={(c) => <FixCardView card={c} rank={offset + d.items.indexOf(c) + 1} same={sameIn(c, pairs ?? [])} loading={want} onHandle={setWant} />} />
          </>
        )}
      </QueryState>
      {want ? <LoadRows want={want} q={raw.q} status={status} onRows={gotRows} onFail={failed} /> : null}
      {handling ? <HandleDialog {...handling} onClose={() => setHandling(null)} /> : null}
    </div>
  )
}
