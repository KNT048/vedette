import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Section } from '@/components/common/PageHeader'
import { EmptyState, ErrorState, Loading } from '@/components/common/States'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Chip, type Tone } from '@/components/common/StatusChip'
import { fmtDateTime } from '@/lib/format'
import { useLog } from './api'
import { verifyChain } from './logic'
import type { LogEntry } from './types'

const TONE: Partial<Record<LogEntry['kind'], Tone>> = { refused: 'warn', failed: 'danger', emergency_stop: 'danger', executed: 'ok', approved: 'ok', rolled_back: 'accent', ttl_removed: 'accent' }

/** Re-computes every hash in the browser (crypto.subtle) and checks each entry points at the one before it. */
function useChain(items: LogEntry[] | undefined) {
  const [res, setRes] = useState<{ for: LogEntry[]; ok: boolean; broken_at: number | null } | null>(null)
  useEffect(() => {
    let live = true
    if (items) void verifyChain(items).then((r) => { if (live) setRes({ for: items, ...r }) })
    return () => { live = false }
  }, [items])
  return res && res.for === items ? res : null
}

export function LogTab() {
  const { t } = useTranslation('response')
  const q = useLog()
  const chain = useChain(q.data?.items)
  if (q.isPending) return <Loading />
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />
  const items = q.data.items
  const columns: ColumnDef<LogEntry>[] = [
    { id: 'ts', header: t('log.time'), enableSorting: false, cell: ({ row }) => <span className="whitespace-nowrap">{fmtDateTime(row.original.ts)}</span> },
    { id: 'kind', header: t('log.kind'), enableSorting: false, cell: ({ row }) => <Chip tone={TONE[row.original.kind] ?? 'off'}>{t(`log.kinds.${row.original.kind}`)}</Chip> },
    { id: 'actor', header: t('log.actor'), enableSorting: false, accessorFn: (e) => e.actor },
    { id: 'detail', header: t('log.detail'), enableSorting: false, accessorFn: (e) => e.detail },
    { id: 'hash', header: t('log.hash'), enableSorting: false, cell: ({ row }) => <span className="font-mono text-caption text-muted" title={row.original.hash}>{row.original.hash.slice(0, 10)}</span> },
  ]
  return (
    <Section label={t('log.title')} description={t('log.description')} info={t('log.descriptionInfo')} stories={['S-RESP-2', 'S-AI-8']}
      actions={chain === null ? <Chip tone="off">{t('log.checking')}</Chip> : chain.ok ? <Chip tone="ok">{t('log.verified')}</Chip> : <Chip tone="danger">{t('log.broken', { n: (chain.broken_at ?? 0) + 1 })}</Chip>}>
      {items.length ? (
        <DataTable urlKey="response-log" caption={t('log.title')} data={[...items].reverse()} columns={columns} pageSize={50}
          mobileRow={(e) => <div className="grid gap-1 text-sm"><div className="flex flex-wrap items-center gap-2"><Chip tone={TONE[e.kind] ?? 'off'}>{t(`log.kinds.${e.kind}`)}</Chip><span className="text-meta text-muted">{fmtDateTime(e.ts)}, {e.actor}</span></div><p>{e.detail}</p><p className="font-mono text-caption text-muted" title={e.hash}>{e.hash.slice(0, 10)}</p></div>} />
      ) : <EmptyState title={t('log.empty')}>{t('log.emptyBody')}</EmptyState>}
    </Section>
  )
}
