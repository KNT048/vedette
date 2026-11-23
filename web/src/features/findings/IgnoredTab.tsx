// Ignored devices: the open findings left out of every other list and count because a person ignored their device, one card per
// device with Restore (stop ignoring: the device goes back to To review and its findings to the lists).
import { useMemo } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { useListParams } from '@/components/common/listParams'
import { EmptyState, QueryState } from '@/components/common/States'
import { CveList } from '@/components/common/status'
import { Button } from '@/components/ui/button'
import { useCan } from '@/lib/session'
import { useDeviceAction } from '@/features/inventory/api'
import { useDeviceCards } from './api'
import { PAGE_DEFAULT, PAGE_MAX } from './contract'
import { errMsg } from './errors'
import { DeviceLine } from './parts'
import type { DeviceCard } from './types'

function IgnoredDevice({ card }: { card: DeviceCard }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const act = useDeviceAction(card.device.id)
  const name = card.device.name
  const findings = card.blocks.flatMap((b) => b.findings)
  return (
    <article aria-label={name} className="grid gap-2 py-1">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="grid gap-0.5">
          <DeviceLine device={card.device} badge={false} />
          <span className="text-meta text-muted">{t('byDevice.counts', { count: card.findings, cves: card.cves })}</span>
        </span>
        <Button size="sm" disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })} busy={act.ignore.isPending} busyLabel={t('common:busy.saving')}
          aria-label={t('ignoredTab.restoreOf', { name })}
          onClick={() => act.ignore.mutate(false, { onSuccess: () => toast.success(t('ignoredTab.restored', { name })), onError: (e) => toast.error(errMsg(e)) })}>{t('ignoredTab.restore')}</Button>
      </div>
      <CveList label={t('ignoredTab.cvesOf', { name })} items={findings.map((f) => ({ cve: f.cve, id: f.id, severity: f.severity, status: f.status, to: `/findings/${encodeURIComponent(f.id)}` }))} />
    </article>
  )
}

export function IgnoredTab() {
  const { t } = useTranslation('findings')
  const raw = useListParams('ignored')
  const list = useMemo(() => ({ ...raw, size: raw.size === undefined ? undefined : Math.min(raw.size, PAGE_MAX) }), [raw])
  const size = list.size ?? PAGE_DEFAULT
  const q = useDeviceCards({ ignored: true }, { offset: list.page * size, limit: size })
  const columns: ColumnDef<DeviceCard>[] = [
    { id: 'device', header: t('byDevice.col'), cell: ({ row: { original: c } }) => <IgnoredDevice card={c} /> },
  ]
  return (
    <div className="grid gap-3">
      <p className="max-w-3xl text-meta text-muted">{t('ignoredTab.intro')}</p>
      <QueryState query={q}>
        {(d) => d.total === 0 ? <EmptyState title={t('ignoredTab.none')} /> : (
          <DataTable urlKey="ignored" caption={t('ignoredTab.caption')} data={d.items} columns={columns} pageSize={PAGE_DEFAULT}
            server={{ total: d.total, list }} mobileRow={(c) => <IgnoredDevice card={c} />} />
        )}
      </QueryState>
    </div>
  )
}
