import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import type { UseQueryResult } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/common/Card'
import { EmptyState, QueryState } from '@/components/common/States'
import { useCan } from '@/lib/session'
import { useDeviceAction } from '@/features/inventory/api'
import { errMsg } from './errors'
import { deviceName } from './basis'
import { FindingStatus } from './legacyStatus'
import type { FindingRow } from './types'

function IgnoredDevice({ id, name, rows }: { id: string; name: string; rows: FindingRow[] }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const act = useDeviceAction(id)
  return (
    <li className="grid gap-2 px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="flex flex-wrap items-baseline gap-x-2">
          <Link to={`/devices/${id}`} className="font-medium text-accent underline-offset-4 [overflow-wrap:anywhere] hover:underline">{name}</Link>
          <span className="text-meta text-muted">{t('ignoredTab.count', { count: rows.length })}</span>
        </span>
        <Button size="sm" disabled={!can} busy={act.ignore.isPending} busyLabel={t('common:busy.saving')}
          onClick={() => act.ignore.mutate(false, { onSuccess: () => toast.success(t('ignoredTab.restored', { name })), onError: (e) => toast.error(errMsg(e)) })}>{t('ignoredTab.restore')}</Button>
      </div>
      <ul className="grid gap-1 text-sm">
        {rows.map((f) => (
          <li key={f.id} className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <Link to={`/findings/${f.id}`} className="font-medium text-accent underline-offset-4 hover:underline">{f.cve}</Link>
            <span className="text-muted">{f.kev?.display ?? ''}</span>
            <FindingStatus f={f} />
          </li>
        ))}
      </ul>
    </li>
  )
}

/** The findings hidden because their device is ignored, one block per device, with Restore (stop ignoring: the device goes back to To review). */
export function IgnoredTab({ q }: { q: UseQueryResult<{ items: FindingRow[] }> }) {
  const { t } = useTranslation('findings')
  return (
    <QueryState query={q}>
      {(d) => {
        const by = new Map<string, FindingRow[]>()
        for (const f of d.items) if (f.asset?.ignored) by.set(f.asset_id, [...(by.get(f.asset_id) ?? []), f])
        const groups = [...by.entries()].map(([id, rows]) => ({ id, rows, name: deviceName(rows[0]!.asset, t('removedDevice')) })).sort((a, b) => a.name.localeCompare(b.name))
        return (
          <div className="grid gap-3">
            <p className="max-w-3xl text-meta text-muted">{t('ignoredTab.intro')}</p>
            {groups.length === 0 ? <EmptyState title={t('ignoredTab.none')} /> : (
              <Card flush><ul className="divide-y divide-rule">{groups.map((g) => <IgnoredDevice key={g.id} {...g} />)}</ul></Card>
            )}
          </div>
        )
      }}
    </QueryState>
  )
}
