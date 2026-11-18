// The recommended updates a person marked done (S-TIER-1), under the list on /plan and on the device page: read only when opened.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { QueryState } from '@/components/common/States'
import { InfoTip } from '@/components/common/InfoTip'
import { usePlan } from './api'
import { PlanItems } from './Plan'

export function DoneList({ count, asset, showDevice = false }: { count: number; asset?: string; showDevice?: boolean }) {
  const { t } = useTranslation('findings')
  const [open, setOpen] = useState(false)
  const q = usePlan('all', asset, open, true)
  return (
    <details className="mt-4" onToggle={(e) => setOpen((e.target as HTMLDetailsElement).open)}>
      <summary className="w-fit cursor-pointer text-sm font-medium text-accent underline-offset-4 hover:underline">
        {t('plan.done.listTitle', { count })}
      </summary>
      <div className="mt-2 grid gap-2">
        <p className="flex items-center gap-1 text-meta text-muted">{t('plan.done.listInfo')}<InfoTip topic={t('plan.done.listTitle', { count })}>{t('plan.done.listInfo')}</InfoTip></p>
        {open ? <QueryState query={q}>{(d) => <PlanItems items={d.items} showDevice={showDevice} />}</QueryState> : null}
      </div>
    </details>
  )
}
