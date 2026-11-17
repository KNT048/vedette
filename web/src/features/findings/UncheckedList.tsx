// #910 phase 1 (J3/J5 trust): exploited CVEs of software the box has that it could not check are shown, never silent.
// No finding is created from this list; the customer checks the advisory. "Add the version" is done here, in the same dialog
// the Devices page uses.
import { useEffect, useState } from 'react'
import { Link, useLocation } from 'react-router'
import { useTranslation } from 'react-i18next'
import { Notice } from '@/components/common/PageHeader'
import { Chip } from '@/components/common/StatusChip'
import { Button } from '@/components/ui/button'
import { VersionDialog } from '@/features/inventory/VersionDialog'
import { useCan } from '@/lib/session'
import { deviceName } from './basis'
import type { UncheckedItem } from './types'

export const UNCHECKED_ANCHOR = 'unchecked'
const SHOWN = 3

const nvdUrl = (cve: string) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`

function Item({ item, onAdd }: { item: UncheckedItem; onAdd: (i: UncheckedItem) => void }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const [all, setAll] = useState(false)
  const name = deviceName(item.asset, t('removedDevice'))
  const self = name === item.software || name === t('inventory:noDevice', { product: item.software })
  const shown = all ? item.cves : item.cves.slice(0, SHOWN)
  return (
    <li className="grid gap-1">
      <p>
        {self ? null : <><Link to={`/devices/${item.asset_id}`} className="font-medium text-accent underline-offset-4 hover:underline">{name}</Link>{': '}</>}
        <span className="font-medium">{item.software}{item.version ? ` ${item.version}` : ''}</span>
        {' - '}{t(`unchecked.reason.${item.reason}`, { software: item.software, version: item.version ?? '' })}
      </p>
      <ul className="grid gap-0.5 pl-4">
        {shown.map((c) => (
          <li key={c.cve} className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
            <a href={c.advisory ?? nvdUrl(c.cve)} target="_blank" rel="noreferrer noopener" className="text-accent underline-offset-4 hover:underline"
              aria-label={t(c.advisory ? 'unchecked.advisoryLabel' : 'unchecked.nvdLabel', { cve: c.cve })}>{c.cve}</a>
            <span>{c.name}</span>
            {c.ransomware ? <Chip tone="danger">{t('unchecked.ransomware')}</Chip> : null}
          </li>
        ))}
      </ul>
      {item.cves.length > SHOWN ? (
        <div className="pl-4"><Button size="sm" variant="ghost" aria-expanded={all} onClick={() => setAll(!all)}>
          {all ? t('unchecked.less') : t('unchecked.more', { count: item.cves.length - SHOWN })}
        </Button></div>
      ) : null}
      {item.action === 'add_version' && item.software_id ? (
        <div className="pl-4"><Button size="sm" disabled={!can} onClick={() => onAdd(item)}>{t('unchecked.addVersion')}</Button></div>
      ) : null}
    </li>
  )
}

export function UncheckedList({ items }: { items: UncheckedItem[] }) {
  const { t } = useTranslation('findings')
  const { hash } = useLocation()
  const [adding, setAdding] = useState<UncheckedItem | null>(null)
  const count = new Set(items.flatMap((i) => i.cves.map((c) => c.cve))).size
  useEffect(() => {
    if (hash === `#${UNCHECKED_ANCHOR}`) document.getElementById(UNCHECKED_ANCHOR)?.scrollIntoView?.({ block: 'start' })
  }, [hash])
  return (
    <section id={UNCHECKED_ANCHOR} aria-labelledby="unchecked-title" className="scroll-mt-4">
      <Notice tone="warn" title={<span id="unchecked-title">{t('unchecked.title', { count })}</span>} info={t('unchecked.info')}>
        <p>{t('unchecked.help')}</p>
        <ul className="mt-2 grid gap-3">
          {items.map((i) => <Item key={`${i.asset_id}/${i.software_id ?? i.software}/${i.reason}`} item={i} onAdd={setAdding} />)}
        </ul>
      </Notice>
      {adding?.software_id ? (
        <VersionDialog key={adding.software_id} sw={{ id: adding.software_id, display: adding.software, version: adding.version ?? '' }} assetId={adding.asset_id} onClose={() => setAdding(null)} />
      ) : null}
    </section>
  )
}
