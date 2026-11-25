// By device (the screen's default tab): one card per device with open findings, the most urgent first; inside, one block per fix
// ("Update OpenSSH 10.2p1 → 10.6: fixes 3 CVEs") with its CVEs, the most severe first, each one click from its finding. A device
// with a finding and no known fix is listed too ("No fix known yet"). The server groups, orders and pages (GET /findings/devices).
import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ChevronDown, X } from 'lucide-react'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { ListSearch } from '@/components/common/Pager'
import { useListParams } from '@/components/common/listParams'
import { EmptyState, QueryState } from '@/components/common/States'
import { CveList, StatusBadge } from '@/components/common/status'
import { Button } from '@/components/ui/button'
import { useCan } from '@/lib/session'
import { useDeviceCards } from './api'
import { PAGE_DEFAULT, PAGE_MAX } from './contract'
import { HandleDialog, type HandleRow } from './HandleDialog'
import { NotAdded } from './NotAdded'
import { asAsset, DeviceLine, FixLink, useFixTitle } from './parts'
import { StatusFilter } from './StatusFilter'
import type { DeviceCard, DeviceRef, FixBlock } from './types'

export type Handling = { device: DeviceRef; rows: HandleRow[]; fix?: string; software?: string | null; complete?: boolean }

function Block({ device, block, narrowed, onHandle, fold = false }: { device: DeviceRef; block: FixBlock; narrowed: boolean; onHandle: (h: Handling) => void; fold?: boolean }) {
  const { t } = useTranslation('findings')
  const [open, setOpen] = useState(!fold) // on the device's own page a block opens on click
  const can = useCan('operator')
  const title = useFixTitle()
  const need = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const rows: HandleRow[] = block.findings.map((f) => ({ id: f.id, cve: f.cve, severity: f.severity, status: f.status }))
  const what = title(block.fix, block.software)
  return (
    <li className="grid gap-2 py-3 first:pt-0 last:pb-0" aria-label={what}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm">
          {fold ? (
            <Button variant="ghost" size="sm" aria-expanded={open} onClick={() => setOpen((o) => !o)} className="-ml-2 h-auto min-h-8 gap-1.5 whitespace-normal py-1 text-left">
              <ChevronDown aria-hidden className={open ? 'rotate-180' : ''} /><span className="font-medium [overflow-wrap:anywhere]">{what}</span>
            </Button>
          ) : <span className="font-medium [overflow-wrap:anywhere]">{what}</span>}
          <span className="text-muted">{block.fix.kind === 'none_yet' || block.fix.kind === 'unknown' ? t('byDevice.affects', { count: block.findings.length }) : t('byDevice.fixes', { count: block.findings.length })}</span>
          <StatusBadge code={block.status} />
          {block.findings.length > 1 ? <span className="text-meta text-muted">{t('byDevice.cause', { cve: block.cause })}</span> : null}
          <FixLink fix={block.fix} cve={block.cause} />
        </p>
        <Button size="sm" disabled={!can} title={need} aria-label={t('byDevice.handleBlockOf', { fix: what, device: device.name })}
          onClick={() => onHandle({ device, rows, fix: block.fix.key, software: block.software?.id ?? null, complete: !narrowed })}>{t('byDevice.handleBlock')}</Button>
      </div>
      {open ? <CveList rows showStatus label={t('byDevice.cvesOf', { fix: what })}
        items={block.findings.map((f) => ({ cve: f.cve, id: f.id, severity: f.severity, status: f.status, urgency: f.urgency, verification: f.verification, to: `/findings/${encodeURIComponent(f.id)}` }))}
        action={(i) => (
          <Button size="sm" variant="ghost" className="h-7" disabled={!can} title={need} aria-label={t('byDevice.handleOneOf', { cve: i.cve, device: device.name })}
            onClick={() => onHandle({ device, rows: rows.filter((r) => r.id === i.id) })}>{t('byDevice.handleOne')}</Button>
        )} /> : null}
    </li>
  )
}

/** One device: its name line and badge, Add device and Ignore while nobody added it, then its fix blocks. On the device's own page
 *  (`own`) the page already names the device and offers those actions: the card is its counts and its fix blocks. */
export function DeviceCardView({ card, narrowed, onHandle, own = false }: { card: DeviceCard; narrowed: boolean; onHandle: (h: Handling) => void; own?: boolean }) {
  const { t } = useTranslation('findings')
  const title = useFixTitle()
  const [open, setOpen] = useState(false) // By device: a device opens on click, like a fix in By fix
  const counts = <span className="text-meta text-muted">{t('byDevice.counts', { count: card.findings, cves: card.cves })}</span>
  const urgency = (['under_attack', 'exploited', 'public_exploit', 'critical_edge', 'update_recommended'] as const).filter((k) => card.counts[k] > 0).map((k) => t(`common:deviceStatus.${k}`, { count: card.counts[k] })).join(' · ')
  const top = card.blocks[0]
  const panel = `device-${card.device.id.replace(/[^\w-]/g, '_')}`
  const list = (
    <ul id={own ? undefined : panel} aria-label={t('byDevice.blocksOf', { device: card.device.name })} className="grid divide-y divide-rule">
      {card.blocks.map((b) => <Block key={b.fix.key} device={card.device} block={b} narrowed={narrowed} onHandle={onHandle} fold={own} />)}
    </ul>
  )
  return (
    <article aria-label={card.device.name} className="grid gap-3 py-1">
      {own ? <>{counts}{list}</> : (
        <>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="grid gap-0.5">
              <div className="flex items-center gap-1">
                <Button variant="ghost" size="icon" aria-expanded={open} aria-controls={panel} aria-label={t('byDevice.toggle', { device: card.device.name })} onClick={() => setOpen((o) => !o)} className="size-8 shrink-0">
                  <ChevronDown aria-hidden className={open ? 'rotate-180' : ''} />
                </Button>
                <DeviceLine device={card.device} status={card.status} />
              </div>
              <span className="ml-9 flex flex-wrap items-center gap-x-2 text-meta text-muted">{counts}{urgency ? <span>{urgency}</span> : null}</span>
              {top ? <span className="ml-9 text-meta text-muted">{t('byDevice.worst', { fix: title(top.fix, top.software), cve: top.cause })}</span> : null}
            </div>
            {!card.device.added && !card.device.ignored ? <NotAdded asset={asAsset(card.device)} findings={card.findings} /> : null}
          </div>
          {open ? list : null}
        </>
      )}
    </article>
  )
}

export function ByDevice({ status, device, onDevice }: { status: string; device: string; onDevice: (id: string) => void }) {
  const { t } = useTranslation('findings')
  const raw = useListParams('by-device')
  const list = useMemo(() => ({ ...raw, size: raw.size === undefined ? undefined : Math.min(raw.size, PAGE_MAX) }), [raw])
  const size = list.size ?? PAGE_DEFAULT
  const q = useDeviceCards({ q: raw.q, status, device }, { offset: list.page * size, limit: size })
  const [handling, setHandling] = useState<Handling | null>(null)
  const narrowed = !!(raw.q || status)
  const filtered = narrowed || !!device
  const clear = () => { raw.set({ q: '', page: 0 }); onDevice('') }
  const columns: ColumnDef<DeviceCard>[] = [
    { id: 'device', header: t('byDevice.col'), cell: ({ row: { original: c } }) => <DeviceCardView card={c} narrowed={narrowed} onHandle={setHandling} /> },
  ]
  const named = q.data?.items.find((c) => c.device.id === device)?.device.name
  return (
    <div className="grid gap-3">
      <StatusFilter />
      <div className="flex flex-wrap items-center gap-2">
        <ListSearch value={raw.q} onChange={(v) => raw.set({ q: v, page: 0 })} label={t('byDevice.search')} />
        {device ? <Button size="sm" onClick={() => onDevice('')}><X />{t('byDevice.clearDevice', { device: named ?? t('byDevice.thisDevice') })}</Button> : null}
      </div>
      <QueryState query={q}>
        {(d) => d.total === 0 && !filtered ? (
          <EmptyState art="no-findings" title={t('byDevice.empty')}
            action={<span className="flex flex-wrap justify-center gap-x-4 gap-y-2 text-sm">
              <Link to="/devices" className="text-accent underline underline-offset-4">{t('emptyDevices')}</Link>
              <Link to="/settings/scanning" className="text-accent underline underline-offset-4">{t('emptyScan')}</Link>
            </span>}>
            {t('byDevice.emptyBody')}
          </EmptyState>
        ) : (
          <>
            <p role="status" className="text-sm" data-count="device">{t('byDevice.summary', { count: d.findings, devices: t('byDevice.devices', { count: d.total }) })}</p>
            <DataTable urlKey="by-device" caption={t('byDevice.caption')} data={d.items} columns={columns} pageSize={PAGE_DEFAULT}
              server={{ total: d.total, list, max: PAGE_MAX }} filtered={filtered} onClearFilters={clear} resetPageOn={`${status}|${device}`}
              mobileRow={(c) => <DeviceCardView card={c} narrowed={narrowed} onHandle={setHandling} />} />
          </>
        )}
      </QueryState>
      {handling ? <HandleDialog {...handling} onClose={() => setHandling(null)} /> : null}
    </div>
  )
}
