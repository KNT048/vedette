// By device (the screen's default tab): one card per device with open findings, the most urgent first; inside, one block per fix
// ("Update OpenSSH 10.2p1 → 10.6: fixes 3 CVEs") with its CVEs, the most severe first, each one click from its finding. A device
// with a finding and no known fix is listed too ("No fix known yet"). The server groups, orders and pages (GET /findings/devices).
// After them, the possible findings by device (Possible.tsx): counted apart, the count line says how many ("· 16 possible").
import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { X } from 'lucide-react'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { ListRow, ListSummary, ListToolbar, RowList } from '@/components/common/ListParts'
import { useListParams } from '@/components/common/listParams'
import { EmptyState, QueryState } from '@/components/common/States'
import { CveList, StatusBadge } from '@/components/common/status'
import { Button } from '@/components/ui/button'
import { useCan } from '@/lib/session'
import { useDeviceCards, usePossibleCounts } from './api'
import { PAGE_DEFAULT, PAGE_MAX } from './contract'
import { HandleDialog, type HandleRow } from './HandleDialog'
import { NotAdded } from './NotAdded'
import { asAsset, FixLink, useDeviceRow, useFixTitle } from './parts'
import { PossibleLink, PossibleSection } from './Possible'
import { StatusFilter } from './StatusFilter'
import type { DeviceCard, DeviceRef, FixBlock } from './types'

export type Handling = { device: DeviceRef; rows: HandleRow[]; fix?: string; software?: string | null; complete?: boolean }

/** One fix of a device, ranked in the order to do them: "1  Update OpenSSH 10.2p1 → 10.6  fixes 3 CVEs  [Exploited]", its CVEs under
 *  it. On the device's own page (`fold`) a fix opens on click. */
function Block({ device, block, rank, narrowed, onHandle, fold = false }: { device: DeviceRef; block: FixBlock; rank: number; narrowed: boolean; onHandle: (h: Handling) => void; fold?: boolean }) {
  const { t } = useTranslation('findings')
  const [open, setOpen] = useState(!fold) // on the device's own page a block opens on click
  const can = useCan('operator')
  const title = useFixTitle()
  const need = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const rows: HandleRow[] = block.findings.map((f) => ({ id: f.id, cve: f.cve, severity: f.severity, status: f.status }))
  const what = title(block.fix, block.software)
  const panel = `block-${`${device.id}-${block.fix.key}`.replace(/[^\w-]/g, '_')}`
  return (
    <ListRow label={what} rank={rank} title={what}
      toggle={fold ? { open, onToggle: () => setOpen((o) => !o), controls: panel, label: t('byDevice.toggleFix', { fix: what }) } : undefined}
      sub={block.fix.kind === 'none_yet' || block.fix.kind === 'unknown' ? t('byDevice.affects', { count: block.findings.length }) : t('byDevice.fixes', { count: block.findings.length })}
      badges={<><StatusBadge code={block.status} /><FixLink fix={block.fix} cve={block.cause} /></>}
      meta={[block.findings.length > 1 ? t('byDevice.cause', { cve: block.cause }) : null]}
      actions={<Button size="sm" disabled={!can} title={need} aria-label={t('byDevice.handleBlockOf', { fix: what, device: device.name })}
        onClick={() => onHandle({ device, rows, fix: block.fix.key, software: block.software?.id ?? null, complete: !narrowed })}>{t('byDevice.handleBlock')}</Button>}>
      {open ? <div id={panel}><CveList rows showStatus label={t('byDevice.cvesOf', { fix: what })}
        items={block.findings.map((f) => ({ cve: f.cve, id: f.id, severity: f.severity, status: f.status, urgency: f.urgency, verification: f.verification, to: `/findings/${encodeURIComponent(f.id)}` }))}
        action={(i) => (
          <Button size="sm" variant="ghost" className="h-7" disabled={!can} title={need} aria-label={t('byDevice.handleOneOf', { cve: i.cve, device: device.name })}
            onClick={() => onHandle({ device, rows: rows.filter((r) => r.id === i.id) })}>{t('byDevice.handleOne')}</Button>
        )} /></div> : null}
    </ListRow>
  )
}

/** One device, ranked by how urgent its findings are: its name line and badge, Add device and Ignore while nobody added it, then
 *  its fix blocks. On the device's own page (`own`) the page already names the device and offers those actions: the card is its
 *  counts and its fix blocks, a list of its own. */
export function DeviceCardView({ card, rank, narrowed, onHandle, own = false }: { card: DeviceCard; rank?: number; narrowed: boolean; onHandle: (h: Handling) => void; own?: boolean }) {
  const { t } = useTranslation('findings')
  const title = useFixTitle()
  const deviceRow = useDeviceRow()
  const [open, setOpen] = useState(false) // By device: a device opens on click, like a fix in By fix
  const counts = t('byDevice.counts', { count: card.findings, cves: card.cves })
  const urgency = (['under_attack', 'exploited', 'public_exploit', 'critical_edge', 'update_recommended'] as const).filter((k) => card.counts[k] > 0).map((k) => t(`common:deviceStatus.${k}`, { count: card.counts[k] })).join(' · ')
  const top = card.blocks[0]
  const panel = `device-${card.device.id.replace(/[^\w-]/g, '_')}`
  const blocks = card.blocks.map((b, i) => <Block key={b.fix.key} device={card.device} block={b} rank={i + 1} narrowed={narrowed} onHandle={onHandle} fold={own} />)
  if (own) {
    return (
      <div className="grid gap-3">
        <ListSummary>{counts}</ListSummary>
        <RowList boxed label={t('byDevice.blocksOf', { device: card.device.name })}>{blocks}</RowList>
      </div>
    )
  }
  return (
    <ListRow label={card.device.name} rank={rank} {...deviceRow(card.device, { status: card.status })}
      toggle={{ open, onToggle: () => setOpen((o) => !o), controls: panel, label: t('byDevice.toggle', { device: card.device.name }) }}
      meta={[<>{counts}{urgency ? <span>{urgency}</span> : null}</>, top ? t('byDevice.worst', { fix: title(top.fix, top.software), cve: top.cause }) : null]}
      actions={!card.device.added && !card.device.ignored ? <NotAdded asset={asAsset(card.device)} findings={card.findings} /> : null}>
      {open ? <RowList id={panel} label={t('byDevice.blocksOf', { device: card.device.name })}>{blocks}</RowList> : null}
    </ListRow>
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
  // a list of cards: the column only names it (the server searches and orders it)
  const columns: ColumnDef<DeviceCard>[] = [{ id: 'device', header: t('byDevice.col') }]
  const offset = list.page * size
  const named = q.data?.items.find((c) => c.device.id === device)?.device.name
  // the possible findings are not searched or filtered by status here: their count is said only with the whole list
  const possibleCounts = usePossibleCounts(device || undefined, !narrowed).data
  const possible = possibleCounts?.possible ?? 0
  const older = possibleCounts?.older_build ?? 0
  return (
    <div className="grid gap-3">
      <ListToolbar search={{ value: raw.q, onChange: (v) => raw.set({ q: v, page: 0 }), label: t('byDevice.search') }}>
        {device ? <Button size="sm" onClick={() => onDevice('')}><X />{t('byDevice.clearDevice', { device: named ?? t('byDevice.thisDevice') })}</Button> : null}
        <StatusFilter />
      </ListToolbar>
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
            <DataTable urlKey="by-device" caption={t('byDevice.caption')} data={d.items} columns={columns} pageSize={PAGE_DEFAULT}
              summary={<>{t('byDevice.summary', { count: d.findings, devices: t('byDevice.devices', { count: d.total }) })}<PossibleLink count={narrowed ? 0 : possible} older={narrowed ? 0 : older} /></>}
              server={{ total: d.total, list, max: PAGE_MAX }} filtered={filtered} onClearFilters={clear} resetPageOn={`${status}|${device}`}
              list={(c) => <DeviceCardView card={c} rank={offset + d.items.indexOf(c) + 1} narrowed={narrowed} onHandle={setHandling} />} />
          </>
        )}
      </QueryState>
      <PossibleSection by="device" device={device} />
      {handling ? <HandleDialog {...handling} onClose={() => setHandling(null)} /> : null}
    </div>
  )
}

