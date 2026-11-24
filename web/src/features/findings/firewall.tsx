// Which firewall protects the device of a finding: one rule for the whole "What to do" section, with a confirmed pack and without one.
// The candidates are the devices that act as a firewall or router (their type is set), then the ones the identification rules say are
// most likely one (type still unknown); the device itself is never its own firewall. The first confirmed one is chosen, else the first
// likely one, else the page asks. The person can pick another right on the finding; a likely one can be confirmed there too.
import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { api } from '@/lib/api'
import { actsAs, kindLabel } from '@/lib/deviceTypes'
import { useModuleEnabled } from '@/lib/modules'
import { useCan } from '@/lib/session'
import { AddDialog } from '@/features/inventory/AddDialog'
import { useDeviceAction } from '@/features/inventory/api'
import { nameOf } from '@/features/inventory/nameOf'
import type { DeviceRow, DevicesResponse } from '@/features/inventory/types'
import { errMsg } from './errors'
import type { FindingDetail, FirewallVendor } from './types'

const EDGE = ['firewall', 'router']

export type Wall = {
  id: string
  name: string
  ip: string | null
  /** The type it acts as, or the likely type while its type is unknown. */
  kind: string
  likely: boolean
  /** The firewall tab of a confirmed pack its maker has; null when Vedette does not know the maker or no tab is written for it. */
  vendor: FirewallVendor | null
}

/** The pack tab a device's maker has, from what Vedette reads of it: its maker, model, OS or firmware, and its names. */
export function wallVendor(d: Pick<DeviceRow, 'vendor' | 'model' | 'os' | 'hostname' | 'name'>): FirewallVendor | null {
  const text = [d.vendor?.value, d.model?.value, d.os?.value, d.hostname, d.name].filter(Boolean).join(' ').toLowerCase()
  if (/forti(net|gate|os)/.test(text)) return 'fortigate'
  if (/mikrotik|routeros|routerboard/.test(text)) return 'mikrotik'
  return null
}

/** The candidates in the order of the rule: confirmed firewalls, confirmed routers, then likely ones (the same order inside each). */
export function wallsOf(items: DeviceRow[], self: string | undefined, fallback: string): Wall[] {
  const out: Wall[] = []
  for (const d of items) {
    if (d.id === self) continue
    const confirmed = EDGE.includes(actsAs(d.kind))
    const likely = !confirmed && d.kind === 'unknown' && !!d.guess && EDGE.includes(actsAs(d.guess.kind))
    if (!confirmed && !likely) continue
    out.push({ id: d.id, name: nameOf(d, fallback), ip: d.ip && d.ip !== '—' ? d.ip : null, kind: confirmed ? actsAs(d.kind) : actsAs(d.guess!.kind), likely, vendor: wallVendor(d) })
  }
  const rank = (w: Wall) => (w.likely ? 2 : 0) + (w.kind === 'firewall' ? 0 : 1)
  return out.sort((a, b) => rank(a) - rank(b))
}

const storeKey = (device: string) => `vedette.findings.firewall.${device}`
function remembered(device: string | undefined): string | null {
  if (!device) return null
  try { return window.localStorage.getItem(storeKey(device)) } catch { return null }
}
function remember(device: string | undefined, wall: string) {
  if (!device) return
  try { window.localStorage.setItem(storeKey(device), wall) } catch { /* the choice lasts for this page only */ }
}

/** The firewalls Vedette knows for this finding and the one in front of its device. `ready` is false while the list loads or the
 *  inventory module is off (then nothing is said about the firewall). */
export function useWalls(f: FindingDetail) {
  const { t } = useTranslation('findings')
  const inventoryOn = useModuleEnabled('inventory') !== false
  const q = useQuery({
    queryKey: ['inventory', 'devices', 'firewalls'], enabled: inventoryOn,
    queryFn: () => api.get<DevicesResponse>('/inventory/devices?type=firewall,router,unknown'),
  })
  const walls = q.data ? wallsOf(q.data.items, f.asset?.id, t('removedDevice')) : []
  const [picked, setPicked] = useState<string | null>(() => remembered(f.asset?.id))
  const chosen = walls.find((w) => w.id === picked) ?? walls[0] ?? null
  const choose = (id: string) => { setPicked(id); remember(f.asset?.id, id) }
  // settled: the list answered, failed, or will not be read (inventory off), so the page can pick a tab without changing it after
  return { ready: inventoryOn && q.isSuccess, settled: !inventoryOn || q.isSuccess || q.isError, walls, chosen, choose, refetch: () => void q.refetch() }
}

export type WallsState = ReturnType<typeof useWalls>

/** "Which firewall protects <device>?": the candidates to pick from, a likely one to confirm, or a firewall to add right here. */
export function WallPicker({ f, w }: { f: FindingDetail; w: WallsState }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const needRole = can ? undefined : t('common:needRole', { role: t('common:role.operator') })
  const [adding, setAdding] = useState(false)
  const act = useDeviceAction(w.chosen?.id ?? '')
  const device = f.asset?.name || t('removedDevice')
  if (!w.ready) return null
  const label = (x: Wall) => `${x.name}${x.ip ? ` (${x.ip})` : ''} · ${x.likely ? t('fw.likely', { kind: kindLabel(x.kind) }) : kindLabel(x.kind)}`
  const confirm = (x: Wall) => act.patch.mutate({ kind: x.kind }, {
    onSuccess: () => toast.success(t('fw.confirmed', { name: x.name, kind: kindLabel(x.kind) })),
    onError: (e) => toast.error(errMsg(e)),
  })
  return (
    <div className="grid gap-2" data-testid="firewall-picker">
      {w.walls.length ? (
        <>
          <label htmlFor={`fw-pick-${f.id}`} className="text-sm font-medium">{t('fw.which', { device })}</label>
          <div className="flex flex-wrap items-center gap-2">
            {w.walls.length > 1 ? (
              <select id={`fw-pick-${f.id}`} className="h-9 max-w-full rounded-md border border-rule bg-surface px-2 text-sm" value={w.chosen?.id ?? ''} onChange={(e) => w.choose(e.target.value)}>
                {w.walls.map((x) => <option key={x.id} value={x.id}>{label(x)}</option>)}
              </select>
            ) : (
              <span id={`fw-pick-${f.id}`} className="text-sm">{label(w.walls[0]!)}</span>
            )}
            {w.chosen ? <Link to={`/devices/${encodeURIComponent(w.chosen.id)}`} className="text-sm text-accent underline-offset-4 hover:underline">{t('fw.open')}</Link> : null}
            <Button size="sm" variant="secondary" disabled={!can} title={needRole} onClick={() => setAdding(true)}>{t('fw.addAnother')}</Button>
          </div>
          {w.chosen?.likely ? (
            <div className="flex flex-wrap items-center gap-2 text-meta">
              <span>{t('fw.likelyNote', { name: w.chosen.name, kind: kindLabel(w.chosen.kind) })}</span>
              <Button size="sm" disabled={!can || act.patch.isPending} busy={act.patch.isPending} busyLabel={t('common:busy.saving')} title={needRole} onClick={() => confirm(w.chosen!)}>
                {t('fw.confirm', { kind: kindLabel(w.chosen.kind) })}
              </Button>
            </div>
          ) : null}
        </>
      ) : (
        <div className="flex flex-wrap items-center gap-3">
          <p className="text-sm">{t('fw.none', { device })}</p>
          <Button size="sm" disabled={!can} title={needRole} onClick={() => setAdding(true)}>{t('todo.fwAdd')}</Button>
        </div>
      )}
      {adding ? <AddDialog open onOpenChange={(o) => { if (!o) { setAdding(false); w.refetch() } }} /> : null}
    </div>
  )
}
