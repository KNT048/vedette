// "I updated <software>" (S-MIT-1, item 14): tell Vedette the new version once; the re-match closes what it fixes.
import { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { ScanNowButton } from '@/features/scanning/ScanNow'
import { useScanning } from '@/features/scanning/api'
import { scanRefusal } from '@/features/scanning/canScan'
import { useAgentReport, useAskReport, useDevices } from '@/features/inventory/api'
import { fmtDateTime, fmtTime } from '@/lib/format'
import { useModuleEnabled } from '@/lib/modules'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/input'
import { ApiError } from '@/lib/api'
import { useCan } from '@/lib/session'
import type { SoftwareLine } from '@/features/inventory/types'
import { deviceName, hasIp, isOpen } from './basis'
import { errMsg } from './errors'
import type { FindingAsset, FindingDetail } from './types'
import { softwareFor, useDeviceSoftware, useSetVersion, type Outcome } from './rematch'
import { agentNow } from './agentNow'

const ERRORS = ['bad_version', 'duplicate_software', 'not_manual']

/** What "I updated it" needs of a software row: the finding page passes the row. */
export type UpdatedSoftware = Pick<SoftwareLine, 'id' | 'display' | 'version' | 'source' | 'kev_cves'>

/**
 * "I updated it" for one software of one device, the one control the finding page uses: it does
 * what the update needs, never a control with nothing behind it.
 * - Agent-read software (S-MIT-1, agent-intake INV-23): on a device an osquery agent of this box reports, "I updated it: ask the agent
 *   now" (POST /inventory/agents/devices/{id}/report, operator), with its busy state and then the open ask in words; a device only
 *   Wazuh reads gets a line with Vedette's pull interval (Vedette cannot ask Wazuh); otherwise a line that the agent reports by itself.
 *   `os`: the row is the operating system (a Windows cumulative update, a Linux kernel), whose new build shows only after a restart;
 *   an app's new version needs none.
 * - Scan-read software (nmap, scan, SNMP, passive): the button is "Check this device now" itself (POST
 *   /scanning/engines/nmap-discovery/run, admin, the same ScanNowButton as the device page), with its busy state and its result,
 *   where Vedette may scan the device now; elsewhere the reason. Any other source gets nothing.
 * - Typed (manual) software: the version dialog. `fixed` prefills it, if known.
 * `active`: an open finding is behind it (nothing on what is already closed); the manual button stays while its own dialog is
 * open, so the dialog can say what the re-match closed. `progress`: show the check's progress under the button (the finding page).
 * `onTyped`: the page holds the typed version's dialog itself (TypedVersionDialog, where it outlives the row the update closes);
 * the button only opens it.
 */
export function IUpdated({ asset, software, fixed, size, active = true, progress = true, os = false, box = false, onTyped }: { asset: FindingAsset; software: UpdatedSoftware; fixed?: string; size?: 'sm'; active?: boolean; progress?: boolean; os?: boolean; box?: boolean; onTyped?: () => void }) {
  if (software.source === 'agent') return active ? <AgentAsk asset={asset} size={size} os={os} box={box} /> : null
  if (SCAN_READ.has(software.source)) return active ? <CheckNow asset={asset} size={size} progress={progress} /> : null
  if (software.source !== 'manual') return null // #944: an unknown source is not scan-read: no control with nothing behind it
  if (onTyped) return active ? <TypedButton software={software} size={size} onClick={onTyped} /> : null
  return <TypedVersion asset={asset} software={software} fixed={fixed} size={size} active={active} />
}

/** A software row that is the operating system itself, by its inventory vendor and product (agent-intake mapper.go): Windows' own row
 *  ("Windows Server 2025", "Windows 11 23H2", "Windows (build 28000)") or the Linux kernel. Its update shows only after a restart. */
export function isOsSoftware(vendor: string, product: string): boolean {
  const v = vendor.toLowerCase(), p = product.toLowerCase()
  return (v === 'linux' && p === 'kernel') || (v === 'microsoft' && /^windows( server\b| \d|\s*\(build)/.test(p))
}

/** Pull intervals of the Wazuh connection (agent-intake INV-6) in words. */
const WAZUH_EVERY = new Set([5, 15, 60, 360, 1440])

/** Agent-read software (agent-intake INV-23): ask the device's osquery agent now, or say how the new version arrives. */
function AgentAsk({ asset, size, os, box }: { asset: FindingAsset; size?: 'sm'; os: boolean; box: boolean }) {
  const { t } = useTranslation('findings')
  const on = useModuleEnabled('agent-intake')
  const q = useAgentReport(asset.id, on === true)
  const ask = useAskReport(asset.id)
  const can = useCan('operator')
  const device = deviceName(asset, t('removedDevice'))
  // #953: read the state again when a new ask becomes possible, so the button comes back by itself
  const againAt = q.data?.ask_again_at ? Date.parse(q.data.ask_again_at) : NaN
  const { refetch } = q
  useEffect(() => {
    if (!Number.isFinite(againAt)) return undefined
    const id = setTimeout(() => { void refetch() }, Math.max(0, againAt - Date.now()) + 1000)
    return () => clearTimeout(id)
  }, [againAt, refetch])
  // the one check of every "the agent reports" sentence (agentNow): the finding's title and steps
  const now = agentNow(on, q, box)
  if (now === undefined) return null
  const r = q.data
  const line = (key: string, opts: Record<string, string> = {}) => <p className="text-meta text-muted">{t(key, { device, ...opts })}</p>
  // #953: nothing reads the device now (module off, node revoked or pruned, Wazuh disconnected): no promise
  // the box reads its own packages, whether agent-intake is on or not
  if (now === 'box') return line(os ? 'updated.boxLineOs' : 'updated.boxLine')
  if (now === 'none' || !r) return line('updated.noAgentLine')
  if (r.agent === 'wazuh') {
    const m = r.wazuh_interval_minutes ?? 0
    return line(os ? 'updated.wazuhLineOs' : 'updated.wazuhLine', { every: WAZUH_EVERY.has(m) ? t(`updated.every.${m}`) : t('updated.every.other') })
  }
  const seen = fmtDateTime(r.last_seen)
  const again = r.ask_again_at && Date.parse(r.ask_again_at) > Date.now() ? fmtTime(r.ask_again_at) : ''
  if (r.asked_at) {
    // #953: an agent that has not called for a while gets the ask only when it is back
    const key = r.stale ? 'updated.askedStale' : os ? 'updated.askedOs' : 'updated.asked'
    return <p role="status" className="text-meta">{t(key, { device, time: fmtTime(r.asked_at), seen, again: again || fmtTime(r.ask_again_at) })}</p>
  }
  return (
    <div className="flex flex-col gap-1">
      {r.stale ? line('updated.staleLine', { seen }) : null}
      {os ? line('updated.restartFirst') : null}
      <div>
        <Button size={size} variant="secondary" busy={ask.isPending} busyLabel={t('updated.asking')} disabled={!can || !!again}
          title={!can ? t('common:needRole', { role: t('common:role.operator') }) : again ? t('updated.againAt', { time: again }) : undefined} onClick={() => ask.mutate()}>
          {t('updated.ask')}
        </Button>
      </div>
      {again ? line('updated.againAt', { time: again }) : null}
      {ask.error ? <p role="alert" className="text-meta text-danger">{errMsg(ask.error)}</p> : null}
    </div>
  )
}

/** The sources a network check re-reads (#944: anything else is not scan-read). */
const SCAN_READ = new Set<string>(['nmap', 'scan', 'snmp', 'passive'])

/** Scan-read software: "Check this device now" itself, only where Vedette may scan the device now (scanning/canScan.ts, the rule
 *  of the device page); otherwise the reason, never a button that can only be refused. */
export function CheckNow({ asset, size, progress }: { asset: FindingAsset; size?: 'sm'; progress: boolean }) {
  const { t } = useTranslation('scanning')
  const row = useDevices().data?.items.find((x) => x.id === asset.id)
  const scanning = useScanning().data
  if (!hasIp(asset)) return <p className="text-meta text-muted">{t('selection.device.no_ip')}</p>
  const r = row ? scanRefusal(row, scanning) : null
  if (r) return <p className="text-meta text-muted">{t(`selection.device.${r}`)}</p>
  return <ScanNowButton targets={[asset.id]} size={size} variant="secondary" showProgress={progress} />
}

/** Typed (manual) software: "I updated <software>" and its dialog: the new version, then what the re-match closed. */
function TypedVersion({ asset, software, fixed, size, active }: { asset: FindingAsset; software: UpdatedSoftware; fixed?: string; size?: 'sm'; active: boolean }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      {active || open ? <TypedButton software={software} size={size} onClick={() => setOpen(true)} /> : null}
      <TypedVersionDialog asset={asset} software={software} fixed={fixed} open={open} onOpenChange={setOpen} />
    </>
  )
}

/** The "I updated <software>" button of typed software (operator). */
function TypedButton({ software, size, onClick }: { software: UpdatedSoftware; size?: 'sm'; onClick: () => void }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  return (
    <Button size={size} disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })} onClick={onClick}>
      {t('updated.button', { software: software.display })}
    </Button>
  )
}

/** The typed version's dialog: the new version, then what the re-match closed. Each opening starts empty (`fixed` prefills it). */
export function TypedVersionDialog({ asset, software, fixed, open, onOpenChange }: { asset: FindingAsset; software: UpdatedSoftware; fixed?: string; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation('findings')
  const set = useSetVersion(asset.id)
  const prefill = () => (fixed && fixed !== software.version ? fixed : '')
  const [version, setVersion] = useState(() => (open ? prefill() : ''))
  const [error, setError] = useState<string | undefined>()
  const [done, setDone] = useState<{ version: string; out: Outcome } | null>(null)
  const [wasOpen, setWasOpen] = useState(open)
  if (open !== wasOpen) { // a new opening starts from the prefill, with no error and no earlier result
    setWasOpen(open)
    if (open) { setVersion(prefill()); setError(undefined); setDone(null) }
  }
  const device = deviceName(asset, t('removedDevice'))
  const sw = software.display
  const id = `upd-${software.id}`

  function submit() {
    const v = version.trim()
    if (!v) { setError(t('updated.required')); return }
    if (v === (software.version ?? '')) { setError(t('updated.same', { version: v })); return }
    setError(undefined)
    set.mutate({ sid: software.id, version: v, cves: software.kev_cves }, {
      onSuccess: (out) => setDone({ version: v, out }),
      onError: (e) => setError(e instanceof ApiError && ERRORS.includes(e.code) ? t(`updated.${e.code}`, { software: sw, version: v, device }) : errMsg(e)),
    })
  }

  let result = ''
  if (done) {
    const { closed, still, settled } = done.out
    result = [
      t('updated.saved', { version: done.version }),
      settled ? (closed ? t('updated.closed', { count: closed, device }) : t('updated.closedNone', { device })) : t('updated.pending'),
      settled ? (still ? t('updated.still', { count: still }) : t('updated.stillNone')) : '',
    ].filter(Boolean).join(' ')
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={t('updated.title', { software: sw })} description={t('updated.description', { device })} info={t('updated.descriptionInfo', { software: sw })}>
        {done ? (
          <p role="status" className="text-sm">{result}</p>
        ) : (
          <Field htmlFor={id} label={t('updated.version')} error={error}
            hint={software.version ? t('updated.current', { version: software.version }) : t('updated.noCurrent')}>
            <Input id={id} value={version} maxLength={40} className="w-48" onChange={(e) => { setVersion(e.target.value); setError(undefined) }}
              onKeyDown={(e) => { if (e.key === 'Enter') submit() }} aria-invalid={!!error} aria-describedby={error ? `${id}-error` : `${id}-hint`} />
          </Field>
        )}
        <DialogFooter>
          {!done ? (
            <>
              <Button onClick={() => onOpenChange(false)}>{t('common:cancel')}</Button>
              <Button variant="primary" busy={set.isPending} busyLabel={t('updated.checking')} onClick={submit}>{t('updated.submit')}</Button>
            </>
          ) : <Button onClick={() => onOpenChange(false)}>{t('common:close')}</Button>}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** The finding page's buttons: one per software the CVE was matched to (usually one); none when Vedette cannot tell which. */
export function IUpdatedFinding({ f }: { f: FindingDetail }) {
  const q = useDeviceSoftware(f.asset?.id)
  if (!f.asset) return null
  const fixed = f.fixed_in?.kind === 'fixed' ? f.fixed_in.fixed : undefined
  return softwareFor(q.data?.asset.software, f.cve).map((s) => <IUpdated key={s.id} asset={f.asset!} software={s} fixed={fixed} active={isOpen(f.status)} os={isOsSoftware(s.vendor, s.product)} box={!!q.data?.asset.is_box} />)
}
