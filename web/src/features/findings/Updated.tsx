// "I updated <software>" (D-499, S-MIT-1, item 14): tell Vedette the new version once; the re-match closes what it fixes.
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Button } from '@/components/ui/button'
import { ScanNowButton } from '@/features/scanning/ScanNow'
import { useScanning } from '@/features/scanning/api'
import { scanRefusal } from '@/features/scanning/canScan'
import { useDevices } from '@/features/inventory/api'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/input'
import { ApiError } from '@/lib/api'
import { useCan } from '@/lib/session'
import type { SoftwareView } from '@/features/inventory/types'
import { deviceName, hasIp, isOpen } from './basis'
import { errMsg } from './errors'
import type { FindingAsset, FindingDetail } from './types'
import { softwareFor, useDeviceSoftware, useSetVersion, type Outcome } from './rematch'

const ERRORS = ['bad_version', 'duplicate_software', 'not_manual']

/** What "I updated it" needs of a software row: the finding page passes the row, a To fix action builds it from its own fields. */
export type UpdatedSoftware = Pick<SoftwareView, 'id' | 'display' | 'version' | 'source' | 'kev_cves'>

/**
 * "I updated it" for one software of one device, the one control the finding page and each To fix action use (kien G12): it does
 * what the update needs, never a control with nothing behind it.
 * - Agent-read software: no button; a line says the agent reports the new version by itself and the findings close on their own.
 * - Scan-read software (nmap, scan, SNMP, passive): the button is "Check this device now" itself (POST
 *   /scanning/engines/nmap-discovery/run, admin, the same ScanNowButton as the device page), with its busy state and its result,
 *   where Vedette may scan the device now; elsewhere the reason. Any other source gets nothing.
 * - Typed (manual) software: the version dialog (D-499). `fixed` prefills it (D-488 `fixed`), if known.
 * `active`: an open finding is behind it (kien G5: nothing on what is already closed); the manual button stays while its own dialog is
 * open, so the dialog can say what the re-match closed. `progress`: show the check's progress under the button (the finding page).
 */
export function IUpdated({ asset, software, fixed, size, active = true, progress = true }: { asset: FindingAsset; software: UpdatedSoftware; fixed?: string; size?: 'sm'; active?: boolean; progress?: boolean }) {
  const { t } = useTranslation('findings')
  if (software.source === 'agent') {
    return active ? <p className="text-meta text-muted">{t('updated.agentLine', { device: deviceName(asset, t('removedDevice')) })}</p> : null
  }
  if (SCAN_READ.has(software.source)) return active ? <CheckNow asset={asset} size={size} progress={progress} /> : null
  if (software.source !== 'manual') return null // review r1 of #944: an unknown source is not scan-read: no control with nothing behind it
  return <TypedVersion asset={asset} software={software} fixed={fixed} size={size} active={active} />
}

/** The sources a network check re-reads (review r1 of #944: anything else is not scan-read). */
const SCAN_READ = new Set<string>(['nmap', 'scan', 'snmp', 'passive'])

/** Scan-read software: "Check this device now" itself, only where Vedette may scan the device now (scanning/canScan.ts, the rule
 *  of the device page); otherwise the reason, never a button that can only be refused (G5). */
function CheckNow({ asset, size, progress }: { asset: FindingAsset; size?: 'sm'; progress: boolean }) {
  const { t } = useTranslation('scanning')
  const row = useDevices().data?.items.find((x) => x.id === asset.id)
  const scanning = useScanning().data
  if (!hasIp(asset)) return <p className="text-meta text-muted">{t('selection.device.no_ip')}</p>
  const r = row ? scanRefusal(row, scanning) : null
  if (r) return <p className="text-meta text-muted">{t(`selection.device.${r}`)}</p>
  return <ScanNowButton targets={[asset.id]} size={size} variant="secondary" showProgress={progress} />
}

/** Typed (manual) software: "I updated <software>" and its dialog (D-499): the new version, then what the re-match closed. */
function TypedVersion({ asset, software, fixed, size, active }: { asset: FindingAsset; software: UpdatedSoftware; fixed?: string; size?: 'sm'; active: boolean }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const set = useSetVersion(asset.id)
  const [open, setOpen] = useState(false)
  const [version, setVersion] = useState('')
  const [error, setError] = useState<string | undefined>()
  const [done, setDone] = useState<{ version: string; out: Outcome } | null>(null)
  const device = deviceName(asset, t('removedDevice'))
  const sw = software.display
  const id = `upd-${software.id}`

  function show(v: boolean) {
    if (v) { setVersion(fixed && fixed !== software.version ? fixed : ''); setError(undefined); setDone(null) }
    setOpen(v)
  }
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
    <>
      {active || open ? (
        <Button size={size} disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })} onClick={() => show(true)}>
          {t('updated.button', { software: sw })}
        </Button>
      ) : null}
      <Dialog open={open} onOpenChange={show}>
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
                <Button onClick={() => show(false)}>{t('common:cancel')}</Button>
                <Button variant="primary" busy={set.isPending} busyLabel={t('updated.checking')} onClick={submit}>{t('updated.submit')}</Button>
              </>
            ) : <Button onClick={() => show(false)}>{t('common:close')}</Button>}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

/** The finding page's buttons: one per software the CVE was matched to (usually one); none when Vedette cannot tell which. */
export function IUpdatedFinding({ f }: { f: FindingDetail }) {
  const q = useDeviceSoftware(f.asset?.id)
  if (!f.asset) return null
  const fixed = f.fixed_in?.kind === 'fixed' ? f.fixed_in.fixed : undefined
  return softwareFor(q.data?.asset.software, f.cve).map((s) => <IUpdated key={s.id} asset={f.asset!} software={s} fixed={fixed} active={isOpen(f.status)} />)
}
