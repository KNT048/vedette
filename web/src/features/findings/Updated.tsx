// "I updated <software>" (D-499, S-MIT-1, item 14): tell Vedette the new version once; the re-match closes what it fixes.
import { useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { ScanSearch } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/input'
import { ApiError } from '@/lib/api'
import { useCan } from '@/lib/session'
import type { SoftwareView } from '@/features/inventory/types'
import { deviceName, hasIp } from './basis'
import { errMsg } from './errors'
import type { FindingAsset, FindingDetail } from './types'
import { softwareFor, useDeviceSoftware, useSetVersion, type Outcome } from './rematch'

const ERRORS = ['bad_version', 'duplicate_software', 'not_manual']

/** One button and its dialog for one software of one device. `fixed` prefills the version (D-488 `fixed`), if known. */
export function IUpdated({ asset, software, fixed, size }: { asset: FindingAsset; software: SoftwareView; fixed?: string; size?: 'sm' }) {
  const { t } = useTranslation('findings')
  const can = useCan('operator')
  const manual = software.source === 'manual'
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
      <Button size={size} disabled={!can} title={can ? undefined : t('common:needRole', { role: t('common:role.operator') })} onClick={() => show(true)}>
        {manual ? t('updated.button', { software: sw }) : t('updated.buttonScan')}
      </Button>
      <Dialog open={open} onOpenChange={show}>
        <DialogContent title={t('updated.title', { software: sw })} description={manual ? t('updated.description', { device, software: sw }) : undefined}>
          {software.source === 'agent' ? (
            <p className="text-sm">{t('updated.agent', { device })}</p>
          ) : !manual ? (
            <div className="grid gap-3 text-sm">
              <p>{t('updated.scanned', { device })}</p>
              {hasIp(asset) ? (
                <Button asChild variant="primary" className="w-fit"><Link to={`/scans?target=${asset.id}`}><ScanSearch />{t('updated.scan', { device })}</Link></Button>
              ) : <p className="text-[13px] text-muted">{t('evidence.noIpScan')}</p>}
            </div>
          ) : done ? (
            <p role="status" className="text-sm">{result}</p>
          ) : (
            <Field htmlFor={id} label={t('updated.version')} error={error}
              hint={software.version ? t('updated.current', { version: software.version }) : t('updated.noCurrent')}>
              <Input id={id} value={version} maxLength={40} className="w-48" onChange={(e) => { setVersion(e.target.value); setError(undefined) }}
                onKeyDown={(e) => { if (e.key === 'Enter') submit() }} aria-invalid={!!error} aria-describedby={error ? `${id}-error` : `${id}-hint`} />
            </Field>
          )}
          <DialogFooter>
            {manual && !done ? (
              <>
                <Button onClick={() => show(false)}>{t('common:cancel')}</Button>
                <Button variant="primary" disabled={set.isPending} onClick={submit}>{set.isPending ? t('updated.checking') : t('updated.submit')}</Button>
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
  return softwareFor(q.data?.asset.software, f.cve).map((s) => <IUpdated key={s.id} asset={f.asset!} software={s} fixed={fixed} />)
}
