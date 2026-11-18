import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { ErrorState } from '@/components/common/States'
import { Notice } from '@/components/common/PageHeader'
import { kindLabel } from '@/lib/deviceTypes'
import { useApplySnmpSimilar, useSnmpSimilar } from './api'
import { errMsg } from './kinds'
import type { SnmpApplyResponse, SnmpSimilarDevice } from './types'

/**
 * "Use these settings on similar devices": a button for a device whose SNMP works, and the checklist it opens (S-INV-1). The candidates
 * are devices of the same maker (prechecked) or the same type with no SNMP settings of their own; applying copies the settings, secret
 * included, on the box (the browser never sees it) and each device is read only at its own address.
 */
export function SnmpSimilarButton({ id }: { id: string }) {
  const { t } = useTranslation('inventory')
  const [open, setOpen] = useState(false)
  return (
    <>
      <Button size="sm" onClick={() => setOpen(true)}>{t('deviceSnmp.similar.button')}</Button>
      {open ? <SimilarDialog id={id} onClose={() => setOpen(false)} /> : null}
    </>
  )
}

const label = (d: SnmpSimilarDevice) => d.name || d.ip || d.device_id

function SimilarDialog({ id, onClose }: { id: string; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const q = useSnmpSimilar(id, true)
  const apply = useApplySnmpSimilar(id)
  const [picked, setPicked] = useState<Set<string> | null>(null)
  const [done, setDone] = useState<SnmpApplyResponse | null>(null)
  const list = q.data?.devices ?? []
  // prechecked: the devices of the same maker, until the person changes a box
  const on = picked ?? new Set(list.filter((d) => d.same_maker).map((d) => d.device_id))
  const toggle = (dev: string) => setPicked((cur) => { const n = new Set(cur ?? on); if (n.has(dev)) n.delete(dev); else n.add(dev); return n })
  const submit = () => apply.mutate([...on], {
    onSuccess: (r) => {
      setDone(r)
      const ok = r.results.filter((x) => x.ok).length
      if (ok > 0) toast.success(t('deviceSnmp.similar.applied', { count: ok }))
    },
    onError: (e) => toast.error(errMsg(e)),
  })
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('deviceSnmp.similar.title')} description={t('deviceSnmp.similar.description')}>
        {done ? (
          <ul className="grid gap-1.5 text-sm" aria-label={t('deviceSnmp.similar.results')}>
            {done.results.map((r) => (
              <li key={r.device_id}>
                <span className="font-medium">{r.name || r.device_id}</span>{' '}
                {r.ok ? <span>{t('deviceSnmp.similar.saved')}</span> : <span className="text-danger">{r.message}</span>}
              </li>
            ))}
          </ul>
        ) : q.isPending ? <p className="text-meta text-muted">{t('common:loading')}</p>
          : q.error ? <ErrorState error={q.error} onRetry={() => void q.refetch()} />
          : list.length === 0 ? <p className="text-meta text-muted">{t('deviceSnmp.similar.none')}</p>
          : (
            <fieldset className="grid max-h-80 gap-1.5 overflow-y-auto">
              <legend className="sr-only">{t('deviceSnmp.similar.legend')}</legend>
              {list.map((d) => (
                <label key={d.device_id} className="flex items-start gap-2 text-sm">
                  <input type="checkbox" className="mt-1" checked={on.has(d.device_id)} onChange={() => toggle(d.device_id)} />
                  <span className="min-w-0 [overflow-wrap:anywhere]">
                    {label(d)} <span className="text-meta text-muted">{[d.ip, d.vendor, d.kind !== 'unknown' ? kindLabel(d.kind) : ''].filter(Boolean).join(' · ')}</span>
                    {!d.approved ? <span className="block text-meta text-muted">{t('deviceSnmp.similar.notApproved')}</span> : null}
                  </span>
                </label>
              ))}
            </fieldset>
          )}
        {!done && list.length > 0 ? <Notice tone="accent" role="note" className="mb-0" title={t('deviceSnmp.similar.noteTitle')}>{t('deviceSnmp.similar.note')}</Notice> : null}
        <DialogFooter>
          <DialogClose asChild><Button>{done ? t('common:close') : t('common:cancel')}</Button></DialogClose>
          {!done && list.length > 0 ? <Button variant="primary" disabled={on.size === 0} busy={apply.isPending} busyLabel={t('common:busy.saving')} onClick={submit}>{t('deviceSnmp.similar.apply', { count: on.size })}</Button> : null}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
