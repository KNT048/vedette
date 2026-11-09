import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Label } from '@/components/ui/input'
import { useDeleteTarget } from './api'
import type { Target } from './types'

const errMsg = (e: unknown) => (e instanceof Error ? e.message : String(e))

/**
 * Remove a public IP (S-EXP-1, D-79). One dialog for the list and for the IP's own page, so both offer the same choice with the same default:
 * "Don't add it again if detected" is ticked, because an address the box uses but that is not the company's must not come back.
 * `target` null = closed. `onDone` runs after the IP is gone (the page of a removed IP goes back to the list).
 */
export function RemoveDialog({ target, onClose, onDone }: { target: Target | null; onClose: () => void; onDone?: () => void }) {
  const { t } = useTranslation('exposure')
  const del = useDeleteTarget()
  const [ignore, setIgnore] = useState(true)
  const [seen, setSeen] = useState<string | null>(null)
  // Reset when the dialog opens for an IP and when it closes, so Cancel followed by Remove on the same IP starts ticked again.
  if ((target?.id ?? null) !== seen) { setSeen(target?.id ?? null); setIgnore(true) }
  return (
    <Dialog open={target !== null} onOpenChange={(o) => { if (!o) onClose() }}>
      {target ? (
        <DialogContent title={t('boxIp.remove.title', { value: target.value })} description={t('boxIp.remove.body')}>
          <div className="flex items-start gap-3">
            <Checkbox id="box-ignore" checked={ignore} onCheckedChange={(v) => setIgnore(v === true)} className="mt-0.5" aria-describedby="box-ignore-hint" />
            <div className="grid gap-1">
              <Label htmlFor="box-ignore" className="font-normal">{t('boxIp.remove.ignoreLabel')}</Label>
              <p id="box-ignore-hint" className="text-[13px] text-muted">{ignore ? t('boxIp.remove.ignoreOn') : t('boxIp.remove.ignoreOff')}</p>
            </div>
          </div>
          <DialogFooter>
            <Button onClick={onClose}>{t('common:cancel')}</Button>
            <Button variant="danger" disabled={del.isPending} onClick={() => { del.mutateAsync({ id: target.id, ignore }).then(() => { toast.success(t(ignore ? 'boxIp.remove.toastIgnored' : 'boxIp.remove.toast', { value: target.value })); onClose(); onDone?.() }, (e: unknown) => toast.error(errMsg(e))) }}>{t('boxIp.remove.confirm')}</Button>
          </DialogFooter>
        </DialogContent>
      ) : null}
    </Dialog>
  )
}
