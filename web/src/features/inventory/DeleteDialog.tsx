import { useTranslation } from 'react-i18next'
import { Dialog, DialogContent, DialogFooter, DialogClose } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'

/** Confirm removing a device from the inventory (nothing is deleted on the real network). */
export function DeleteDialog({ open, onOpenChange, name, findings, pending, onConfirm }: { open: boolean; onOpenChange: (o: boolean) => void; name: string; findings: number; pending: boolean; onConfirm: () => void }) {
  const { t } = useTranslation('inventory')
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={t('delete.title', { name })} description={<>{t('delete.body')} {t('delete.comesBack')}{findings > 0 ? <strong className="mt-2 block font-medium text-ink">{t('delete.findings', { count: findings })}</strong> : null}</>}
        info={<><p>{t('delete.bodyInfo')}</p>{findings > 0 ? <p>{t('delete.findingsInfo')}</p> : null}</>}>
        <DialogFooter>
          <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
          <Button variant="danger" busy={pending} busyLabel={t('common:busy.deleting')} onClick={onConfirm}>{t('delete.confirm')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
