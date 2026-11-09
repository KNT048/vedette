import { useTranslation } from 'react-i18next'
import { Dialog, DialogContent, DialogFooter, DialogClose } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'

/** Xác nhận xoá thiết bị khỏi kiểm kê (không xoá thật trên mạng). */
export function DeleteDialog({ open, onOpenChange, name, findings, pending, onConfirm }: { open: boolean; onOpenChange: (o: boolean) => void; name: string; findings: number; pending: boolean; onConfirm: () => void }) {
  const { t } = useTranslation('inventory')
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={t('delete.title', { name })} description={<>{t('delete.body')}{findings > 0 ? <strong className="mt-2 block font-medium text-ink">{t('delete.findings', { count: findings })}</strong> : null}</>}>
        <DialogFooter>
          <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
          <Button variant="danger" disabled={pending} onClick={onConfirm}>{t('delete.confirm')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
