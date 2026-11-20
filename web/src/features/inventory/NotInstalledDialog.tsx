import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { notInstalledText, useNotInstalled } from '@/features/findings/notInstalled'
import { errMsg } from './kinds'
import type { SoftwareLine } from './types'

/** INV-41 (6): the person says a row a scan, SNMP or an agent reported is not installed on the device (one confirmation). It is
 *  kept as an inventory correction while the source reads that row: the row stops matching and its findings close (findings INV-6c);
 *  Clear on the row undoes it, and a read at another version is a new install that Vedette checks. */
export function NotInstalledDialog({ sw, assetId, device, onClose }: { sw: Pick<SoftwareLine, 'id' | 'display' | 'version' | 'kev_cves'> | null; assetId: string; device: string; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const mark = useNotInstalled(assetId)
  if (!sw) return null
  const name = [sw.display, sw.version].filter(Boolean).join(' ')
  const save = () => mark.mark(sw).then((o) => { toast.success(notInstalledText(t, name, device, o)); onClose() }, (e: unknown) => toast.error(errMsg(e)))
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('software.notInstalledTitle', { name, device })} description={t('software.notInstalledBody')} info={t('software.notInstalledBodyInfo')}>
        <DialogFooter>
          <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
          <Button variant="primary" busy={mark.isPending} busyLabel={t('common:busy.saving')} onClick={save}>{t('software.notInstalledConfirm')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
