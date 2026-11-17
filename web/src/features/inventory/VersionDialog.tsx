import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Notice } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/input'
import { useDeviceAction } from './api'
import { errMsg } from './kinds'
import type { SoftwareView } from './types'

/** "Change the version" of software a person declared (edit version); empty removes it. */
export function VersionDialog({ sw, assetId, onClose }: { sw: Pick<SoftwareView, 'id' | 'display' | 'version'> | null; assetId: string; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const act = useDeviceAction(assetId)
  const [value, setValue] = useState(sw?.version ?? '')
  const [error, setError] = useState<string | null>(null)
  if (!sw) return null
  const save = (e: FormEvent) => {
    e.preventDefault()
    const version = value.trim()
    act.setVersion.mutate({ sid: sw.id, version }, {
      onSuccess: () => { toast.success(version ? t('software.edited', { name: sw.display, version }) : t('software.editedNone', { name: sw.display })); onClose() },
      onError: (er) => setError(errMsg(er)),
    })
  }
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('software.editTitle', { name: sw.display })} description={t('software.editBody')} info={t('software.editBodyInfo')}>
        <form onSubmit={save} className="grid gap-4" noValidate>
          <Field label={t('add.version')} htmlFor="sw-version" hint={t('add.versionHint')}>
            <Input id="sw-version" value={value} maxLength={40} placeholder={t('add.versionPlaceholder')} aria-describedby="sw-version-hint" onChange={(e) => { setValue(e.target.value); setError(null) }} />
          </Field>
          {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
          <DialogFooter>
            <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
            <Button type="submit" variant="primary" busy={act.setVersion.isPending} busyLabel={t('common:busy.saving')}>{t('software.editSave')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
