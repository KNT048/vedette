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
export function VersionDialog({ sw, assetId, onClose }: { sw: Pick<SoftwareView, 'id' | 'display' | 'version'> & Partial<Pick<SoftwareView, 'pkg_version' | 'correction'>> | null; assetId: string; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const act = useDeviceAction(assetId)
  const [value, setValue] = useState(sw?.version ?? '')
  // a package release is shown for a row that carries one (a person's entry of it, or a correction of a reported row)
  const withPkg = !!sw?.pkg_version || !!sw?.correction
  const [pkg, setPkg] = useState(sw?.pkg_version ?? '')
  const [error, setError] = useState<string | null>(null)
  if (!sw) return null
  const save = (e: FormEvent) => {
    e.preventDefault()
    const version = value.trim()
    const release = pkg.trim()
    const pkgChanged = withPkg && release !== (sw.pkg_version ?? '')
    const versionChanged = version !== (sw.version ?? '')
    const done = () => {
      toast.success(pkgChanged && !versionChanged ? (release ? t('software.editedPkg', { name: sw.display, release }) : t('software.editedPkgNone', { name: sw.display }))
        : version ? t('software.edited', { name: sw.display, version }) : t('software.editedNone', { name: sw.display }))
      onClose()
    }
    // what did not change is not sent: an empty field would remove a value the person did not touch
    act.correct.mutate({ sid: sw.id, ...(versionChanged || !pkgChanged ? { version } : {}), ...(pkgChanged ? { pkg_version: release } : {}) }, { onSuccess: done, onError: (er) => setError(errMsg(er)) })
  }
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('software.editTitle', { name: sw.display })} description={t('software.editBody')} info={t('software.editBodyInfo')}>
        <form onSubmit={save} className="grid gap-4" noValidate>
          <Field label={t('add.version')} htmlFor="sw-version" hint={t('add.versionHint')}>
            <Input id="sw-version" value={value} maxLength={40} placeholder={t('add.versionPlaceholder')} aria-describedby="sw-version-hint" onChange={(e) => { setValue(e.target.value); setError(null) }} />
          </Field>
          {withPkg ? (
            <Field label={t('software.pkgVersion')} htmlFor="sw-pkg-version" hint={t('software.pkgVersionHint')}>
              <Input id="sw-pkg-version" value={pkg} maxLength={100} aria-describedby="sw-pkg-version-hint" onChange={(e) => { setPkg(e.target.value); setError(null) }} />
            </Field>
          ) : null}
          {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
          <DialogFooter>
            <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
            <Button type="submit" variant="primary" busy={act.correct.isPending} busyLabel={t('common:busy.saving')}>{t('software.editSave')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
