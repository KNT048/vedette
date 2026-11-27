import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Notice } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/input'
import { ApiError } from '@/lib/api'
import { useDeviceAction } from './api'
import { errMsg } from './kinds'
import type { SoftwareLine } from './types'

/** "Change the version" of software a person declared (edit version); empty removes it. One value is asked, by what the line is: a
 *  distribution package also takes its package release (as the package manager shows it), anything else the version as the vendor
 *  writes it. What the person gives is checked against the device: a version the device itself states otherwise is said back once
 *  (409 contradicts_device) and kept only with "Save anyway"; an entry that changes nothing says so. */
export function VersionDialog({ sw, assetId, onClose }: { sw: Pick<SoftwareLine, 'id' | 'display' | 'version'> & Partial<Pick<SoftwareLine, 'pkg_version' | 'correction' | 'package_line'>> | null; assetId: string; onClose: () => void }) {
  const { t } = useTranslation('inventory')
  const act = useDeviceAction(assetId)
  const [value, setValue] = useState(sw?.version ?? '')
  // the package release only on a distribution package (the server says which: package_line); a line read before that field keeps
  // the box when it carries a release
  const withPkg = sw?.package_line ?? !!sw?.pkg_version
  const [pkg, setPkg] = useState(sw?.pkg_version ?? '')
  const [error, setError] = useState<string | null>(null)
  const [conflict, setConflict] = useState<string | null>(null)
  if (!sw) return null
  const send = (confirm: boolean) => {
    const version = value.trim()
    const release = pkg.trim()
    const pkgChanged = withPkg && release !== (sw.pkg_version ?? '')
    const versionChanged = version !== (sw.version ?? '')
    const done = (r: { changed?: boolean }) => {
      if (r.changed === false) toast.info(t('software.nothingChanged', { name: sw.display }))
      else toast.success(pkgChanged && !versionChanged ? (release ? t('software.editedPkg', { name: sw.display, release }) : t('software.editedPkgNone', { name: sw.display }))
        : version ? t('software.edited', { name: sw.display, version }) : t('software.editedNone', { name: sw.display }))
      onClose()
    }
    const failed = (er: unknown) => {
      if (er instanceof ApiError && er.code === 'contradicts_device') setConflict(er.message)
      else setError(errMsg(er))
    }
    // what did not change is not sent: an empty field would remove a value the person did not touch
    act.correct.mutate({ sid: sw.id, ...(versionChanged || !pkgChanged ? { version } : {}), ...(pkgChanged ? { pkg_version: release } : {}), ...(confirm ? { confirm: true } : {}) },
      { onSuccess: done, onError: failed })
  }
  const save = (e: FormEvent) => {
    e.preventDefault()
    send(false)
  }
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('software.editTitle', { name: sw.display })} description={t('software.editBody')} info={t('software.editBodyInfo')}>
        <form onSubmit={save} className="grid gap-4" noValidate>
          <Field label={t('add.version')} htmlFor="sw-version" hint={withPkg ? t('add.versionHint') : t('software.versionVendorHint')}>
            <Input id="sw-version" value={value} maxLength={40} placeholder={t('add.versionPlaceholder')} aria-describedby="sw-version-hint" onChange={(e) => { setValue(e.target.value); setError(null); setConflict(null) }} />
          </Field>
          <p className="text-meta text-muted">{t('software.newerWins')}</p>
          {withPkg ? (
            <Field label={t('software.pkgVersion')} htmlFor="sw-pkg-version" hint={t('software.pkgVersionHint')}>
              <Input id="sw-pkg-version" value={pkg} maxLength={100} aria-describedby="sw-pkg-version-hint" onChange={(e) => { setPkg(e.target.value); setError(null); setConflict(null) }} />
            </Field>
          ) : null}
          {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
          {conflict ? (
            <Notice tone="warn" role="alert" className="mb-0" title={conflict}
              actions={<Button size="sm" onClick={() => send(true)} busy={act.correct.isPending} busyLabel={t('common:busy.saving')}>{t('software.saveAnyway')}</Button>} />
          ) : null}
          <DialogFooter>
            <DialogClose asChild><Button>{t('common:cancel')}</Button></DialogClose>
            <Button type="submit" variant="primary" busy={act.correct.isPending} busyLabel={t('common:busy.saving')}>{t('software.editSave')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
