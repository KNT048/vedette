import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Upload } from 'lucide-react'
import { Notice } from '@/components/common/PageHeader'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Label } from '@/components/ui/input'
import { ApiError } from '@/lib/api'
import { fmtDateTime } from '@/lib/format'
import { useMe } from '@/lib/session'
import { isPasswordProtected, useRestoreFile, useUploadBackupFile } from './api'
import { FILE_INPUT, keyBase64 } from './backupFile'
import { errMsg } from './parts'
import type { DataBackupUpload } from './types'

/**
 * Restore from a file on a set-up box (S-CORE-1): a backup downloaded earlier from Settings → Data, for example after the copies
 * on the box were lost. Check the file uploads it and the box says what it holds (nothing changes yet); a protected file asks
 * for its password first. The saved secrets come back with the key inside a protected file or with this box's own key (a
 * backup of this box); otherwise the dialog says what is lost and takes the key file. Restore then asks what every restore asks
 * (what is replaced, the copy kept first, the current password and two-step code) and the page follows the run.
 */
export function RestoreFile({ disabled, title }: { disabled: boolean; title?: string }) {
  const { t } = useTranslation('core')
  const me = useMe().data
  const upload = useUploadBackupFile()
  const restore = useRestoreFile()
  const [open, setOpen] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [locked, setLocked] = useState(false)
  const [filePassword, setFilePassword] = useState('')
  const [checked, setChecked] = useState<DataBackupUpload | null>(null)
  const [keyFile, setKeyFile] = useState<File | null>(null)
  const [lossOk, setLossOk] = useState(false)
  const [sure, setSure] = useState(false)
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [errors, setErrors] = useState<Record<string, string>>({})
  const busy = upload.isPending || restore.isPending

  function start() {
    setFile(null); setLocked(false); setFilePassword(''); setChecked(null); setKeyFile(null)
    setLossOk(false); setSure(false); setPassword(''); setCode(''); setErrors({})
    setOpen(true)
  }

  async function pick(f: File | null) {
    setFile(f)
    setChecked(null)
    setFilePassword('')
    setErrors({})
    setLocked(f ? await isPasswordProtected(f).catch(() => false) : false)
  }

  async function check() {
    const e: Record<string, string> = {}
    if (!file) e.file = t('setup.restore.fileMissing')
    if (locked && !filePassword) e.filePassword = t('setup.restore.passwordMissing')
    setErrors(e)
    if (Object.keys(e).length || !file) return
    try { setChecked(await upload.mutateAsync({ file, ...(locked ? { password: filePassword } : {}) })) } catch (err) {
      const c = err instanceof ApiError ? err.code : ''
      if (c === 'backup_password_required' || c === 'wrong_backup_password') { setLocked(true); setErrors({ filePassword: errMsg(err, t) }) }
      else if (c === 'not_a_backup' || c === 'schema_newer' || c === 'too_large') setErrors({ file: errMsg(err, t) })
      else setErrors({ form: errMsg(err, t) })
    }
  }

  const keyBack = checked !== null && (checked.key_included || checked.box_key || checked.secrets === 0)
  const askKey = checked !== null && !keyBack
  const loss = askKey && !keyFile

  async function doRestore() {
    if (!checked) return
    setErrors({})
    let key: string | undefined
    if (askKey && keyFile) {
      const k = await keyBase64(keyFile)
      if (!k) { setErrors({ key: t('setup.restore.keyBad') }); return }
      key = k
    }
    try {
      await restore.mutateAsync({ upload_id: checked.id, confirm_data_loss: true, password, ...(code.trim() ? { code: code.trim() } : {}), ...(key ? { key } : loss ? { confirm_without_key: true } : {}) })
      setOpen(false)
    } catch (err) {
      const c = err instanceof ApiError ? err.code : ''
      if (c === 'invalid_key' || c === 'wrong_key') setErrors({ key: errMsg(err, t) })
      else if (c === 'upload_unknown') { setChecked(null); setErrors({ file: errMsg(err, t) }) }
      else if (c === 'wrong_password') setErrors({ password: errMsg(err, t) })
      else if (c === 'code_required' || c === 'invalid_code' || c === 'wrong_code') setErrors({ code: errMsg(err, t) })
      else setErrors({ form: errMsg(err, t) })
    }
  }

  return (
    <>
      <div><Button id="restore-file" disabled={disabled} title={title} onClick={start}><Upload />{t('data.restore.file.button')}</Button></div>
      <Dialog open={open} onOpenChange={(o) => { if (!busy) setOpen(o) }}>
        <DialogContent title={t('data.restore.file.title')} description={t('data.restore.file.desc')} info={t('data.restore.file.info')}>
          <Field label={t('setup.restore.file')} hint={t('setup.restore.fileHint')} htmlFor="rf-file" error={errors.file}>
            <input id="rf-file" type="file" accept=".gz,.tgz,.age,application/gzip" className={FILE_INPUT} aria-invalid={!!errors.file} disabled={busy}
              onChange={(e) => void pick(e.target.files?.[0] ?? null)} />
          </Field>
          {locked ? (
            <Field label={t('setup.restore.password')} hint={t('setup.restore.passwordHint')} htmlFor="rf-file-password" error={errors.filePassword}>
              <Input id="rf-file-password" type="password" autoComplete="off" value={filePassword} aria-invalid={!!errors.filePassword} disabled={busy}
                onChange={(e) => { setFilePassword(e.target.value); setChecked(null) }} />
            </Field>
          ) : null}
          {checked ? (
            <>
              <div role="group" className="grid gap-2 border-y border-rule py-3 text-sm" aria-label={t('setup.restore.checkedLabel')}>
                <p>{t('setup.restore.checked', { org: checked.org, when: fmtDateTime(checked.created_at), users: checked.users })}</p>
                {checked.key_included ? <p className="text-meta">{t('setup.restore.keyInside')}</p>
                  : checked.box_key ? <p className="text-meta">{t('data.restore.file.boxKey')}</p> : null}
                {askKey ? (
                  <>
                    <Field label={t('setup.restore.key')} hint={t('setup.restore.keyHint')} info={t('setup.restore.keyInfo')} htmlFor="rf-key" error={errors.key}>
                      <input id="rf-key" type="file" accept=".key" className={FILE_INPUT} aria-invalid={!!errors.key} disabled={busy} onChange={(e) => { setKeyFile(e.target.files?.[0] ?? null); setErrors((x) => ({ ...x, key: '' })) }} />
                    </Field>
                    {keyFile ? <p className="text-meta text-muted">{t('setup.restore.withKey')}</p> : (
                      <>
                        <ul className="list-disc pl-5 text-meta">
                          <li>{t('setup.restore.lost.secrets', { n: checked.secrets })}</li>
                          {checked.twofa_users > 0 ? <li>{t('setup.restore.lost.twofa', { n: checked.twofa_users })}</li> : null}
                        </ul>
                        {checked.admins_without_key === 0 ? <Notice tone="danger" role="alert" className="mb-0" title={t('setup.restore.lost.noAdmin')} info={t('setup.restore.lost.noAdminInfo')} /> : null}
                        <div className="flex items-start gap-2">
                          <Checkbox id="rf-loss" checked={lossOk} onCheckedChange={(on) => setLossOk(on === true)} className="mt-0.5" />
                          <Label htmlFor="rf-loss">{t('setup.restore.understand')}</Label>
                        </div>
                      </>
                    )}
                  </>
                ) : null}
              </div>
              {/* What every restore replaces and keeps, in the body as for a backup kept on the box */}
              <p className="text-sm">{t('data.restore.ask.lost')}</p>
              <ul className="grid list-disc gap-1 pl-5 text-sm">
                <li>{t('data.restore.ask.kept')}</li>
                <li>{t('data.restore.ask.restart')}</li>
              </ul>
              <Field label={t('data.restore.ask.password')} htmlFor="rf-password" error={errors.password}>
                <Input id="rf-password" type="password" autoComplete="current-password" value={password} aria-invalid={!!errors.password} disabled={busy} onChange={(e) => setPassword(e.target.value)} />
              </Field>
              {me?.twofa ? (
                <Field label={t('data.restore.ask.code')} htmlFor="rf-code" error={errors.code} hint={me.twofa_method === 'email' ? t('data.purge.ask.codeEmail') : t('data.purge.ask.codeApp')}>
                  <Input id="rf-code" inputMode="numeric" autoComplete="one-time-code" value={code} aria-invalid={!!errors.code} disabled={busy} onChange={(e) => setCode(e.target.value)} />
                </Field>
              ) : null}
              <div className="flex items-center gap-2">
                <Checkbox id="rf-sure" checked={sure} onCheckedChange={(on) => setSure(on === true)} />
                <Label htmlFor="rf-sure">{t('data.restore.ask.understand')}</Label>
              </div>
            </>
          ) : null}
          {errors.form ? <p role="alert" className="text-sm text-danger">{errors.form}</p> : null}
          <BusyNote busy={upload.isPending}>{t('setup.restore.checkWaiting')}</BusyNote>
          <BusyNote busy={restore.isPending}>{t('setup.restore.importWaiting')}</BusyNote>
          <DialogFooter>
            <Button disabled={busy} onClick={() => setOpen(false)}>{t('common:cancel')}</Button>
            {checked
              ? <Button variant="danger" disabled={!sure || !password || (loss && !lossOk)} busy={restore.isPending} busyLabel={t('setup.restore.importing')} onClick={() => void doRestore()}>{t('data.restore.ask.confirm')}</Button>
              : <Button variant="primary" busy={upload.isPending} busyLabel={t('setup.restore.checking')} onClick={() => void check()}>{t('data.restore.file.check')}</Button>}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
