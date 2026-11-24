import { useState } from 'react'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { InfoTip } from '@/components/common/InfoTip'
import { Notice } from '@/components/common/PageHeader'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, Input, Label } from '@/components/ui/input'
import { ApiError } from '@/lib/api'
import type { InstallKind } from '@/lib/modules'
import { fmtDateTime } from '@/lib/format'
import { isPasswordProtected, useSetupRestore, useSetupRestoreRun, useUploadBackup } from './api'
import { ContainerBackup } from './ContainerOnly'
import { RestartSlow } from './RestartSlow'
import { useRestartWait } from './useRestartWait'
import { errMsg } from './parts'
import type { BackupUpload } from './types'
import { FILE_INPUT, keyBase64 } from './backupFile'

/**
 * First-run restore from a backup file (S-CORE-1): the setup code, the backup downloaded from Settings → Data and,
 * kept apart, the decryption key file. A password-protected backup carries the key inside it, so the key file is not asked
 * for unless the box says this one did not (key_included). Check the backup uploads it and the box says what it holds;
 * without the key the page says what is lost before Restore is possible; Restore follows the run across Vedette's restart to the sign-in page.
 * It is reached from the Account step of setup, after the terms of use were accepted on the first; the box refuses a
 * restore without that acceptance.
 */
export function SetupRestore({ install, termsAccepted, onBack }: { install?: InstallKind; termsAccepted: boolean; onBack: () => void }) {
  const { t } = useTranslation('core')
  const navigate = useNavigate()
  const qc = useQueryClient()
  const upload = useUploadBackup()
  const restore = useSetupRestore()
  const [code, setCode] = useState('')
  const [file, setFile] = useState<File | null>(null)
  // A backup downloaded with a password (an age file): seen in the file's first bytes, or said by the box (backup_password_required).
  const [locked, setLocked] = useState(false)
  const [backupPassword, setBackupPassword] = useState('')
  const [keyFile, setKeyFile] = useState<File | null>(null)
  const [checked, setChecked] = useState<BackupUpload | null>(null)
  const [sure, setSure] = useState(false)
  const [started, setStarted] = useState(false)
  const [errors, setErrors] = useState<Record<string, string>>({})
  const poll = useSetupRestoreRun(started)
  const run = poll.data
  const finished = run?.status === 'done' || run?.status === 'reverted' || run?.status === 'failed'
  // The shared waiting rule while Vedette restarts (useRestartWait): this read is public, so it never loses a session.
  const wait = useRestartWait(started && !finished, poll.error, 'restore')

  if (install === 'container') {
    return (
      <div className="mt-6 grid gap-4">
        <div className="flex items-center gap-1">
          <p className="text-sm">{t('setup.restore.container')}</p>
          <InfoTip topic={t('setup.restore.title')}>{t('setup.restore.containerInfo')}</InfoTip>
        </div>
        <ContainerBackup />
        <div><Button onClick={onBack}>{t('setup.back')}</Button></div>
      </div>
    )
  }

  async function check() {
    const e: Record<string, string> = {}
    if (!code.trim()) e.code = t('setup.account.codeError')
    if (!file) e.file = t('setup.restore.fileMissing')
    if (locked && !backupPassword) e.password = t('setup.restore.passwordMissing')
    setErrors(e)
    if (Object.keys(e).length || !file) return
    setChecked(null)
    try { setChecked(await upload.mutateAsync({ code, file, ...(locked ? { password: backupPassword } : {}) })) } catch (err) {
      const c = err instanceof ApiError ? err.code : ''
      if (c === 'backup_password_required' || c === 'wrong_backup_password') { setLocked(true); setErrors({ password: errMsg(err, t) }) }
      else setErrors(c === 'invalid_setup_code' ? { code: errMsg(err, t) } : c === 'rate_limited' ? { form: errMsg(err, t) } : { file: errMsg(err, t) })
    }
  }

  async function pick(f: File | null) {
    setFile(f)
    setChecked(null)
    setBackupPassword('')
    setErrors((x) => ({ ...x, file: '', password: '' }))
    setLocked(f ? await isPasswordProtected(f).catch(() => false) : false)
  }

  async function doRestore() {
    if (!checked) return
    setErrors({})
    let key: string | undefined
    if (keyFile && checked.secrets > 0 && !checked.key_included) { // nothing to check a key against: the box keeps its own
      const k = await keyBase64(keyFile)
      if (!k) { setErrors({ key: t('setup.restore.keyBad') }); return }
      key = k
    }
    try {
      await restore.mutateAsync({ setup_code: code.trim(), upload_id: checked.id, accept_terms: termsAccepted, ...(key ? { key } : checked.key_included ? {} : { confirm_without_key: sure }) })
      setStarted(true)
    } catch (err) {
      if (err instanceof ApiError && (err.code === 'invalid_key' || err.code === 'wrong_key')) setErrors({ key: errMsg(err, t) })
      else if (err instanceof ApiError && err.code === 'upload_unknown') { setChecked(null); setErrors({ file: errMsg(err, t) }) }
      else setErrors({ form: errMsg(err, t) })
    }
  }

  if (started) {
    const ended = run?.status === 'reverted' || run?.status === 'failed'
    return (
      <div className="mt-6 grid gap-3" aria-live="polite">
        {run?.status === 'done' ? (
          <>
            <p role="status" className="text-sm">{t('setup.restore.done')}</p>
            <div><Button variant="primary" onClick={() => { void qc.invalidateQueries({ queryKey: ['setup'] }); navigate('/login', { replace: true }) }}>{t('setup.restore.signIn')}</Button></div>
          </>
        ) : ended ? (
          <>
            <p role="alert" className="text-sm text-danger">{run.status === 'reverted' ? t('setup.restore.reverted') : t('setup.restore.failed', { error: run.error ?? '' })}</p>
            <div><Button onClick={() => { setStarted(false); setChecked(null); setFile(null); setSure(false) }}>{t('setup.restore.again')}</Button></div>
          </>
        ) : (
          <>
            <p role="status" className="text-sm">{t('setup.restore.running', { org: checked?.org ?? '' })}</p>
            {/* The restored box may serve a new certificate (box CA): a browser that accepted the old one then fails every poll. */}
            {wait.reconnecting ? <div className="flex items-center gap-1"><p className="text-meta text-muted">{t('setup.restore.reconnect')}</p><InfoTip topic={t('setup.restore.reconnect')}>{t('setup.restore.reconnectInfo')}</InfoTip></div> : null}
            <RestartSlow wait={wait} />
          </>
        )}
      </div>
    )
  }

  // A protected file the box made carries the key: the key file is asked for only when the box says this one did not.
  const carried = checked?.key_included === true
  const askKey = locked ? checked !== null && !carried : true
  const noKeyLoss = !carried && !keyFile && checked !== null && checked.secrets > 0
  return (
    <div className="mt-4 grid gap-4">
      <Field label={t('setup.account.code')} hint={t('setup.account.codeHint')} info={t('setup.account.codeInfoAppliance')} htmlFor="r-code" error={errors.code}>
        <Input id="r-code" autoComplete="off" spellCheck={false} value={code} aria-invalid={!!errors.code} onChange={(e) => setCode(e.target.value)} />
      </Field>
      <Field label={t('setup.restore.file')} hint={t('setup.restore.fileHint')} htmlFor="r-file" error={errors.file}>
        <input id="r-file" type="file" accept=".gz,.tgz,.age,application/gzip" className={FILE_INPUT} aria-invalid={!!errors.file}
          onChange={(e) => void pick(e.target.files?.[0] ?? null)} />
      </Field>
      {locked ? (
        <Field label={t('setup.restore.password')} hint={t('setup.restore.passwordHint')} htmlFor="r-password" error={errors.password}>
          <Input id="r-password" type="password" autoComplete="off" value={backupPassword} aria-invalid={!!errors.password}
            onChange={(e) => { setBackupPassword(e.target.value); setChecked(null) }} />
        </Field>
      ) : null}
      {askKey ? (
        <Field label={t('setup.restore.key')} hint={t('setup.restore.keyHint')} info={t('setup.restore.keyInfo')} htmlFor="r-key" error={errors.key}>
          <input id="r-key" type="file" accept=".key" className={FILE_INPUT} aria-invalid={!!errors.key} onChange={(e) => { setKeyFile(e.target.files?.[0] ?? null); setErrors((x) => ({ ...x, key: '' })) }} />
        </Field>
      ) : locked && !checked ? <p className="text-meta text-muted">{t('setup.restore.keyInsideFile')}</p> : null}
      {askKey && !keyFile ? (
        <Notice tone="warn" role="note" className="mb-0" title={t('setup.restore.noKey.title')}>
          <ul className="list-disc pl-5 text-meta"><li>{t('setup.restore.noKey.secrets')}</li><li>{t('setup.restore.noKey.twofa')}</li></ul>
        </Notice>
      ) : null}
      {checked ? (
        <div role="group" className="grid gap-2 border-y border-rule py-3 text-sm" aria-label={t('setup.restore.checkedLabel')}>
          <p>{t('setup.restore.checked', { org: checked.org, when: fmtDateTime(checked.created_at), users: checked.users })}</p>
          {carried ? <p className="text-meta">{t('setup.restore.keyInside')}</p>
            : keyFile ? <p className="text-meta text-muted">{t(checked.secrets > 0 ? 'setup.restore.withKey' : 'setup.restore.keyNotNeeded')}</p> : null}
          {noKeyLoss ? (
            <>
              <ul className="list-disc pl-5 text-meta">
                <li>{t('setup.restore.lost.secrets', { n: checked.secrets })}</li>
                {checked.twofa_users > 0 ? <li>{t('setup.restore.lost.twofa', { n: checked.twofa_users })}</li> : null}
              </ul>
              {checked.admins_without_key === 0 ? (
                <Notice tone="danger" role="alert" className="mb-0" title={t('setup.restore.lost.noAdmin')} info={t('setup.restore.lost.noAdminInfo')} />
              ) : null}
              <div className="flex items-start gap-2">
                <Checkbox id="r-sure" checked={sure} onCheckedChange={(on) => setSure(on === true)} className="mt-0.5" />
                <Label htmlFor="r-sure">{t('setup.restore.understand')}</Label>
              </div>
            </>
          ) : null}
        </div>
      ) : null}
      {errors.form ? <Notice tone="danger" role="alert" className="mb-0" title={errors.form} /> : null}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Button onClick={onBack} disabled={upload.isPending || restore.isPending}>{t('setup.back')}</Button>
        {checked
          ? <Button variant="primary" disabled={noKeyLoss && !sure} busy={restore.isPending} busyLabel={t('setup.restore.importing')} onClick={() => void doRestore()}>{t('setup.restore.restore')}</Button>
          : <Button variant="primary" busy={upload.isPending} busyLabel={t('setup.restore.checking')} onClick={() => void check()}>{t('setup.restore.check')}</Button>}
      </div>
      <BusyNote busy={upload.isPending}>{t('setup.restore.checkWaiting')}</BusyNote>
      <BusyNote busy={restore.isPending}>{t('setup.restore.importWaiting')}</BusyNote>
    </div>
  )
}
