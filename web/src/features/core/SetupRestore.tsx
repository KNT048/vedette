import { useState } from 'react'
import { useNavigate } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Field, Input, Label } from '@/components/ui/input'
import { ApiError } from '@/lib/api'
import type { InstallKind } from '@/lib/modules'
import { fmtDateTime } from '@/lib/format'
import { useSetupRestore, useSetupRestoreRun, useUploadBackup } from './api'
import { ContainerBackup } from './ContainerOnly'
import { errMsg } from './parts'
import type { BackupUpload } from './types'

const FILE_INPUT = 'text-sm file:mr-3 file:h-9 file:cursor-pointer file:rounded-md file:border file:border-rule file:bg-surface file:px-3 file:text-sm'
/** The key file is the 32 bytes of vedette.key; anything over 4 KiB is not one and is not read. */
const MAX_KEY_FILE = 4096

async function keyBase64(f: File): Promise<string | null> {
  if (f.size > MAX_KEY_FILE) return null
  const b = new Uint8Array(await f.arrayBuffer())
  return btoa(String.fromCharCode(...b))
}

/**
 * First-run restore from a backup file (S-CORE-1, D-518): the setup code, the backup downloaded from Settings → Data and,
 * kept apart, the decryption key file. Check the backup uploads it and the box says what it holds; without the key the page
 * says what is lost before Restore is possible; Restore follows the run across Vedette's restart to the sign-in page.
 * It is reached from the Account step of setup, after the terms of use were accepted on the first (D-544); the box refuses a
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
  const [keyFile, setKeyFile] = useState<File | null>(null)
  const [checked, setChecked] = useState<BackupUpload | null>(null)
  const [sure, setSure] = useState(false)
  const [started, setStarted] = useState(false)
  const [errors, setErrors] = useState<Record<string, string>>({})
  const poll = useSetupRestoreRun(started)
  const run = poll.data

  if (install === 'container') {
    return (
      <div className="mt-6 grid gap-4">
        <p className="text-sm">{t('setup.restore.container')}</p>
        <ContainerBackup />
        <div><Button onClick={onBack}>{t('setup.back')}</Button></div>
      </div>
    )
  }

  async function check() {
    const e: Record<string, string> = {}
    if (!code.trim()) e.code = t('setup.account.codeError')
    if (!file) e.file = t('setup.restore.fileMissing')
    setErrors(e)
    if (Object.keys(e).length || !file) return
    setChecked(null)
    try { setChecked(await upload.mutateAsync({ code, file })) } catch (err) {
      setErrors(err instanceof ApiError && err.code === 'invalid_setup_code' ? { code: errMsg(err, t) } : { file: errMsg(err, t) })
    }
  }

  async function doRestore() {
    if (!checked) return
    setErrors({})
    let key: string | undefined
    if (keyFile && checked.secrets > 0) { // nothing to check a key against: the box keeps its own (D-518)
      const k = await keyBase64(keyFile)
      if (!k) { setErrors({ key: t('setup.restore.keyBad') }); return }
      key = k
    }
    try {
      await restore.mutateAsync({ setup_code: code.trim(), upload_id: checked.id, accept_terms: termsAccepted, ...(key ? { key } : { confirm_without_key: sure }) })
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
            {/* The restored box may serve a new certificate (box CA, D-351): a browser that accepted the old one then fails every poll. */}
            {poll.isError ? <p className="text-[13px] text-muted">{t('setup.restore.reconnect')}</p> : null}
          </>
        )}
      </div>
    )
  }

  const noKeyLoss = !keyFile && checked !== null && checked.secrets > 0
  return (
    <div className="mt-4 grid gap-4">
      <Field label={t('setup.account.code')} hint={t('setup.account.codeHintAppliance')} htmlFor="r-code" error={errors.code}>
        <Input id="r-code" autoComplete="off" spellCheck={false} value={code} aria-invalid={!!errors.code} onChange={(e) => setCode(e.target.value)} />
      </Field>
      <Field label={t('setup.restore.file')} hint={t('setup.restore.fileHint')} htmlFor="r-file" error={errors.file}>
        <input id="r-file" type="file" accept=".gz,.tgz,application/gzip" className={FILE_INPUT} aria-invalid={!!errors.file}
          onChange={(e) => { setFile(e.target.files?.[0] ?? null); setChecked(null) }} />
      </Field>
      <Field label={t('setup.restore.key')} hint={t('setup.restore.keyHint')} htmlFor="r-key" error={errors.key}>
        <input id="r-key" type="file" accept=".key" className={FILE_INPUT} aria-invalid={!!errors.key} onChange={(e) => { setKeyFile(e.target.files?.[0] ?? null); setErrors((x) => ({ ...x, key: '' })) }} />
      </Field>
      {!keyFile ? (
        <div className="grid gap-1 rounded-md border border-rule bg-sunken p-3 text-[13px]" role="note">
          <p className="font-medium">{t('setup.restore.noKey.title')}</p>
          <ul className="list-disc pl-5"><li>{t('setup.restore.noKey.secrets')}</li><li>{t('setup.restore.noKey.twofa')}</li></ul>
        </div>
      ) : null}
      {checked ? (
        <div className="grid gap-2 rounded-md border border-rule p-3 text-sm" aria-label={t('setup.restore.checkedLabel')}>
          <p>{t('setup.restore.checked', { org: checked.org, when: fmtDateTime(checked.created_at), users: checked.users })}</p>
          {keyFile ? <p className="text-[13px] text-muted">{t(checked.secrets > 0 ? 'setup.restore.withKey' : 'setup.restore.keyNotNeeded')}</p> : null}
          {noKeyLoss ? (
            <>
              <ul className="list-disc pl-5 text-[13px]">
                <li>{t('setup.restore.lost.secrets', { n: checked.secrets })}</li>
                {checked.twofa_users > 0 ? <li>{t('setup.restore.lost.twofa', { n: checked.twofa_users })}</li> : null}
              </ul>
              {checked.admins_without_key === 0 ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-[13px]">{t('setup.restore.lost.noAdmin')}</p> : null}
              <div className="flex items-start gap-2">
                <Checkbox id="r-sure" checked={sure} onCheckedChange={(on) => setSure(on === true)} className="mt-0.5" />
                <Label htmlFor="r-sure">{t('setup.restore.understand')}</Label>
              </div>
            </>
          ) : null}
        </div>
      ) : null}
      {errors.form ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{errors.form}</p> : null}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Button onClick={onBack} disabled={upload.isPending || restore.isPending}>{t('setup.back')}</Button>
        {checked
          ? <Button variant="primary" disabled={restore.isPending || (noKeyLoss && !sure)} onClick={() => void doRestore()}>{restore.isPending ? t('setup.restore.importing') : t('setup.restore.restore')}</Button>
          : <Button variant="primary" disabled={upload.isPending} onClick={() => void check()}>{upload.isPending ? t('setup.restore.checking') : t('setup.restore.check')}</Button>}
      </div>
    </div>
  )
}
