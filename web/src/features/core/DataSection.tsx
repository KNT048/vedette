import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Download } from 'lucide-react'
import { Notice, PageHeader, Section } from '@/components/common/PageHeader'
import { Card } from '@/components/common/Card'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { DownloadButton } from '@/components/common/DownloadButton'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from '@/components/ui/button'
import { InfoTip } from '@/components/common/InfoTip'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/input'
import { api, ApiError } from '@/lib/api'
import { useMe } from '@/lib/session'
import { resetMockDb } from '@/mocks/db'

/** Sample data exists only in the preview (mock) build; a real box answers 400 sample_unavailable, so the release build does not offer to restore it (issue #244). */
const isPreview = () => import.meta.env.VITE_API_MOCK !== 'off'
import { useAccount, useBoxBackups, useDownloadBackup, useDownloadKey, usePurge, useRestore, useRestoreRun } from './api'
import { useInstallKind, useModuleAvailable } from '@/lib/modules'
import { useScope } from '@/lib/v1'
import { ContainerBackup, InstallPending } from './ContainerOnly'
import { RestoreFile } from './RestoreFile'
import { RestartSlow } from './RestartSlow'
import { useRestartWait } from './useRestartWait'
import type { BoxBackup } from './types'
import { dayOf, fmtDateTime, fmtTime } from '@/lib/format'
import { errMsg, useGate } from './parts'
import { nav } from './util'
import { beginBoxRestart } from './BoxRestarting'
import { LOG_CATEGORIES, logsExportQuery, type LogCategory } from './logCategories'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/input'
import { Select } from '@/components/ui/input'

/** "2026-11-24-0750": the organization's day and time to the minute, so two backups of one day get two names. */
const fileStamp = () => { const now = new Date().toISOString(); return `${dayOf(now)}-${fmtTime(now).replace(':', '')}` }

export default function DataSection() {
  const { t } = useTranslation('core')
  const gate = useGate('admin')
  const me = useMe().data
  const org = me?.org ?? ''
  const install = useInstallKind() // A container-only install has no helper, so no box backups; the customer copies the volume (S-CORE-9)
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const purge = usePurge()
  const [askPurge, setAskPurge] = useState(false)
  const [typed, setTyped] = useState('')
  const [purgeErr, setPurgeErr] = useState<string | null>(null)
  const [askReset, setAskReset] = useState(false)

  const dl = (path: string, filename: string) => ({ path, filename, onSaved: (saved: string) => toast.success(t('data.downloaded', { file: saved })), onError: (e: unknown) => toast.error(errMsg(e, t)) })
  const [day] = useState(() => dayOf(new Date().toISOString())) // today in the organization's zone

  const [picked, setCats] = useState<LogCategory[]>(LOG_CATEGORIES.map((c) => c.id))
  // No AI response log to offer while this build does not offer that module and this box never turned it on
  const noResponse = useScope('response') === 'hidden'
  const shownCats = noResponse ? LOG_CATEGORIES.filter((c) => c.id !== 'response') : LOG_CATEGORIES
  // S-CORE-6: an install that cannot run traps (container-only) has no honeypot hits: the box greys it and leaves it out.
  const noTraps = useModuleAvailable('honeypot') === false
  const cats = picked.filter((c) => !(noTraps && c === 'honeypot') && !(noResponse && c === 'response'))
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [fmt, setFmt] = useState<'json' | 'csv'>('json')
  const logsErr = cats.length === 0 ? t('data.logs.none') : from && to && from > to ? t('data.logs.range') : ''

  async function doPurge() {
    setPurgeErr(null)
    try {
      const r = await purge.mutateAsync({ confirm: typed, password, ...(code.trim() ? { code: code.trim() } : {}) })
      setAskPurge(false)
      beginBoxRestart(r.kept) // says what was not deleted on the waiting page; the box restarts: a full-page wait, then the setup page (A13-4)
    } catch (e) { setPurgeErr(errMsg(e, t)) }
  }
  async function doReset() {
    // Exists only in the mock build; the real backend has no such button. Back to the original sample data and the sample admin sign-in.
    resetMockDb()
    try { await api.post('/core/setup', { sample: true }) } catch (e) { toast.error(errMsg(e, t)); return }
    nav.reload()
  }

  return (
    <>
      <PageHeader title={t('settings.data')} meta={install === 'container' ? t('container.data.meta') : t('data.meta')} info={install === 'container' ? t('container.data.metaInfo') : t('data.metaInfo')} stories={['S-CORE-1']} />
      {install === 'container' ? <ContainerBackup /> : install === 'appliance' ? (
        <>
          <Section id="backup" title={t('data.backup.title')} description={t('data.backup.desc')} info={t('data.backup.info')}>
            <Card className="max-w-3xl">
              <p className="mb-3 text-meta text-muted">{t('data.backup.keepsCopy')}</p>
              <BackupDownload disabled={gate.disabled} title={gate.title} />
              <KeyAside disabled={gate.disabled} title={gate.title} />
            </Card>
          </Section>
          <Section id="restore" title={t('data.restore.title')} description={t('data.restore.desc')} info={t('data.restore.info')}>
            <BoxBackups disabled={gate.disabled} title={gate.title} />
          </Section>
        </>
      ) : <InstallPending />}
      <Section id="export" title={t('data.export.title')} description={t('data.export.desc')} info={t('data.export.info')}>
        <Card className="max-w-3xl"><DownloadButton disabled={gate.disabled} title={gate.title} {...dl('/core/data/export', `vedette-export-${day}.json`)}><Download />{t('data.export.button')}</DownloadButton></Card>
      </Section>
      <Section id="logs-export" title={t('data.logs.title')} description={t('data.logs.desc')} info={<><p>{t('data.logs.info')}</p><p>{t('data.logs.verify')}</p></>} stories={['S-CORE-6']}>
        <Card className="grid max-w-3xl gap-4">
          <fieldset className="grid gap-2">
            <legend className="mb-1 text-sm font-medium">{t('data.logs.categories')}</legend>
            <div className="grid gap-2 sm:grid-cols-2">
              {shownCats.map((c) => (
                <div key={c.id} className="flex items-center gap-2">
                  <Checkbox id={`log-${c.id}`} checked={cats.includes(c.id)} disabled={gate.disabled || (noTraps && c.id === 'honeypot')} onCheckedChange={(on) => setCats((l) => (on ? [...l, c.id] : l.filter((x) => x !== c.id)))} />
                  <Label htmlFor={`log-${c.id}`}>{t(`data.logs.cat.${c.id}`)}{noTraps && c.id === 'honeypot' ? <span className="text-muted"> {t('data.logs.noTraps')}</span> : null}</Label>
                </div>
              ))}
            </div>
          </fieldset>
          <div className="grid gap-3 sm:grid-cols-3">
            <Field label={t('data.logs.from')} htmlFor="log-from"><Input id="log-from" type="date" value={from} onChange={(e) => setFrom(e.target.value)} disabled={gate.disabled} /></Field>
            <Field label={t('data.logs.to')} htmlFor="log-to"><Input id="log-to" type="date" value={to} onChange={(e) => setTo(e.target.value)} disabled={gate.disabled} /></Field>
            <Field label={t('data.logs.format')} htmlFor="log-format"><Select id="log-format" value={fmt} onChange={(e) => setFmt(e.target.value as 'json' | 'csv')} disabled={gate.disabled}><option value="json">JSON</option><option value="csv">CSV</option></Select></Field>
          </div>
          {logsErr ? <p role="alert" className="text-sm text-danger">{logsErr}</p> : null}
          <div><DownloadButton disabled={gate.disabled || !!logsErr} title={gate.title} {...dl(`/core/logs/export?${logsExportQuery(cats, fmt, from, to)}`, `vedette-logs-${day}.${fmt}`)}><Download />{t('data.logs.button')}</DownloadButton></div>
        </Card>
      </Section>
      <Section id="purge" title={t('data.purge.title')} description={t('data.purge.desc')} info={t('data.purge.info')}>
        <Card className="max-w-3xl"><Button variant="danger" disabled={gate.disabled} title={gate.title} onClick={() => { setPurgeErr(null); setTyped(''); setPassword(''); setCode(''); setAskPurge(true) }}>{t('data.purge.button')}</Button></Card>
      </Section>
      {isPreview() ? (
        <Section title={t('data.sample.title')} description={t('data.sample.desc')} info={t('data.sample.info')}>
          <Card className="max-w-3xl"><Button disabled={gate.disabled} title={gate.title} onClick={() => setAskReset(true)}>{t('data.sample.button')}</Button></Card>
        </Section>
      ) : null}

      <Dialog open={askPurge} onOpenChange={setAskPurge}>
        <DialogContent title={t('data.purge.ask.title')} description={t('data.purge.ask.body')} info={<><p>{t('data.purge.ask.info')}</p><p>{t('data.purge.ask.keeps')}</p></>}>
          <p className="text-sm">{t('data.purge.ask.removes')}</p>
          <Field label={t('data.purge.ask.type', { org })} htmlFor="purge-confirm" error={purgeErr ?? undefined}>
            <Input id="purge-confirm" autoComplete="off" value={typed} aria-invalid={!!purgeErr} onChange={(e) => setTyped(e.target.value)} />
          </Field>
          <Field label={t('data.purge.ask.password')} htmlFor="purge-password">
            <Input id="purge-password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
          {me?.twofa ? (
            <Field label={t('data.purge.ask.code')} htmlFor="purge-code" hint={me.twofa_method === 'email' ? t('data.purge.ask.codeEmail') : t('data.purge.ask.codeApp')}>
              <Input id="purge-code" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} />
            </Field>
          ) : null}
          <DialogFooter>
            <Button onClick={() => setAskPurge(false)}>{t('common:cancel')}</Button>
            <Button variant="danger" disabled={typed !== org || !password} busy={purge.isPending} busyLabel={t('common:busy.deleting')} onClick={() => void doPurge()}>{t('data.purge.ask.confirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {isPreview() ? (
        <Dialog open={askReset} onOpenChange={setAskReset}>
          <DialogContent title={t('data.sample.ask.title')} description={t('data.sample.ask.body')} info={t('data.sample.ask.info')}>
            <DialogFooter><Button onClick={() => setAskReset(false)}>{t('common:cancel')}</Button><Button variant="danger" onClick={() => void doReset()}>{t('data.sample.ask.confirm')}</Button></DialogFooter>
          </DialogContent>
        </Dialog>
      ) : null}
    </>
  )
}

/** Download backup (S-CORE-1): a dialog that offers a password, on by default. With one the box encrypts the file as it sends
 * it (age, .tar.gz.age) and puts the decryption key inside it, so a new box gets every saved secret back and a copy left on a
 * laptop or a share gives nothing away; the dialog says plainly that a lost password
 * cannot be recovered. Without one it says what the plain file holds. The box makes a full backup before the first byte comes
 * (up to a minute on a large box): the dialog stays open and says so meanwhile, then the new Manual row shows in the list. */
function BackupDownload({ disabled, title }: { disabled: boolean; title?: string }) {
  const { t } = useTranslation('core')
  const qc = useQueryClient()
  const dl = useDownloadBackup()
  const [open, setOpen] = useState(false)
  const [protect, setProtect] = useState(true)
  const [password, setPassword] = useState('')
  const [again, setAgain] = useState('')
  const [errors, setErrors] = useState<{ password?: string; again?: string; form?: string }>({})
  function start() { setProtect(true); setPassword(''); setAgain(''); setErrors({}); setOpen(true) }
  async function save() {
    const e: typeof errors = {}
    if (protect) {
      if ([...password].length < 12) e.password = t('data.backup.ask.short')
      else if (again !== password) e.again = t('data.backup.ask.mismatch')
    }
    setErrors(e)
    if (Object.keys(e).length) return
    try {
      const file = await dl.mutateAsync({ filename: `vedette-backup-${fileStamp()}.tar.gz${protect ? '.age' : ''}`, ...(protect ? { password } : {}) })
      setOpen(false)
      setPassword(''); setAgain('')
      toast.success(t('data.backup.done', { file }))
      void qc.invalidateQueries({ queryKey: ['core', 'backups'] })
    } catch (err) {
      setErrors(err instanceof ApiError && err.code === 'weak_password' ? { password: errMsg(err, t) } : { form: errMsg(err, t) })
    }
  }
  return (
    <>
      <Button id="backup-download" disabled={disabled} title={title} onClick={start}><Download />{t('data.backup.button')}</Button>
      <Dialog open={open} onOpenChange={(o) => { if (!dl.isPending) setOpen(o) }}>
        <DialogContent title={t('data.backup.ask.title')} description={t('data.backup.ask.body')} info={t('data.backup.info')}>
          <div className="flex items-start gap-2">
            <Checkbox id="backup-protect" checked={protect} disabled={dl.isPending} onCheckedChange={(on) => { setProtect(on === true); setErrors({}) }} className="mt-0.5" />
            <Label htmlFor="backup-protect">{t('data.backup.ask.protect')}</Label>
          </div>
          {protect ? (
            <>
              <Field label={t('data.backup.ask.password')} hint={t('data.backup.ask.passwordHint')} htmlFor="backup-password" error={errors.password}>
                <Input id="backup-password" type="password" autoComplete="new-password" value={password} aria-invalid={!!errors.password} disabled={dl.isPending} onChange={(e) => setPassword(e.target.value)} />
              </Field>
              <Field label={t('data.backup.ask.again')} htmlFor="backup-again" error={errors.again}>
                <Input id="backup-again" type="password" autoComplete="new-password" value={again} aria-invalid={!!errors.again} disabled={dl.isPending} onChange={(e) => setAgain(e.target.value)} />
              </Field>
              <p className="text-meta">{t('data.backup.ask.carriesKey')}</p>
              <Notice tone="warn" role="note" className="mb-0" title={t('data.backup.ask.lostTitle')}>{t('data.backup.ask.lost')}</Notice>
              <p className="text-meta text-muted">{t('data.backup.ask.how')}</p>
            </>
          ) : (
            <Notice tone="warn" role="note" className="mb-0" title={t('data.backup.plainTitle')}>{t('data.backup.plain')}</Notice>
          )}
          {errors.form ? <p role="alert" className="text-sm text-danger">{errors.form}</p> : null}
          <BusyNote busy={dl.isPending}>{t('data.backup.preparing')}</BusyNote>
          <DialogFooter>
            <Button disabled={dl.isPending} onClick={() => setOpen(false)}>{t('common:cancel')}</Button>
            <Button variant="primary" busy={dl.isPending} busyLabel={t('data.backup.ask.busy')} onClick={() => void save()}><Download />{t('data.backup.ask.confirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}

/** Backups the helper keeps on the box and Restore (S-CORE-1), and Restore from a file for a backup downloaded earlier: the dialogs say what is replaced and that a copy of the current data is kept first. */
function BoxBackups({ disabled, title }: { disabled: boolean; title?: string }) {
  const { t } = useTranslation('core')
  const list = useBoxBackups()
  const runQ = useRestoreRun()
  const run = runQ.data
  // Vedette restarts during the run: the shared waiting rule says when it is back, and takes the person to sign in when the
  // restored data does not know this browser's session (the restore is over then).
  const wait = useRestartWait(run?.status === 'running', runQ.error, 'restore')
  const restore = useRestore()
  const me = useMe().data
  const [pick, setPick] = useState<BoxBackup | null>(null)
  const [sure, setSure] = useState(false)
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const running = run?.status === 'running'

  async function doRestore() {
    if (!pick) return
    setErr(null)
    try { await restore.mutateAsync({ backup_id: pick.id, confirm_data_loss: true, password, ...(code.trim() ? { code: code.trim() } : {}) }); setPick(null) } catch (e) { setErr(errMsg(e, t)) }
  }

  if (list.isError) return <p role="alert" className="text-sm text-danger">{errMsg(list.error, t)}</p>
  const rows = list.data?.backups ?? []
  const when = run ? fmtDateTime(run.backup_created_at) : ''
  // The helper keeps the newest 3 Before restore copies in a pool of their own (#458); with 3 already, the new one pushes the oldest out.
  const pre = rows.filter((b) => b.kind === 'pre_restore')
  const pushedOut = pre.length >= 3 ? pre[pre.length - 1] : undefined
  const restoreButton = (b: BoxBackup) => <Button size="sm" disabled={disabled || running} title={title} onClick={() => { setErr(null); setSure(false); setPassword(''); setCode(''); setPick(b) }}>{t('data.restore.button')}</Button>
  const columns: ColumnDef<BoxBackup>[] = [
    { id: 'when', header: t('data.restore.col.when'), accessorFn: (b) => b.created_at, cell: ({ row }) => <span className="whitespace-nowrap">{fmtDateTime(row.original.created_at)}</span> },
    { id: 'kind', header: t('data.restore.col.kind'), accessorFn: (b) => b.kind, cell: ({ row }) => t(`data.restore.kind.${row.original.kind}`) },
    { id: 'size', header: t('data.restore.col.size'), accessorFn: (b) => b.size, cell: ({ row }) => <span className="block text-right tabular-nums">{(row.original.size / 1e6).toFixed(1)} MB</span> },
    { id: 'key', header: t('data.restore.col.key'), accessorFn: (b) => Number(b.includes_key), cell: ({ row }) => (row.original.includes_key ? t('data.restore.withKey') : t('data.restore.withoutKey')) },
    { id: 'restore', header: () => <span className="sr-only">{t('data.restore.button')}</span>, enableSorting: false, accessorFn: () => '', cell: ({ row }) => <div className="text-right">{restoreButton(row.original)}</div> },
  ]
  return (
    <div className="grid gap-3">
      <RestoreFile disabled={disabled || running} title={title} />
      {run ? (
        <p role="status" className={run.status === 'done' || run.status === 'running' ? 'text-sm' : 'text-sm text-danger'}>
          {run.status === 'failed' ? t('data.restore.failed', { error: run.error ?? '' }) : t(`data.restore.${run.status}`, { when })}
        </p>
      ) : null}
      <RestartSlow wait={wait} />
      {list.isSuccess ? (
        <DataTable urlKey="restore-points" data={rows} columns={columns} caption={t('data.restore.title')} pageSize={20} empty={t('data.restore.empty')}
          mobileRow={(b) => (
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="grid gap-0.5"><span className="font-medium">{fmtDateTime(b.created_at)}</span><span className="text-meta text-muted">{t(`data.restore.kind.${b.kind}`)}, {(b.size / 1e6).toFixed(1)} MB, {b.includes_key ? t('data.restore.withKey') : t('data.restore.withoutKey')}</span></div>
              {restoreButton(b)}
            </div>
          )} />
      ) : null}
      {rows.length ? <div className="flex items-center gap-1"><p className="text-meta text-muted">{t('data.restore.keyLine')}</p><InfoTip topic={t('data.restore.col.key')}>{t('data.restore.keyExplained')}</InfoTip></div> : null}
      <Dialog open={pick !== null} onOpenChange={(o) => { if (!o) setPick(null) }}>
        <DialogContent title={t('data.restore.ask.title', { when: pick ? fmtDateTime(pick.created_at) : '' })} description={t('data.restore.ask.lost')} info={t('data.restore.ask.retention')}>
          {/* What happens, in the body: the copy kept first and what restarts; only the retention rule is behind More */}
          <ul className="grid list-disc gap-1 pl-5 text-sm">
            <li>{t('data.restore.ask.kept')}</li>
            <li>{t('data.restore.ask.restart')}</li>
          </ul>
          {pushedOut ? <p className="text-sm">{t('data.restore.ask.pushesOut', { when: fmtDateTime(pushedOut.created_at) })}</p> : null}
          <Field label={t('data.restore.ask.password')} htmlFor="restore-password">
            <Input id="restore-password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
          {me?.twofa ? (
            <Field label={t('data.restore.ask.code')} htmlFor="restore-code" hint={me.twofa_method === 'email' ? t('data.purge.ask.codeEmail') : t('data.purge.ask.codeApp')}>
              <Input id="restore-code" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} />
            </Field>
          ) : null}
          <div className="flex items-center gap-2">
            <Checkbox id="restore-sure" checked={sure} onCheckedChange={(on) => setSure(on === true)} />
            <Label htmlFor="restore-sure">{t('data.restore.ask.understand')}</Label>
          </div>
          {err ? <p role="alert" className="text-sm text-danger">{err}</p> : null}
          <DialogFooter>
            <Button onClick={() => setPick(null)}>{t('common:cancel')}</Button>
            <Button variant="danger" disabled={!sure || !password} busy={restore.isPending} busyLabel={t('common:busy.restoring')} onClick={() => void doRestore()}>{t('data.restore.ask.confirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

/** A13-2: the downloaded backup has no decryption key, so on another box it cannot bring back saved secrets or two-step
 * sign-in. The key is downloaded once, behind the password (and two-step code), to keep apart from the backups. */
function KeyAside({ disabled, title }: { disabled: boolean; title?: string }) {
  const { t } = useTranslation('core')
  const me = useMe().data
  const sso = useAccount().data?.user.sso === true // no Vedette password to confirm with (deferred)
  const key = useDownloadKey()
  const [open, setOpen] = useState(false)
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [err, setErr] = useState<string | null>(null)
  async function save() {
    setErr(null)
    try {
      const file = await key.mutateAsync({ password, ...(code.trim() ? { code: code.trim() } : {}) })
      setOpen(false)
      toast.success(t('data.key.saved', { file }))
    } catch (e) { setErr(errMsg(e, t)) }
  }
  return (
    <div id="backup-key" className="mt-4 grid gap-2 border-t border-rule pt-4">
      <div className="flex items-center gap-1"><p className="text-sm font-medium">{t('data.key.title')}</p><InfoTip topic={t('data.key.title')}>{t('data.key.descInfo')}</InfoTip></div>
      <p className="text-meta text-muted">{t('data.key.desc')}</p>
      {sso ? <div className="flex items-center gap-1"><p className="text-meta">{t('data.key.sso')}</p><InfoTip topic={t('data.key.sso')}>{t('data.key.ssoInfo')}</InfoTip></div> : <div><Button disabled={disabled} title={title} onClick={() => { setErr(null); setPassword(''); setCode(''); setOpen(true) }}><Download />{t('data.key.button')}</Button></div>}
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent title={t('data.key.ask.title')} description={t('data.key.ask.body')} info={t('data.key.ask.info')}>
          <Field label={t('data.restore.ask.password')} htmlFor="key-password">
            <Input id="key-password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
          {me?.twofa ? (
            <Field label={t('data.restore.ask.code')} htmlFor="key-code" hint={me.twofa_method === 'email' ? t('data.key.ask.codeEmail') : t('data.purge.ask.codeApp')}>
              <Input id="key-code" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} />
            </Field>
          ) : null}
          {err ? <p role="alert" className="text-sm text-danger">{err}</p> : null}
          <DialogFooter>
            <Button onClick={() => setOpen(false)}>{t('common:cancel')}</Button>
            <Button variant="primary" disabled={!password} busy={key.isPending} busyLabel={t('common:busy.working')} onClick={() => void save()}>{t('data.key.ask.confirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
