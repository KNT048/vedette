import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Download } from 'lucide-react'
import { PageHeader, Section } from '@/components/common/PageHeader'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/input'
import { api, download } from '@/lib/api'
import { useMe } from '@/lib/session'
import { resetMockDb } from '@/mocks/db'

/** Sample data exists only in the preview (mock) build; a real box answers 400 sample_unavailable, so the release build does not offer to restore it (issue #244). */
const isPreview = () => import.meta.env.VITE_API_MOCK !== 'off'
import { useQueryClient } from '@tanstack/react-query'
import { useBoxBackups, useDownloadKey, usePurge, useRestore, useRestoreRun } from './api'
import { useInstallKind, useModuleAvailable } from '@/lib/modules'
import { ContainerBackup, InstallPending } from './ContainerOnly'
import type { BoxBackup } from './types'
import { fmtDateTime } from '@/lib/format'
import { errMsg, useGate } from './parts'
import { nav } from './util'
import { LOG_CATEGORIES, logsExportQuery, type LogCategory } from './logCategories'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/input'
import { Select } from '@/components/ui/input'

export default function DataSection() {
  const { t } = useTranslation('core')
  const gate = useGate('admin')
  const me = useMe().data
  const org = me?.org ?? ''
  const install = useInstallKind() // D-381: a container-only install has no helper, so no box backups; the customer copies the volume (S-CORE-9 G2)
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [kept, setKept] = useState<string[] | null>(null) // set once the purge is done and something could not be deleted
  const qc = useQueryClient()
  const purge = usePurge()
  const [askPurge, setAskPurge] = useState(false)
  const [typed, setTyped] = useState('')
  const [purgeErr, setPurgeErr] = useState<string | null>(null)
  const [askReset, setAskReset] = useState(false)

  const dl = (path: string, file: string) => () => void download(path, file).then((saved) => toast.success(t('data.downloaded', { file: saved }))).catch((e) => toast.error(errMsg(e, t)))
  const [day] = useState(() => new Date().toISOString().slice(0, 10))

  const [picked, setCats] = useState<LogCategory[]>(LOG_CATEGORIES.map((c) => c.id))
  // S-CORE-6 (walk 4): an install that cannot run traps (container-only, D-381) has no honeypot hits: the box greys it and leaves it out.
  const noTraps = useModuleAvailable('honeypot') === false
  const cats = noTraps ? picked.filter((c) => c !== 'honeypot') : picked
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [fmt, setFmt] = useState<'json' | 'csv'>('json')
  const logsErr = cats.length === 0 ? t('data.logs.none') : from && to && from > to ? t('data.logs.range') : ''

  async function doPurge() {
    setPurgeErr(null)
    try {
      const r = await purge.mutateAsync({ confirm: typed, password, ...(code.trim() ? { code: code.trim() } : {}) })
      setAskPurge(false)
      qc.clear()
      if (r.kept.length > 0) { setKept(r.kept); return } // say what was not deleted before leaving the page
      nav.toSetup() // hộp về trạng thái mới cài: tải lại ở màn cài đặt ban đầu
    } catch (e) { setPurgeErr(errMsg(e, t)) }
  }
  async function doReset() {
    // Chỉ có ở bản chạy trên mock; backend thật không có nút này. Về dữ liệu mẫu nguyên bản và đăng nhập lại quản trị mẫu.
    resetMockDb()
    try { await api.post('/core/setup', { sample: true }) } catch (e) { toast.error(errMsg(e, t)); return }
    nav.reload()
  }

  return (
    <>
      <PageHeader title={t('data.title')} meta={install === 'container' ? t('container.data.meta') : t('data.meta')} stories={['S-CORE-1']} />
      {install === 'container' ? <ContainerBackup /> : install === 'appliance' ? (
        <>
          <Section title={t('data.backup.title')} description={t('data.backup.desc')}>
            <Button disabled={gate.disabled} title={gate.title} onClick={dl('/core/data/backup', `vedette-backup-${day}.tar.gz`)}><Download />{t('data.backup.button')}</Button>
            <KeyAside disabled={gate.disabled} title={gate.title} />
          </Section>
          <Section title={t('data.restore.title')} description={t('data.restore.desc')}>
            <BoxBackups disabled={gate.disabled} title={gate.title} />
          </Section>
        </>
      ) : <InstallPending />}
      <Section title={t('data.export.title')} description={t('data.export.desc')}>
        <Button disabled={gate.disabled} title={gate.title} onClick={dl('/core/data/export', `vedette-export-${day}.json`)}><Download />{t('data.export.button')}</Button>
      </Section>
      <Section title={t('data.logs.title')} description={t('data.logs.desc')} stories={['S-CORE-6']}>
        <div className="grid max-w-3xl gap-4">
          <fieldset className="grid gap-2">
            <legend className="mb-1 text-sm font-medium">{t('data.logs.categories')}</legend>
            <div className="grid gap-2 sm:grid-cols-2">
              {LOG_CATEGORIES.map((c) => (
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
          <div><Button disabled={gate.disabled || !!logsErr} title={gate.title} onClick={dl(`/core/logs/export?${logsExportQuery(cats, fmt, from, to)}`, `vedette-logs-${day}.${fmt}`)}><Download />{t('data.logs.button')}</Button></div>
          <p className="text-[13px] text-muted">{t('data.logs.verify')}</p>
        </div>
      </Section>
      <Section title={t('data.purge.title')} description={t('data.purge.desc')}>
        <Button variant="danger" disabled={gate.disabled} title={gate.title} onClick={() => { setPurgeErr(null); setTyped(''); setPassword(''); setCode(''); setAskPurge(true) }}>{t('data.purge.button')}</Button>
      </Section>
      {isPreview() ? (
        <Section title={t('data.sample.title')} description={t('data.sample.desc')}>
          <Button disabled={gate.disabled} title={gate.title} onClick={() => setAskReset(true)}>{t('data.sample.button')}</Button>
        </Section>
      ) : null}

      <Dialog open={askPurge} onOpenChange={setAskPurge}>
        <DialogContent title={t('data.purge.ask.title')} description={t('data.purge.ask.body')}>
          <ul className="list-disc pl-5 text-sm"><li>{t('data.purge.ask.removes')}</li><li>{t('data.purge.ask.keeps')}</li></ul>
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
            <Button variant="danger" disabled={typed !== org || !password || purge.isPending} onClick={() => void doPurge()}>{t('data.purge.ask.confirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={kept !== null} onOpenChange={() => undefined}>
        <DialogContent title={t('data.purge.done.title')} description={t('data.purge.done.body')}>
          <ul className="list-disc pl-5 text-sm">{(kept ?? []).map((k) => <li key={k}>{t(`data.purge.done.kept.${k}`)}</li>)}</ul>
          <DialogFooter><Button variant="danger" onClick={() => nav.toSetup()}>{t('data.purge.done.continue')}</Button></DialogFooter>
        </DialogContent>
      </Dialog>

      {isPreview() ? (
        <Dialog open={askReset} onOpenChange={setAskReset}>
          <DialogContent title={t('data.sample.ask.title')} description={t('data.sample.ask.body')}>
            <DialogFooter><Button onClick={() => setAskReset(false)}>{t('common:cancel')}</Button><Button variant="danger" onClick={() => void doReset()}>{t('data.sample.ask.confirm')}</Button></DialogFooter>
          </DialogContent>
        </Dialog>
      ) : null}
    </>
  )
}

/** Backups the helper keeps on the box and Restore (S-CORE-1, D-377): the dialog says what is replaced and that a copy of the current data is kept first. */
function BoxBackups({ disabled, title }: { disabled: boolean; title?: string }) {
  const { t } = useTranslation('core')
  const list = useBoxBackups()
  const run = useRestoreRun().data
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
  return (
    <div className="grid gap-3">
      {run ? (
        <p role="status" className={run.status === 'done' || run.status === 'running' ? 'text-sm' : 'text-sm text-danger'}>
          {run.status === 'failed' ? t('data.restore.failed', { error: run.error ?? '' }) : t(`data.restore.${run.status}`, { when })}
        </p>
      ) : null}
      {list.isSuccess && rows.length === 0 ? <p className="text-sm text-muted">{t('data.restore.empty')}</p> : null}
      {rows.length > 0 ? (
        <table className="w-full max-w-3xl text-sm">
          <thead><tr className="text-left text-muted"><th className="py-1 font-medium">{t('data.restore.col.when')}</th><th className="font-medium">{t('data.restore.col.kind')}</th><th className="font-medium">{t('data.restore.col.size')}</th><th className="font-medium">{t('data.restore.col.key')}</th><th /></tr></thead>
          <tbody>
            {rows.map((b) => (
              <tr key={b.id} className="border-t border-border">
                <td className="py-1.5">{fmtDateTime(b.created_at)}</td>
                <td>{t(`data.restore.kind.${b.kind}`)}</td>
                <td>{(b.size / 1e6).toFixed(1)} MB</td>
                <td>{b.includes_key ? t('data.restore.withKey') : t('data.restore.withoutKey')}</td>
                <td className="text-right"><Button disabled={disabled || running} title={title} onClick={() => { setErr(null); setSure(false); setPassword(''); setCode(''); setPick(b) }}>{t('data.restore.button')}</Button></td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
      <Dialog open={pick !== null} onOpenChange={(o) => { if (!o) setPick(null) }}>
        <DialogContent title={t('data.restore.ask.title', { when: pick ? fmtDateTime(pick.created_at) : '' })} description={t('data.restore.ask.lost')}>
          <ul className="list-disc pl-5 text-sm">
            <li>{t('data.restore.ask.kept')}</li>
            <li>{t('data.restore.ask.retention')}{pushedOut ? ' ' + t('data.restore.ask.pushesOut', { when: fmtDateTime(pushedOut.created_at) }) : ''}</li>
            <li>{t('data.restore.ask.restart')}</li>
          </ul>
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
            <Button variant="danger" disabled={!sure || !password || restore.isPending} onClick={() => void doRestore()}>{t('data.restore.ask.confirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}

/** A13-2 (D-518): the downloaded backup has no decryption key, so on another box it cannot bring back saved secrets or two-step
 * sign-in. The key is downloaded once, behind the password (and two-step code), to keep apart from the backups. */
function KeyAside({ disabled, title }: { disabled: boolean; title?: string }) {
  const { t } = useTranslation('core')
  const me = useMe().data
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
    <div className="mt-4 grid max-w-3xl gap-2 rounded-md border border-rule bg-sunken p-3">
      <p className="text-sm font-medium">{t('data.key.title')}</p>
      <p className="text-[13px] text-muted">{t('data.key.desc')}</p>
      <div><Button disabled={disabled} title={title} onClick={() => { setErr(null); setPassword(''); setCode(''); setOpen(true) }}><Download />{t('data.key.button')}</Button></div>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent title={t('data.key.ask.title')} description={t('data.key.ask.body')}>
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
            <Button variant="primary" disabled={!password || key.isPending} onClick={() => void save()}>{t('data.key.ask.confirm')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
