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
import { useQueryClient } from '@tanstack/react-query'
import { usePurge } from './api'
import { errMsg, useGate } from './parts'
import { nav } from './util'
import { LOG_CATEGORIES, type LogCategory } from './logCategories'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/input'
import { Select } from '@/components/ui/input'

export default function DataSection() {
  const { t } = useTranslation('core')
  const gate = useGate('admin')
  const me = useMe().data
  const org = me?.org ?? ''
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [kept, setKept] = useState<string[] | null>(null) // set once the purge is done and something could not be deleted
  const qc = useQueryClient()
  const purge = usePurge()
  const [askPurge, setAskPurge] = useState(false)
  const [typed, setTyped] = useState('')
  const [purgeErr, setPurgeErr] = useState<string | null>(null)
  const [askReset, setAskReset] = useState(false)

  const dl = (path: string, file: string) => () => void download(path, file).then(() => toast.success(t('data.downloaded', { file }))).catch((e) => toast.error(errMsg(e, t)))
  const [day] = useState(() => new Date().toISOString().slice(0, 10))

  const [cats, setCats] = useState<LogCategory[]>(LOG_CATEGORIES.map((c) => c.id))
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [fmt, setFmt] = useState<'json' | 'csv'>('json')
  const logsErr = cats.length === 0 ? t('data.logs.none') : from && to && from > to ? t('data.logs.range') : ''
  const logsQuery = () => { const q = new URLSearchParams({ categories: cats.join(','), format: fmt }); if (from) q.set('from', new Date(`${from}T00:00:00`).toISOString()); if (to) q.set('to', new Date(`${to}T23:59:59.999`).toISOString()); return q.toString() }

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
      <PageHeader title={t('data.title')} meta={t('data.meta')} stories={['S-CORE-1']} />
      <Section title={t('data.backup.title')} description={t('data.backup.desc')}>
        <Button disabled={gate.disabled} title={gate.title} onClick={dl('/core/data/backup', `vedette-backup-${day}.json`)}><Download />{t('data.backup.button')}</Button>
      </Section>
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
                  <Checkbox id={`log-${c.id}`} checked={cats.includes(c.id)} disabled={gate.disabled} onCheckedChange={(on) => setCats((l) => (on ? [...l, c.id] : l.filter((x) => x !== c.id)))} />
                  <Label htmlFor={`log-${c.id}`}>{t(`data.logs.cat.${c.id}`)}</Label>
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
          <div><Button disabled={gate.disabled || !!logsErr} title={gate.title} onClick={dl(`/core/logs/export?${logsQuery()}`, `vedette-logs-${day}.${fmt}`)}><Download />{t('data.logs.button')}</Button></div>
          <p className="text-[13px] text-muted">{t('data.logs.verify')}</p>
        </div>
      </Section>
      <Section title={t('data.purge.title')} description={t('data.purge.desc')}>
        <Button variant="danger" disabled={gate.disabled} title={gate.title} onClick={() => { setPurgeErr(null); setTyped(''); setPassword(''); setCode(''); setAskPurge(true) }}>{t('data.purge.button')}</Button>
      </Section>
      <Section title={t('data.sample.title')} description={t('data.sample.desc')}>
        <Button disabled={gate.disabled} title={gate.title} onClick={() => setAskReset(true)}>{t('data.sample.button')}</Button>
      </Section>

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

      <Dialog open={askReset} onOpenChange={setAskReset}>
        <DialogContent title={t('data.sample.ask.title')} description={t('data.sample.ask.body')}>
          <DialogFooter><Button onClick={() => setAskReset(false)}>{t('common:cancel')}</Button><Button variant="danger" onClick={() => void doReset()}>{t('data.sample.ask.confirm')}</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
