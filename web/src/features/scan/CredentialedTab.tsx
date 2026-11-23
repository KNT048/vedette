import { useCallback, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Upload } from 'lucide-react'
import { InfoTip } from '@/components/common/InfoTip'
import { Notice, Section } from '@/components/common/PageHeader'
import { CodeBlock } from '@/components/common/CodeBlock'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { EmptyState, QueryState, RequireModule } from '@/components/common/States'
import { Chip } from '@/components/common/StatusChip'
import { BusyNote } from '@/components/common/BusyNote'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Select, Textarea } from '@/components/ui/input'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useAddCred, useCreds, useDelCred, useTargets, useTestCred } from './api'
import { errMsg } from './errors'
import type { CredTarget, ScanTarget } from './types'
import { actsAs } from '@/lib/deviceTypes'

const MAX_KEY = 16 * 1024
/** A credentialed scan over SSH only suits servers: no cameras, printers, switches, workstations. */
/** Devices an SSH login can check: types acting as server, NAS or web (a virtual machine or a hypervisor acts as server). */
const SSH_KINDS = ['server', 'nas', 'web']

function Prepare() {
  const { t } = useTranslation('scan')
  return (
    <details className="rounded-md border border-rule bg-surface px-4 py-3">
      <summary className="cursor-pointer text-sm font-medium">{t('cred.prepare')}</summary>
      <div className="mt-3 grid gap-3">
        <p className="text-meta text-muted">{t('cred.prepareIntro')}</p>
        <CodeBlock label={t('cred.step1')} code={'ssh-keygen -t ed25519 -f vedette_scan_key -C "vedette-scan" -N ""'} />
        <CodeBlock label={t('cred.step2')} code={'sudo adduser --disabled-password --gecos "" vedette-scan'} />
        <CodeBlock label={t('cred.step3')} code={'scp vedette_scan_key.pub <ADMIN-USER>@<TARGET-IP>:/tmp/vedette_scan_key.pub'} />
        <CodeBlock label={t('cred.step4')} code={'sudo mkdir -p /home/vedette-scan/.ssh\nsudo install -m 600 -o vedette-scan -g vedette-scan /tmp/vedette_scan_key.pub /home/vedette-scan/.ssh/authorized_keys\nsudo chown vedette-scan:vedette-scan /home/vedette-scan/.ssh\nsudo chmod 700 /home/vedette-scan/.ssh'} />
        <p className="text-meta text-muted">{t('cred.prepareEnd')}</p>
      </div>
    </details>
  )
}

function AddForm({ options, onDone }: { options: ScanTarget[]; onDone: () => void }) {
  const { t } = useTranslation('scan')
  const can = useCan('admin')
  const add = useAddCred()
  const file = useRef<HTMLInputElement>(null)
  const [asset, setAsset] = useState('')
  const [port, setPort] = useState('22')
  const [user, setUser] = useState('vedette-scan')
  const [key, setKey] = useState('')
  const [fileName, setFileName] = useState('')
  const [error, setError] = useState<string | undefined>()

  async function pick(f: File | undefined) {
    if (!f) return
    if (f.size > MAX_KEY) { setError(t('cred.keyTooBig')); return }
    setKey(await f.text())
    setFileName(f.name)
    setError(undefined)
  }
  function submit(e: React.FormEvent) {
    e.preventDefault()
    setError(undefined)
    if (!asset) { setError(t('cred.pickHost')); return }
    add.mutate({ asset_id: asset, port: Number(port), username: user.trim(), private_key: key }, {
      onSuccess: (c) => { toast.success(t('cred.saved', { last4: c.key_last4 })); setKey(''); setFileName(''); setAsset(''); add.reset(); onDone() },
      onError: (err) => setError(errMsg(err)),
    })
  }
  return (
    <form onSubmit={submit} className="grid gap-4" noValidate>
      <div className="grid gap-4 sm:grid-cols-[1fr_100px]">
        <Field htmlFor="cr-host" label={t('cred.host')}>
          <Select id="cr-host" value={asset} onChange={(e) => setAsset(e.target.value)} disabled={!can}>
            <option value="">{t('cred.hostPlaceholder')}</option>
            {options.map((o) => <option key={o.id} value={o.id}>{o.label} ({o.ip})</option>)}
          </Select>
        </Field>
        <Field htmlFor="cr-port" label={t('cred.port')}><Input id="cr-port" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value)} disabled={!can} /></Field>
        <Field htmlFor="cr-user" label={t('cred.user')}><Input id="cr-user" value={user} onChange={(e) => setUser(e.target.value)} disabled={!can} autoComplete="off" spellCheck={false} /></Field>
      </div>
      <Field htmlFor="cr-key" label={t('cred.key')} hint={t('cred.keyHint')} info={<><p>{t('cred.keyHintInfo')}</p><p>{t('cred.privacy')} {t('cred.privacyInfo')}</p></>}>
        <Textarea id="cr-key" value={key} onChange={(e) => { setKey(e.target.value); setFileName('') }} disabled={!can} autoComplete="off" spellCheck={false} rows={4}
          className="[-webkit-text-security:disc]" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" />
      </Field>
      <div className="flex flex-wrap items-center gap-3">
        <input ref={file} type="file" className="sr-only" tabIndex={-1} aria-label={t('cred.fileInput')} onChange={(e) => void pick(e.target.files?.[0])} />
        <Button size="sm" disabled={!can} onClick={() => file.current?.click()}><Upload />{t('cred.pickFile')}</Button>
        {fileName ? <span className="text-meta text-muted">{t('cred.fileChosen', { name: fileName })}</span> : null}
      </div>
      {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
      <DialogFooter className="items-center">
        {!can ? <span className="text-meta text-muted">{t('common:needRole', { role: t('common:role.admin') })}</span> : null}
        <Button type="button" onClick={onDone}>{t('common:cancel')}</Button>
        <Button type="submit" variant="primary" disabled={!can} busy={add.isPending} busyLabel={t('common:busy.saving')}>{t('cred.save')}</Button>
      </DialogFooter>
    </form>
  )
}

/** The add-a-server button; the form opens in a dialog over the list. */
function AddServer({ options }: { options: ScanTarget[] }) {
  const { t } = useTranslation('scan')
  const can = useCan('admin')
  const [open, setOpen] = useState(false)
  if (!options.length) return (
    <div className="flex max-w-2xl flex-wrap items-center gap-x-1 rounded-md border border-dashed border-rule bg-surface px-4 py-3 text-sm text-muted">
      <span>{t('cred.noHosts')}</span>
      <InfoTip>{t('cred.noHostsInfo')}</InfoTip>
      <Link to="/devices" className="text-accent underline underline-offset-4">{t('start.openDevices')}</Link>
    </div>
  )
  return (
    <div>
      <Button variant="primary" disabled={!can} title={!can ? t('common:needRole', { role: t('common:role.admin') }) : undefined} onClick={() => setOpen(true)}>{t('cred.addTitle')}</Button>
      <Dialog open={open} onOpenChange={setOpen}>
        {open ? <DialogContent title={t('cred.addTitle')}><AddForm options={options} onDone={() => setOpen(false)} /></DialogContent> : null}
      </Dialog>
    </div>
  )
}

function List({ items }: { items: CredTarget[] }) {
  const { t } = useTranslation('scan')
  const admin = useCan('admin')
  const operator = useCan('operator')
  const test = useTestCred()
  const del = useDelCred()
  const [rm, setRm] = useState<CredTarget | null>(null)
  const opener = useRef<HTMLElement | null>(null)
  const lastRm = useRef<CredTarget | null>(null)
  if (rm) lastRm.current = rm
  const shownRm = rm ?? lastRm.current
  // Stable columns so the buttons are not remounted (losing focus) on every render.
  const askRemove = useCallback((e: React.MouseEvent<HTMLElement>, r: CredTarget) => { opener.current = e.currentTarget; setRm(r) }, [])
  const columns = useMemo<ColumnDef<CredTarget>[]>(() => [
    { id: 'host', header: t('cred.col.host'), accessorFn: (r) => r.label, cell: ({ row: { original: r } }) => <div className="grid"><span className="font-medium">{r.label}</span><span className="text-caption text-muted">{r.username}@{r.host}:{r.port}</span></div> },
    { id: 'key', header: t('cred.col.key'), accessorFn: (r) => r.key_last4, cell: ({ row: { original: r } }) => <span>{t('cred.keyEnds', { last4: r.key_last4 })}</span> },
    { id: 'test', header: t('cred.col.test'), enableSorting: false, cell: ({ row: { original: r } }) => (r.last_test ? (
      <div className="grid gap-1"><span><Chip tone={r.last_test.ok ? 'ok' : 'warn'}>{r.last_test.ok ? t('cred.testOk') : t('cred.testFail')}</Chip> <span className="text-caption text-muted">{fmtDateTime(r.last_test.ts)}</span></span><span className="max-w-md text-meta">{r.last_test.message}</span></div>
    ) : <span className="text-muted">{t('cred.notTested')}</span>) },
    { id: 'actions', header: () => <span className="sr-only">{t('hist.actions')}</span>, enableSorting: false, cell: ({ row: { original: r } }) => (
      <div className="flex gap-2">
        <Button size="sm" disabled={!operator || test.isPending} busy={test.isPending && test.variables === r.id} busyLabel={t('common:busy.testing')} aria-label={t('cred.testAria', { name: r.label })} onClick={() => test.mutate(r.id, { onError: (e) => toast.error(errMsg(e)) })}>{t('cred.test')}</Button>
        <Button size="sm" disabled={!admin} aria-label={t('cred.removeAria', { name: r.label })} onClick={(e) => askRemove(e, r)}>{t('cred.remove')}</Button>
      </div>
    ) },
  ], [t, admin, operator, test.isPending, test.variables, test.mutate, askRemove])
  const testing = test.isPending ? items.find((x) => x.id === test.variables) : undefined
  return (
    <>
      <DataTable urlKey="credentialed" caption={t('cred.caption')} data={items} columns={columns} empty={<EmptyState title={t('cred.empty')}>{t('cred.emptyHelp')}</EmptyState>} />
      {/* An SSH login check waits on the server; say so while it runs */}
      <BusyNote busy={test.isPending} className="mt-2">{t('cred.testWaiting', { name: testing?.label ?? '' })}</BusyNote>
      <Dialog open={!!rm} onOpenChange={(o) => { if (!o) setRm(null) }}>
        {shownRm ? (
          <DialogContent title={t('cred.removeTitle', { name: shownRm.label })} description={t('cred.removeBody')} onCloseAutoFocus={(e) => { e.preventDefault(); opener.current?.focus() }}>
            <DialogFooter>
              <Button onClick={() => setRm(null)}>{t('common:cancel')}</Button>
              <Button variant="danger" busy={del.isPending} busyLabel={t('common:busy.removing')} onClick={() => del.mutate(shownRm.id, { onSuccess: () => { toast.success(t('cred.removed')); setRm(null) }, onError: (e) => toast.error(errMsg(e)) })}>{t('cred.remove')}</Button>
            </DialogFooter>
          </DialogContent>
        ) : null}
      </Dialog>
    </>
  )
}

function Inner() {
  const { t } = useTranslation('scan')
  const creds = useCreds()
  const targets = useTargets()
  return (
    <Section id="cred" title={t('cred.title')} description={t('cred.description')} info={<><p>{t('cred.descriptionInfo')}</p><p>{t('cred.how')}</p></>} stories={['S-SCAN-5']}>
      <div className="grid gap-6">
        <Prepare />
        <QueryState query={creds}>
          {(c) => (
            <>
              <List items={c.items} />
              <div className="grid gap-3">
                <QueryState query={targets}>
                  {(d) => <AddServer options={d.items.filter((x) => x.kind === 'internal' && SSH_KINDS.includes(actsAs(x.device_kind ?? 'unknown')) && x.selectable && !c.items.some((i) => i.asset_id === x.id))} />}
                </QueryState>
              </div>
            </>
          )}
        </QueryState>
      </div>
    </Section>
  )
}

export function CredentialedTab() {
  return <RequireModule module="scan-credentialed"><Inner /></RequireModule>
}
