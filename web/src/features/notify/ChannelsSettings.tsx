import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { QrCode, Send, TriangleAlert, X } from 'lucide-react'
import { PageHeader } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Chip } from '@/components/common/StatusChip'
import { QueryState, RequireModule } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Label, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { ApiError } from '@/lib/api'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { useUsers } from '@/features/core/api'
import History from './History'
import { useChannels, useRemoveChannel, useSaveChannel, useSaveRules, useTestChannel } from './api'
import { APPROVAL_CHANNELS, FIELDS, ROUTE_SEVERITIES } from './types'
import type { Approver, Channel, Grouping, Quiet, RouteSeverity } from './types'

const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : String(e))

function randomKey() {
  const b = new Uint8Array(24)
  crypto.getRandomValues(b)
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
}

function ChannelDialog({ channel, codeUsers, onClose, onSaved }: { channel: Channel; codeUsers: number; onClose: () => void; onSaved: (thenTest: boolean) => void }) {
  const { t } = useTranslation('notify')
  const save = useSaveChannel()
  const type = channel.type
  const name = t(`ch.${type}`)
  const [enabled, setEnabled] = useState(channel.configured ? channel.enabled : true)
  const [fields, setFields] = useState<Record<string, string>>(() => ({ ...(type === 'email' ? { port: '587', security: 'starttls' } : {}), ...channel.fields }))
  const [secret, setSecret] = useState('')
  const [min, setMin] = useState<RouteSeverity>(channel.min_severity)
  const [approvals, setApprovals] = useState(channel.approvals)
  const [approvers, setApprovers] = useState<Approver[]>(channel.approvers)
  const [pick, setPick] = useState('')
  const [qr, setQr] = useState(false)
  const users = useUsers()
  const [appToken, setAppToken] = useState('')
  const [botToken, setBotToken] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [warn, setWarn] = useState<boolean | null>(null) // null = no warning; value = whether to send a test after saving
  const busy = save.isPending

  function submit(e: FormEvent | { preventDefault(): void }, thenTest = false, confirmed = false) {
    e.preventDefault()
    setError(null)
    // Turning the email channel off stops two-step email codes too (D-35): say who is affected before doing it.
    if (type === 'email' && channel.enabled && !enabled && codeUsers > 0 && !confirmed) { setWarn(thenTest); return }
    const canApprove = APPROVAL_CHANNELS.includes(type)
    save.mutate({ type, enabled, fields, secret: secret || undefined, min_severity: min, ...(canApprove ? { approvals, approvers: approvals ? approvers : [] } : {}), ...(type === 'slack' && approvals ? { app_token: appToken || undefined, bot_token: botToken || undefined } : {}) }, {
      onSuccess: () => {
        toast.success(t('channels.saved', { name }))
        onSaved(thenTest)
      },
      onError: (er) => setError(errMsg(er)),
    })
  }
  const set = (k: string, v: string) => setFields((f) => ({ ...f, [k]: v }))
  const eligible = (users.data?.items ?? []).filter((u) => !u.disabled && u.role !== 'viewer')
  const free = eligible.filter((u) => !approvers.some((a) => a.user_id === u.id))
  const addApprover = () => {
    const u = free.find((x) => x.id === pick) ?? free[0]
    if (u) { setApprovers((l) => [...l, { user_id: u.id, address: type === 'email' ? u.email : '' }]); setPick('') }
  }
  const secretHint = channel.secret_last4 ? t('channels.secretSaved', { last4: channel.secret_last4 }) : t(`channels.f.${type}.secret.hint`)
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('channels.dialogTitle', { name })} description={t('channels.dialogDesc')}>
        <form onSubmit={submit} className="grid gap-4" noValidate>
          {error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{error}</p> : null}
          {FIELDS[type].map((k) => {
            const id = `ch-${type}-${k}`
            const label = t(`channels.f.${type}.${k}.label`)
            if (k === 'security') {
              return (
                <Field key={k} label={label} htmlFor={id}>
                  <Select id={id} value={fields[k] ?? 'starttls'} onChange={(e) => {
                    const v = e.target.value
                    // Cổng mặc định đi theo kiểu mã hoá: 465 = SSL/TLS ngầm, 587 = STARTTLS (không đổi nếu người dùng đã tự đặt cổng khác).
                    setFields((f) => ({ ...f, security: v, port: v === 'ssl' && f.port === '587' ? '465' : v === 'starttls' && f.port === '465' ? '587' : f.port ?? '' }))
                  }}>
                    {(['starttls', 'ssl', 'none'] as const).map((o) => <option key={o} value={o}>{t(`channels.f.email.security.${o}`)}</option>)}
                  </Select>
                </Field>
              )
            }
            return (
              <Field key={k} label={label} hint={t(`channels.f.${type}.${k}.hint`)} htmlFor={id}>
                <Input id={id} value={fields[k] ?? ''} type={k === 'port' ? 'number' : 'text'} onChange={(e) => set(k, e.target.value)} autoComplete="off" aria-describedby={`${id}-hint`} />
              </Field>
            )
          })}
          {type === 'zalo-personal' ? (
            <div className="grid gap-3">
              <p role="note" className="flex gap-2 rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm font-medium"><TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />{t('zp.warning')}</p>
              <div className="grid gap-2 rounded-md border border-rule p-3">
                <span className="text-sm font-medium">{t('zp.login')}</span>
                <p className="text-[13px] text-muted">{secret ? t('zp.ready') : channel.secret_last4 ? t('channels.secretSaved', { last4: channel.secret_last4 }) : t('zp.none')}</p>
                {qr ? (
                  <div className="grid justify-items-start gap-2">
                    <div role="img" aria-label={t('zp.qrAlt')} className="grid size-36 place-items-center rounded-md border border-dashed border-rule bg-sunken text-muted"><QrCode className="size-20" aria-hidden /></div>
                    <p className="text-[13px]">{t('zp.scan')}</p>
                    <Button onClick={() => { setSecret(`zl-session-${randomKey()}`); setQr(false) }}>{t('zp.scanned')}</Button>
                  </div>
                ) : <div><Button onClick={() => setQr(true)}><QrCode />{channel.secret_last4 || secret ? t('zp.relogin') : t('zp.show')}</Button></div>}
              </div>
            </div>
          ) : (
            <Field label={t(`channels.f.${type}.secret.label`)} hint={secretHint} htmlFor={`ch-${type}-secret`}>
              <div className="flex gap-2">
                <Input id={`ch-${type}-secret`} type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="new-password" aria-describedby={`ch-${type}-secret-hint`} />
                {type === 'webhook' ? <Button onClick={() => setSecret(randomKey())}>{t('channels.generate')}</Button> : null}
              </div>
            </Field>
          )}
          <fieldset className="grid gap-3 rounded-md border border-rule bg-sunken p-3">
            <legend className="px-1 text-sm font-medium">{t('approve.title')}</legend>
            {APPROVAL_CHANNELS.includes(type) ? (
              <>
                <div className="flex items-center gap-3">
                  <Switch id={`ch-${type}-appr`} checked={approvals} onCheckedChange={setApprovals} />
                  <Label htmlFor={`ch-${type}-appr`}>{t('approve.switch')}</Label>
                </div>
                <p className="text-[13px] text-muted">{t(`approve.hint.${type}`)}</p>
                {type === 'email' ? <ul className="list-disc pl-5 text-[13px] text-muted">{(['p1', 'p2', 'p3', 'p4'] as const).map((k) => <li key={k}>{t(`approve.email.${k}`)}</li>)}</ul> : null}
                {approvals ? (
                  <div className="grid gap-2" role="group" aria-label={t('approve.listTitle')}>
                    <span className="text-sm font-medium">{t('approve.listTitle')}</span>
                    {approvers.length === 0 ? <p className="text-[13px] text-muted">{t('approve.empty')}</p> : null}
                    {approvers.map((a) => {
                      const u = eligible.find((x) => x.id === a.user_id)
                      const who = u?.email ?? a.user_id
                      return (
                        <div key={a.user_id} className="grid items-end gap-2 sm:grid-cols-[1fr_1.4fr_auto]">
                          <div className="grid text-sm"><span className="font-medium">{u?.name ?? a.user_id}</span><span className="text-[12px] text-muted">{u ? `${u.email}, ${t(`common:role.${u.role}`)}` : ''}</span></div>
                          <Field label={t(`approve.address.${type}`)} htmlFor={`ap-${type}-${a.user_id}`}>
                            <Input id={`ap-${type}-${a.user_id}`} value={a.address} placeholder={t(`approve.placeholder.${type}`)} autoComplete="off" onChange={(e) => setApprovers((l) => l.map((x) => (x.user_id === a.user_id ? { ...x, address: e.target.value } : x)))} />
                          </Field>
                          <Button size="sm" variant="ghost" onClick={() => setApprovers((l) => l.filter((x) => x.user_id !== a.user_id))}><X /><span className="sr-only">{t('approve.remove', { who })}</span></Button>
                        </div>
                      )
                    })}
                    <div className="flex flex-wrap items-end gap-2">
                      <Field label={t('approve.addLabel')} htmlFor={`ap-${type}-add`}>
                        <Select id={`ap-${type}-add`} value={pick || free[0]?.id || ''} disabled={free.length === 0} onChange={(e) => setPick(e.target.value)}>
                          {free.map((u) => <option key={u.id} value={u.id}>{u.name} ({u.email})</option>)}
                        </Select>
                      </Field>
                      <Button disabled={free.length === 0} onClick={addApprover}>{t('approve.add')}</Button>
                    </div>
                    <p className="text-[13px] text-muted">{t('approve.viewers')}</p>
                  </div>
                ) : null}
                {type === 'slack' && approvals ? (
                  <>
                    <Field label={t('channels.f.slack.channel_id.label')} hint={t('channels.f.slack.channel_id.hint')} htmlFor="ch-slack-channel_id">
                      <Input id="ch-slack-channel_id" value={fields.channel_id ?? ''} onChange={(e) => set('channel_id', e.target.value)} autoComplete="off" aria-describedby="ch-slack-channel_id-hint" />
                    </Field>
                    <Field label={t('channels.f.slack.app_token.label')} hint={channel.approval_last4.app_token ? t('channels.secretSaved', { last4: channel.approval_last4.app_token }) : t('channels.f.slack.app_token.hint')} htmlFor="ch-slack-app_token">
                      <Input id="ch-slack-app_token" type="password" value={appToken} onChange={(e) => setAppToken(e.target.value)} autoComplete="new-password" aria-describedby="ch-slack-app_token-hint" />
                    </Field>
                    <Field label={t('channels.f.slack.bot_token.label')} hint={channel.approval_last4.bot_token ? t('channels.secretSaved', { last4: channel.approval_last4.bot_token }) : t('channels.f.slack.bot_token.hint')} htmlFor="ch-slack-bot_token">
                      <Input id="ch-slack-bot_token" type="password" value={botToken} onChange={(e) => setBotToken(e.target.value)} autoComplete="new-password" aria-describedby="ch-slack-bot_token-hint" />
                    </Field>
                  </>
                ) : null}
              </>
            ) : <p className="text-[13px] text-muted">{t('approve.linkOnly')}</p>}
          </fieldset>
          <Field label={t('channels.minSeverity')} hint={t('channels.minSeverityHint')} htmlFor={`ch-${type}-min`}>
            <Select id={`ch-${type}-min`} value={min} onChange={(e) => setMin(e.target.value as RouteSeverity)} aria-describedby={`ch-${type}-min-hint`}>
              {ROUTE_SEVERITIES.map((s) => <option key={s} value={s}>{t('channels.min', { sev: t(`common:severity.${s}`) })}</option>)}
            </Select>
          </Field>
          <div className="flex items-center gap-3">
            <Switch id={`ch-${type}-on`} checked={enabled} onCheckedChange={setEnabled} />
            <Label htmlFor={`ch-${type}-on`}>{t('channels.enabled')}</Label>
          </div>
          <DialogFooter>
            <Button onClick={onClose}>{t('common:cancel')}</Button>
            <Button disabled={busy} onClick={(e) => submit(e, true)}><Send />{t('channels.saveTest')}</Button>
            <Button type="submit" variant="primary" disabled={busy}>{t('channels.save')}</Button>
          </DialogFooter>
        </form>
        <Dialog open={warn !== null} onOpenChange={(o) => { if (!o) setWarn(null) }}>
          <DialogContent title={t('channels.turnOffTitle')} description={t('channels.emailCodes', { count: codeUsers })}>
            <DialogFooter>
              <Button onClick={() => setWarn(null)}>{t('channels.keepEditing')}</Button>
              <Button variant="danger" disabled={busy} onClick={(e) => { const test = warn === true; setWarn(null); submit(e, test, true) }}>{t('channels.turnOffConfirm')}</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </DialogContent>
    </Dialog>
  )
}

function Channels({ channels, codeUsers }: { channels: Channel[]; codeUsers: number }) {
  const { t } = useTranslation('notify')
  const isAdmin = useCan('admin')
  const test = useTestChannel()
  const remove = useRemoveChannel()
  const [editing, setEditing] = useState<Channel | null>(null)
  const [removing, setRemoving] = useState<Channel | null>(null)
  const need = isAdmin ? undefined : t('channels.needRole')
  const runTest = (type: Channel['type']) => test.mutate(type, { onSuccess: (res) => (res.ok ? toast.success(res.detail) : toast.error(res.detail)), onError: (e) => toast.error(errMsg(e)) })
  const dest = (c: Channel) => (!c.configured ? '' : c.type === 'zalo-personal' ? t('channels.dest.zaloPersonal', { id: c.fields.user_id }) : c.type === 'telegram' ? t('channels.dest.telegram', { id: c.fields.chat_id }) : c.type === 'slack' ? (c.fields.label || t('channels.dest.slack')) : c.type === 'zalo' ? t('channels.dest.zalo', { id: c.fields.oa_id, user: c.fields.user_id }) : c.type === 'email' ? (c.fields.to ?? '') : (c.fields.url ?? ''))
  const columns: ColumnDef<Channel>[] = [
    { id: 'channel', header: t('channels.col.channel'), accessorFn: (r) => r.type, cell: ({ row }) => <span className="font-medium">{t(`ch.${row.original.type}`)}{row.original.configured && row.original.approvals ? <Chip tone="ok" className="ml-2">{t('approve.chip')}</Chip> : null}</span> },
    { id: 'dest', header: t('channels.col.dest'), enableSorting: false, cell: ({ row }) => <span className="inline-block min-w-[12rem] break-words">{dest(row.original)}</span> },
    { id: 'min', header: t('channels.col.min'), enableSorting: false, cell: ({ row: { original: r } }) => (r.configured ? t('channels.min', { sev: t(`common:severity.${r.min_severity}`) }) : '') },
    { id: 'status', header: t('channels.col.status'), accessorFn: (r) => (r.configured ? (r.enabled ? 0 : 1) : 2), cell: ({ row: { original: r } }) => <Chip tone={!r.configured ? 'off' : r.enabled ? 'ok' : 'off'}>{t(`channels.state.${!r.configured ? 'none' : r.enabled ? 'on' : 'off'}`)}</Chip> },
    { id: 'test', header: t('channels.col.test'), enableSorting: false, cell: ({ row: { original: r } }) => {
      if (!r.configured) return null
      if (!r.last_test) return <span className="text-muted">{t('channels.testNever')}</span>
      return <span className={r.last_test.ok ? 'text-ok' : 'font-medium text-danger'} title={r.last_test.detail}>{t(r.last_test.ok ? 'channels.testOk' : 'channels.testFail', { time: fmtDateTime(r.last_test.at) })}</span>
    } },
    { id: 'actions', header: t('channels.col.actions'), enableSorting: false, cell: ({ row: { original: r } }) => {
      const name = t(`ch.${r.type}`)
      return (
        <div className="flex gap-1">
          <Button size="sm" variant={r.configured ? 'secondary' : 'primary'} disabled={!isAdmin} title={need} onClick={() => setEditing(r)}>{r.configured ? t('channels.edit') : t('channels.configure')} <span className="sr-only">{name}</span></Button>
          {r.configured ? (
            <>
              <Button size="sm" disabled={!isAdmin || test.isPending} title={need}
                onClick={() => runTest(r.type)}>{t('channels.test')} <span className="sr-only">{name}</span></Button>
              <Button size="sm" variant="ghost" disabled={!isAdmin} title={need} onClick={() => setRemoving(r)}>{t('channels.remove')} <span className="sr-only">{name}</span></Button>
            </>
          ) : null}
        </div>
      )
    } },
  ]
  return (
    <>
      <DataTable caption={t('channels.caption')} data={channels} columns={columns} />
      {editing ? <ChannelDialog key={editing.type} channel={editing} codeUsers={codeUsers} onClose={() => setEditing(null)} onSaved={(thenTest) => { setEditing(null); if (thenTest) runTest(editing.type) }} /> : null}
      <Dialog open={removing !== null} onOpenChange={(o) => { if (!o) setRemoving(null) }}>
        {removing ? (
          <DialogContent title={t('channels.removeTitle', { name: t(`ch.${removing.type}`) })} description={t('channels.removeBody')}>
            {removing.type === 'email' && codeUsers > 0 ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{t('channels.emailCodes', { count: codeUsers })}</p> : null}
            <DialogFooter>
              <Button onClick={() => setRemoving(null)}>{t('common:cancel')}</Button>
              <Button variant="danger" disabled={remove.isPending} onClick={() => remove.mutate(removing.type, { onSuccess: () => { toast.success(t('channels.removed', { name: t(`ch.${removing.type}`) })); setRemoving(null) }, onError: (e) => toast.error(errMsg(e)) })}>{t('common:delete')}</Button>
            </DialogFooter>
          </DialogContent>
        ) : null}
      </Dialog>
    </>
  )
}

function Rules({ init }: { init: { quiet: Quiet; grouping: Grouping } }) {
  const { t } = useTranslation('notify')
  const isAdmin = useCan('admin')
  const save = useSaveRules()
  const [quiet, setQuiet] = useState(init.quiet)
  const [grouping, setGrouping] = useState(init.grouping)
  const [error, setError] = useState<string | null>(null)
  function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    save.mutate({ quiet, grouping }, { onSuccess: () => toast.success(t('rules.saved')), onError: (er) => setError(errMsg(er)) })
  }
  return (
    <form onSubmit={submit} className="grid max-w-2xl gap-8" noValidate>
      {error ? <p role="alert" className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm">{error}</p> : null}
      <fieldset disabled={!isAdmin} className="grid gap-3 border-0 p-0">
        <legend className="mb-1 text-base font-semibold">{t('rules.quiet.title')}</legend>
        <p className="text-[13px] text-muted">{t('rules.quiet.description')}</p>
        <div className="flex items-center gap-3"><Switch id="q-on" checked={quiet.enabled} onCheckedChange={(v) => setQuiet({ ...quiet, enabled: v })} /><Label htmlFor="q-on">{t('rules.quiet.enabled')}</Label></div>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label={t('rules.quiet.from')} htmlFor="q-from"><Input id="q-from" type="time" value={quiet.from} onChange={(e) => setQuiet({ ...quiet, from: e.target.value })} /></Field>
          <Field label={t('rules.quiet.to')} htmlFor="q-to"><Input id="q-to" type="time" value={quiet.to} onChange={(e) => setQuiet({ ...quiet, to: e.target.value })} /></Field>
        </div>
        {quiet.enabled && quiet.from && quiet.to && quiet.from !== quiet.to ? <p className="text-[13px]" role="status">{quiet.from > quiet.to ? t('rules.quiet.overnight', { from: quiet.from, to: quiet.to }) : t('rules.quiet.sameDay', { from: quiet.from, to: quiet.to })}</p> : null}
        <div className="flex items-center gap-2"><Checkbox id="q-crit" checked={quiet.allow_critical} onCheckedChange={(c) => setQuiet({ ...quiet, allow_critical: c === true })} /><Label htmlFor="q-crit" className="font-normal">{t('rules.quiet.allowCritical')}</Label></div>
      </fieldset>
      <fieldset disabled={!isAdmin} className="grid gap-3 border-0 p-0">
        <legend className="mb-1 text-base font-semibold">{t('rules.grouping.title')}</legend>
        <p className="text-[13px] text-muted">{t('rules.grouping.description')}</p>
        <div className="flex items-center gap-3"><Switch id="g-on" checked={grouping.enabled} onCheckedChange={(v) => setGrouping({ ...grouping, enabled: v })} /><Label htmlFor="g-on">{t('rules.grouping.enabled')}</Label></div>
        <Field label={t('rules.grouping.window')} htmlFor="g-win" className="max-w-xs">
          <Select id="g-win" value={grouping.window_min} onChange={(e) => setGrouping({ ...grouping, window_min: Number(e.target.value) as Grouping['window_min'] })}>
            {([15, 60, 240] as const).map((m) => <option key={m} value={m}>{t(`rules.grouping.w${m}`)}</option>)}
          </Select>
        </Field>
      </fieldset>
      <div><Button type="submit" variant="primary" disabled={!isAdmin || save.isPending} title={isAdmin ? undefined : t('channels.needRole')}>{t('rules.save')}</Button></div>
    </form>
  )
}

export default function ChannelsSettings() {
  const { t } = useTranslation('notify')
  const q = useChannels()
  return (
    <RequireModule module="notify">
      <PageHeader title={t('channels.title')} meta={t('channels.description')} stories={['S-NOT-1', 'S-NOT-2', 'S-RESP-2']} />
        <p className="mb-4 max-w-3xl rounded-md border border-rule bg-sunken px-3 py-2 text-[13px]">{t('channels.privacy')}</p>
        <QueryState query={q}>
          {(d) => (
            <div className="grid gap-8">
              <Channels channels={d.channels} codeUsers={d.email_code_users} />
              <Rules init={{ quiet: d.quiet, grouping: d.grouping }} />
              <History />
            </div>
          )}
        </QueryState>
    </RequireModule>
  )
}
