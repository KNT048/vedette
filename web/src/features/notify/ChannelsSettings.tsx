import { useState, type FormEvent } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { LoaderCircle, QrCode, Send, TriangleAlert, X } from 'lucide-react'
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
import { checkFeedUrl } from '@/features/feeds/defaults'
import History from './History'
import { useChannels, useRemoveChannel, useSaveChannel, useSaveRules, useTestChannel } from './api'
import { APPROVAL_CHANNELS, FIELDS, ROUTE_SEVERITIES, forbiddenHost, ownHost } from './types'
import type { Approver, Channel, Grouping, Quiet, RouteSeverity } from './types'

const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : String(e))
// The box names the wrong field by its code: the message goes under that field, as in the log source form. Per type, because a code
// can mean another field elsewhere (modules/notify/channel/*.go, mocks.ts validate). A code left out stays at the top of the dialog:
// Slack `secret_required` is the webhook URL, the app token or the bot token; Zalo personal's session is a QR sign-in, not a field.
// Approver errors (`bad_approver_address`, …) stay at the top too: they name the approver in the message.
const FIELD_OF: Record<Channel['type'], Record<string, string>> = {
  telegram: { bad_chat_id: 'chat_id', secret_required: 'secret', bad_token: 'secret' },
  slack: { bad_label: 'label', bad_webhook: 'secret', bad_channel_id: 'channel_id', bad_app_token: 'app_token', bad_bot_token: 'bot_token' },
  zalo: { bad_oa_id: 'oa_id', bad_user_id: 'user_id', secret_required: 'secret', bad_token: 'secret' },
  'zalo-personal': { bad_user_id: 'user_id' }, // at save an approver's ID is `bad_approver_address`; `bad_user_id` is the recipient
  email: { bad_host: 'host', bad_port: 'port', port_mismatch: 'port', bad_security: 'security', bad_username: 'username', secret_required: 'secret', bad_from: 'from', bad_to: 'to' },
  webhook: { bad_url: 'url', url_unreadable: 'url', secret_required: 'secret', bad_secret: 'secret' },
}

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
  const [fields, setFields] = useState<Record<string, string>>(() => ({ ...(type === 'email' ? { port: '587', security: 'starttls' } : {}), ...(type === 'webhook' ? {} : channel.fields) })) // the webhook URL is a secret: only its masked form comes back, so the field starts empty (empty = keep)
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
  const [fieldErr, setFieldErr] = useState<Record<string, string>>({})
  const [warn, setWarn] = useState<boolean | null>(null) // null = no warning; value = whether to send a test after saving
  const busy = save.isPending

  function submit(e: FormEvent | { preventDefault(): void }, thenTest = false, confirmed = false) {
    e.preventDefault()
    setError(null)
    // The webhook form checks what it can before sending (same rules and words as the box), so every wrong field shows at once.
    if (showErrors(type === 'webhook' ? checkWebhook() : {})) return
    // Turning the email channel off stops two-step email codes too (D-35): say who is affected before doing it.
    if (type === 'email' && channel.enabled && !enabled && codeUsers > 0 && !confirmed) { setWarn(thenTest); return }
    const canApprove = APPROVAL_CHANNELS.includes(type)
    // Slack's channel ID and app tokens only belong to approvals: with approvals off they are not sent.
    const sent = type === 'slack' && !approvals ? Object.fromEntries(Object.entries(fields).filter(([k]) => k !== 'channel_id')) : fields
    save.mutate({ type, enabled, fields: sent, secret: secret || undefined, min_severity: min, ...(canApprove ? { approvals, approvers: approvals ? approvers : [] } : {}), ...(type === 'slack' && approvals ? { app_token: appToken || undefined, bot_token: botToken || undefined } : {}) }, {
      onSuccess: () => {
        toast.success(t('channels.saved', { name }))
        onSaved(thenTest)
      },
      onError: (er) => {
        const f = er instanceof ApiError ? FIELD_OF[type][er.code] : undefined
        if (f) showErrors({ [f]: errMsg(er) })
        else setError(errMsg(er))
      },
    })
  }
  function checkWebhook() {
    const errs: Record<string, string> = {}
    const url = (fields.url ?? '').trim()
    const u = url ? checkFeedUrl(url) : channel.fields.url ? 'ok' : 'url' // empty keeps the saved URL
    // A forbidden target gets the box's precise sentence before the http rule, as the box checks it (webhook.go, walk 3 G13).
    if (u !== 'url' && url && forbiddenHost(new URL(url).hostname)) errs.url = t(ownHost(new URL(url).hostname) ? 'channels.err.ownUrl' : 'channels.err.blockedUrl') // D-446
    else if (u !== 'ok') errs.url = t(u === 'https' ? 'channels.err.insecureUrl' : 'channels.err.badUrl')
    if (secret ? secret.length < 16 : !channel.secret_last4) errs.secret = t(secret ? 'channels.err.shortKey' : 'channels.err.noKey')
    return errs
  }
  // Focus after React has drawn the error, so a screen reader reads the field with its message (as the log source form does).
  function showErrors(errs: Record<string, string>) {
    setFieldErr(errs)
    const first = [...FIELDS[type], 'secret', 'channel_id', 'app_token', 'bot_token'].find((k) => errs[k])
    if (first) setTimeout(() => document.getElementById(`ch-${type}-${first}`)?.focus(), 0)
    return first !== undefined
  }
  const fixed = (k: string) => setFieldErr((e) => (e[k] ? { ...e, [k]: '' } : e))
  const aria = (id: string, k: string) => ({ 'aria-invalid': fieldErr[k] ? true : undefined, 'aria-describedby': `${id}-${fieldErr[k] ? 'error' : 'hint'}` })
  const set = (k: string, v: string) => { setFields((f) => ({ ...f, [k]: v })); fixed(k) }
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
                <Field key={k} label={label} htmlFor={id} error={fieldErr[k]}>
                  <Select id={id} value={fields[k] ?? 'starttls'} aria-invalid={fieldErr[k] ? true : undefined} aria-describedby={fieldErr[k] ? `${id}-error` : undefined} onChange={(e) => {
                    const v = e.target.value
                    fixed('security'); fixed('port') // a port/encryption mismatch is shown under the port
                    // Cổng mặc định đi theo kiểu mã hoá: 465 = SSL/TLS ngầm, 587 = STARTTLS hoặc không mã hoá (không đổi nếu người dùng đã tự đặt cổng khác).
                    setFields((f) => ({ ...f, security: v, port: v === 'ssl' && f.port === '587' ? '465' : v !== 'ssl' && f.port === '465' ? '587' : f.port ?? '' }))
                  }}>
                    {(['starttls', 'ssl', 'none'] as const).map((o) => <option key={o} value={o}>{t(`channels.f.email.security.${o}`)}</option>)}
                  </Select>
                </Field>
              )
            }
            const hint = type === 'webhook' && k === 'url' && channel.fields.url ? t('channels.urlSaved', { url: channel.fields.url }) : t(`channels.f.${type}.${k}.hint`)
            return (
              <Field key={k} label={label} hint={hint} htmlFor={id} error={fieldErr[k]}>
                <Input id={id} value={fields[k] ?? ''} type={k === 'port' ? 'number' : 'text'} onChange={(e) => set(k, e.target.value)} autoComplete="off" {...aria(id, k)} />
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
            <Field label={t(`channels.f.${type}.secret.label`)} hint={secretHint} htmlFor={`ch-${type}-secret`} error={fieldErr.secret}>
              <div className="flex gap-2">
                <Input id={`ch-${type}-secret`} type="password" value={secret} onChange={(e) => { setSecret(e.target.value); fixed('secret') }} autoComplete="new-password" {...aria(`ch-${type}-secret`, 'secret')} />
                {type === 'webhook' ? <Button onClick={() => { setSecret(randomKey()); fixed('secret') }}>{t('channels.generate')}</Button> : null}
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
                          {free.length === 0 ? <option value="">{t('approve.noneLeft')}</option> : null}
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
                    <Field label={t('channels.f.slack.channel_id.label')} hint={t('channels.f.slack.channel_id.hint')} htmlFor="ch-slack-channel_id" error={fieldErr.channel_id}>
                      <Input id="ch-slack-channel_id" value={fields.channel_id ?? ''} onChange={(e) => set('channel_id', e.target.value)} autoComplete="off" {...aria('ch-slack-channel_id', 'channel_id')} />
                    </Field>
                    <Field label={t('channels.f.slack.app_token.label')} hint={channel.approval_last4.app_token ? t('channels.secretSaved', { last4: channel.approval_last4.app_token }) : t('channels.f.slack.app_token.hint')} htmlFor="ch-slack-app_token" error={fieldErr.app_token}>
                      <Input id="ch-slack-app_token" type="password" value={appToken} onChange={(e) => { setAppToken(e.target.value); fixed('app_token') }} autoComplete="new-password" {...aria('ch-slack-app_token', 'app_token')} />
                    </Field>
                    <Field label={t('channels.f.slack.bot_token.label')} hint={channel.approval_last4.bot_token ? t('channels.secretSaved', { last4: channel.approval_last4.bot_token }) : t('channels.f.slack.bot_token.hint')} htmlFor="ch-slack-bot_token" error={fieldErr.bot_token}>
                      <Input id="ch-slack-bot_token" type="password" value={botToken} onChange={(e) => { setBotToken(e.target.value); fixed('bot_token') }} autoComplete="new-password" {...aria('ch-slack-bot_token', 'bot_token')} />
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
  const chName = (r: Channel) => <span className="font-medium">{t(`ch.${r.type}`)}{r.configured && r.approvals ? <Chip tone="ok" className="ml-2">{t('approve.chip')}</Chip> : null}</span>
  const min = (r: Channel) => (r.configured ? t('channels.min', { sev: t(`common:severity.${r.min_severity}`) }) : '')
  const status = (r: Channel) => <Chip tone={!r.configured ? 'off' : r.enabled ? 'ok' : 'off'}>{t(`channels.state.${!r.configured ? 'none' : r.enabled ? 'on' : 'off'}`)}</Chip>
  // A test waits for the far end (up to 30 s): the row says so, and a failure shows its reason as text, not only as a hover title (walk 3 G13).
  const lastTest = (r: Channel) => {
    if (!r.configured) return null
    if (test.isPending && test.variables === r.type) return <span role="status" className="inline-flex items-center gap-1.5 text-muted"><LoaderCircle className="size-4 animate-spin motion-reduce:animate-none" aria-hidden />{t('channels.testing')}</span>
    if (!r.last_test) return <span className="text-[13px] text-muted">{t('channels.testNever')}</span>
    if (r.last_test.ok) return <span className="text-[13px] text-ok">{t('channels.testOk', { time: fmtDateTime(r.last_test.at) })}</span>
    return (
      <span className="grid min-w-[12rem] max-w-72 gap-0.5">
        <span className="text-[13px] font-medium text-danger">{t('channels.testFail', { time: fmtDateTime(r.last_test.at) })}</span>
        <span className="text-[12px]">{r.last_test.detail}</span>
        {r.enabled ? <span className="text-[12px] text-muted">{t('channels.onButFailed')}</span> : null}
      </span>
    )
  }
  const actions = (r: Channel, stacked = false) => {
    const name = t(`ch.${r.type}`)
    return (
      <div className={stacked ? 'grid justify-items-start gap-1' : 'flex flex-wrap gap-1'}>
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
  }
  // Three columns, so the table fits the ~730 px content column of a 1280 px screen (app sidebar + settings nav): where it sends and
  // from which severity under the channel's name, the last test under its status, the actions stacked (walk 3 G13, D-423).
  const columns: ColumnDef<Channel>[] = [
    { id: 'channel', header: t('channels.col.channel'), accessorFn: (r) => r.type, cell: ({ row: { original: r } }) => (
      <span className="grid gap-0.5">
        {chName(r)}
        {r.configured ? <span className="max-w-[18rem] break-words text-[12px] text-muted">{dest(r)}</span> : null}
        {r.configured ? <span className="text-[12px] text-muted">{min(r)}</span> : null}
      </span>
    ) },
    { id: 'status', header: t('channels.col.status'), accessorFn: (r) => (r.configured ? (r.enabled ? 0 : 1) : 2), cell: ({ row: { original: r } }) => (
      <span className="grid justify-items-start gap-1">{status(r)}{lastTest(r)}</span>
    ) },
    { id: 'actions', header: t('channels.col.actions'), enableSorting: false, cell: ({ row }) => actions(row.original, true) },
  ]
  // Under 768 px each channel is a card with its actions in it (the table's pattern, as Feeds does; D-423).
  const mobileRow = (r: Channel) => (
    <div className="grid gap-1.5 text-sm">
      <p className="flex flex-wrap items-center gap-2">{chName(r)} {status(r)}</p>
      {r.configured ? <p className="break-words text-muted">{[dest(r), min(r)].filter(Boolean).join(', ')}</p> : null}
      {lastTest(r)}
      {actions(r)}
    </div>
  )
  return (
    <>
      <DataTable caption={t('channels.caption')} data={channels} columns={columns} mobileRow={mobileRow} />
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
