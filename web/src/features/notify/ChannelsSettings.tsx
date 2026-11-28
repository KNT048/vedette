import { useCallback, useState, type FormEvent } from 'react'
import { Link, Navigate, useLocation } from 'react-router'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { History as HistoryIcon, Send, X } from 'lucide-react'
import { Notice, PageHeader } from '@/components/common/PageHeader'
import { InfoTip } from '@/components/common/InfoTip'
import { PageTabs } from '@/components/common/PageFrame'
import { BusyNote } from '@/components/common/BusyNote'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { Chip } from '@/components/common/StatusChip'
import { QueryState, RequireModule } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Label, Select } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { ApiError } from '@/lib/api'
import { fmtDateTime } from '@/lib/format'
import { useCan } from '@/lib/session'
import { notOffered } from '@/lib/v1'
import { useUsers } from '@/features/core/api'
import { checkFeedUrl } from '@/features/feeds/defaults'
import { EMAIL_PROVIDERS, OAUTH_HOST, emailBinding, emailProvider, isMicrosoftSmtp, isOAuth, isUserSignin, savedFor, type EmailProvider } from './emailProviders'
import { EmailSignin } from './EmailSignin'
import { AlertSettings } from './AlertSettings'
import { useChannels, useRemoveChannel, useSaveChannel, useTestChannel } from './api'
import { APPROVAL_CHANNELS, FIELDS, ROUTE_SEVERITIES, forbiddenHost, ownHost } from './types'
import { TelegramFind } from './TelegramFind'
import { ApproverLinkState, LinkApproverField, ZaloRecipient, ZaloSignIn, ZaloWarning, type ZaloTarget } from './ZaloPersonal'
import type { Approver, Channel, RouteSeverity } from './types'

const errMsg = (e: unknown) => (e instanceof ApiError ? e.message : String(e))
// The box names the wrong field by its code: the message goes under that field, as in the log source form. Per type, because a code
// can mean another field elsewhere (modules/notify/channel/*.go, mocks.ts validate). A code left out stays at the top of the dialog:
// Slack `secret_required` is the webhook URL, the app token or the bot token; Zalo personal's session is a QR sign-in, not a field
// (`login_required` too); its `bad_user_id` is the recipient, shown in the recipient box.
// Approver errors (`bad_approver_address`, …) stay at the top too: they name the approver in the message.
const FIELD_OF: Record<Channel['type'], Record<string, string>> = {
  telegram: { bad_chat_id: 'chat_id', secret_required: 'secret', bad_token: 'secret' },
  slack: { bad_label: 'label', bad_webhook: 'secret', bad_channel_id: 'channel_id', bad_app_token: 'app_token', bad_bot_token: 'bot_token' },
  zalo: { bad_oa_id: 'oa_id', bad_user_id: 'user_id', bad_app_id: 'app_id', bad_secret_key: 'secret_key', bad_refresh_token: 'refresh_token', secret_required: 'refresh_token', bad_token: 'secret' },
  'zalo-personal': { bad_user_id: 'user_id' }, // at save an approver's ID is `bad_approver_address`; `bad_user_id` is the recipient
  email: { bad_provider: 'provider', bad_host: 'host', bad_port: 'port', port_mismatch: 'port', bad_security: 'security', bad_username: 'username', bad_tenant_id: 'tenant_id', bad_client_id: 'client_id', secret_required: 'secret', bad_secret: 'secret', bad_from: 'from', bad_to: 'to' },
  webhook: { bad_url: 'url', url_unreadable: 'url', secret_required: 'secret', bad_secret: 'secret' },
}

/** Zalo's page on the OA access and refresh tokens: where the App ID, Secret key and refresh token come from. */
const ZALO_OA_DOC = 'https://developers.zalo.me/docs/official-account/bat-dau/xac-thuc-va-uy-quyen-cho-ung-dung-new'

/** The service account of a Google key file, or null when the text is not one (the box checks the key itself). */
function keyAccount(text: string): string | null {
  try {
    const j = JSON.parse(text) as { type?: unknown; client_email?: unknown; private_key?: unknown }
    return j.type === 'service_account' && typeof j.client_email === 'string' && typeof j.private_key === 'string' ? j.client_email : null
  } catch { return null }
}

/** Translation keys of an email field's label or hint, most specific first: the preset, its sign-in, its kind, then the plain one. */
function emailKeys(p: EmailProvider, k: string, part: 'label' | 'hint' | 'info') {
  const mailbox = p.group === 'password' && p.id !== 'custom'
  const variants = k === 'username' ? [p.id, isUserSignin(p.auth) ? 'user' : isOAuth(p.auth) ? 'oauth' : mailbox ? 'mailbox' : '']
    : k === 'secret' ? [p.id, p.auth, mailbox && p.id !== 'zoho' ? 'app' : '', p.id !== 'custom' ? 'service' : ''] : [p.id, k === 'host' && isOAuth(p.auth) ? 'oauth' : '']
  return [...variants.filter(Boolean).map((v) => `channels.f.email.${k}.${part}_${v}`), `channels.f.email.${k}.${part}`]
}

function randomKey() {
  const b = new Uint8Array(24)
  crypto.getRandomValues(b)
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
}

/** The form of one alert channel (exported for #850: Settings › Scanning creates a channel where matches need one, §0). */
export function ChannelDialog({ channel: opened, codeUsers, onClose, onSaved, onSwitch }: { channel: Channel; codeUsers: number; onClose: () => void; onSaved: (thenTest: boolean) => void; onSwitch?: (type: Channel['type']) => void }) {
  const { t, i18n } = useTranslation('notify')
  // #824: a field's hint is one short line; its explanation, when it has one, is the sibling `info` key of the hint actually shown.
  const infoOf = (keys: string[]) => {
    const hint = keys.find((k) => i18n.exists(k, { ns: 'notify' }))
    const key = hint?.replace(/\.hint(_|$)/, '.info$1')
    return key && key !== hint && i18n.exists(key, { ns: 'notify' }) ? t(key) : undefined
  }
  const save = useSaveChannel()
  const type = opened.type
  // The channel as the box has it now: a Zalo personal dialog stays open after Save to show each approver's link state.
  const channel = useChannels().data?.channels.find((c) => c.type === type) ?? opened
  // approving actions from a channel belongs to the response module, not offered in v1. A channel that already
  // has approvals on keeps the section, so they can be turned off.
  const approvalsFrozen = notOffered('response')
  const showApprovals = !approvalsFrozen || channel.approvals
  const name = t(`ch.${type}`)
  const [enabled, setEnabled] = useState(channel.configured ? channel.enabled : true)
  const [fields, setFields] = useState<Record<string, string>>(() => ({ ...(type === 'email' ? { port: '587', security: 'starttls', provider: 'custom' } : {}), ...(type === 'webhook' ? {} : channel.fields) })) // the webhook URL is a secret: only its masked form comes back, so the field starts empty (empty = keep)
  const [secret, setSecret] = useState('')
  const [keyOf, setKeyOf] = useState<string | null>(null) // the service account of a chosen Google key file
  const [signin, setSignin] = useState<string | null>(null) // a finished user sign-in: its id goes with the save
  // Email presets: the preset decides which fields show and what the secret is; a saved secret counts only for the same sign-in.
  const prov = emailProvider(fields.provider) ?? EMAIL_PROVIDERS[0]!
  // the box sends a saved secret only to the method, server and port it was saved for: say so before saving
  const keepsSecret = !!channel.secret_last4 && (type !== 'email' || savedFor(channel.fields) === emailBinding(fields))
  const [min, setMin] = useState<RouteSeverity>(channel.min_severity)
  const [approvals, setApprovals] = useState(channel.approvals)
  const [approvers, setApprovers] = useState<Approver[]>(channel.approvers)
  const [pick, setPick] = useState('')
  const [zaloSigned, setZaloSigned] = useState<string | null>(null) // the account of a finished QR sign-in: Save keeps its session
  const onZaloSigned = useCallback((n: string | null) => setZaloSigned(n), [])
  const [target, setTarget] = useState<ZaloTarget>({ user_id: opened.fields.user_id ?? '', group: opened.fields.group === 'true', name: opened.fields.name ?? '' })
  const zaloLook = zaloSigned !== null || (channel.configured && channel.secret_last4 !== null)
  const users = useUsers()
  const [zaloKey, setZaloKey] = useState('') // Zalo OA: the app's Secret key and the OA refresh token; empty keeps the saved ones
  const [zaloRefresh, setZaloRefresh] = useState('')
  const zaloGrant = type === 'zalo' && channel.configured && !!channel.fields.app_id && !!channel.secret_last4
  const [appToken, setAppToken] = useState('')
  const [botToken, setBotToken] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [fieldErr, setFieldErr] = useState<Record<string, string>>({})
  const [warn, setWarn] = useState<boolean | null>(null) // null = no warning; value = whether to send a test after saving
  const busy = save.isPending
  const [thenTesting, setThenTesting] = useState(false) // which of Save and Save and send test runs (the busy one)

  function submit(e: FormEvent | { preventDefault(): void }, thenTest = false, confirmed = false) {
    e.preventDefault()
    setError(null)
    // The webhook form checks what it can before sending (same rules and words as the box), so every wrong field shows at once.
    if (showErrors(type === 'webhook' ? checkWebhook() : {})) return
    // Turning the email channel off stops two-step email codes too: say who is affected before doing it.
    if (type === 'email' && channel.enabled && !enabled && codeUsers > 0 && !confirmed) { setWarn(thenTest); return }
    const canApprove = APPROVAL_CHANNELS.includes(type)
    // Slack's channel ID and app tokens only belong to approvals: with approvals off they are not sent.
    const sent = type === 'slack' && !approvals ? Object.fromEntries(Object.entries(fields).filter(([k]) => k !== 'channel_id'))
      : type === 'zalo-personal' ? { user_id: target.user_id, group: target.group ? 'true' : '', name: target.name } : fields
    const zalo = type === 'zalo-personal' ? { zalo_login: zaloSigned !== null } : {}
    setThenTesting(thenTest)
    save.mutate({ type, enabled, fields: sent, secret: secret || undefined, ...(type === 'email' && signin ? { signin } : {}), min_severity: min, ...zalo, ...(canApprove ? { approvals, approvers: approvals ? approvers : [] } : {}), ...(type === 'slack' && approvals ? { app_token: appToken || undefined, bot_token: botToken || undefined } : {}), ...(type === 'zalo' ? { secret_key: zaloKey || undefined, refresh_token: zaloRefresh || undefined } : {}) }, {
      onSuccess: () => {
        toast.success(t('channels.saved', { name }))
        // N-L3: frozen approvers get no new codes, so nothing to stay for
        if (type === 'zalo-personal' && approvals && !thenTest && !approvalsFrozen) { setZaloSigned(null); toast.info(t('zp.codesSent')); return } // stay: show who is linked
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
    // A forbidden target gets the box's precise sentence before the http rule, as the box checks it (webhook.go).
    if (u !== 'url' && url && forbiddenHost(new URL(url).hostname)) errs.url = t(ownHost(new URL(url).hostname) ? 'channels.err.ownUrl' : 'channels.err.blockedUrl')
    else if (u !== 'ok') errs.url = t(u === 'https' ? 'channels.err.insecureUrl' : 'channels.err.badUrl')
    if (secret ? secret.length < 16 : !channel.secret_last4) errs.secret = t(secret ? 'channels.err.shortKey' : 'channels.err.noKey')
    return errs
  }
  // Focus after React has drawn the error, so a screen reader reads the field with its message (as the log source form does).
  function showErrors(errs: Record<string, string>) {
    setFieldErr(errs)
    const first = [...FIELDS[type], 'secret_key', 'refresh_token', 'secret', 'channel_id', 'app_token', 'bot_token'].find((k) => errs[k])
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
  const secretInfo = type === 'zalo' && (zaloGrant || zaloRefresh) ? t('channels.f.zalo.secret.infoGrant') : type === 'email' ? infoOf(emailKeys(prov, 'secret', 'hint')) : infoOf([`channels.f.${type}.secret.hint`])
  const secretHint = type === 'zalo' && (zaloGrant || zaloRefresh) ? t('channels.f.zalo.secret.hintGrant') : type === 'email' && keyOf ? t('channels.f.email.secret.loaded', { email: keyOf }) : keepsSecret ? t('channels.secretSaved', { last4: channel.secret_last4 }) : type === 'email' ? t(emailKeys(prov, 'secret', 'hint')) : t(`channels.f.${type}.secret.hint`)
  // Microsoft Graph sends over HTTPS to a fixed host: no server, port or encryption to show.
  const shown = (k: string) => type !== 'email' || (k !== 'username' || prov.auth !== 'token_as_user') &&
    (prov.auth !== 'microsoft_graph' || !['host', 'port', 'security'].includes(k)) &&
    (k !== 'tenant_id' || prov.auth === 'microsoft_oauth' || prov.auth === 'microsoft_graph' || prov.id === 'microsoft365-user') && (k !== 'client_id' || ['microsoft_oauth', 'microsoft_graph', 'microsoft_user', 'google_user'].includes(prov.auth))
  const pickProvider = (id: string) => {
    const p = emailProvider(id) ?? EMAIL_PROVIDERS[0]!
    if (p.auth !== prov.auth) { setSecret(''); setKeyOf(null) } // a password is not a client secret, nor a key file
    setSignin(null)
    setFields((f) => ({ ...f, provider: p.id, ...(p.host ? { host: p.host, port: p.port, security: p.security } : prov.auth === 'microsoft_graph' ? { host: '', port: '587', security: 'starttls' } : {}), ...(p.username ? { username: p.username } : prov.username && f.username === prov.username ? { username: '' } : {}) }))
    setFieldErr({})
  }
  async function chooseKey(file: File | undefined) {
    if (!file) return
    const text = file.size <= 16384 ? await file.text() : ''
    const who = keyAccount(text)
    setKeyOf(who)
    setSecret(who ? text : '')
    if (who) fixed('secret')
    else showErrors({ secret: t('channels.f.email.secret.notKey') })
  }
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('channels.dialogTitle', { name })} description={t('channels.dialogDesc')}>
        <form onSubmit={submit} className="grid gap-4" noValidate>
          {error ? <Notice tone="danger" role="alert" className="mb-0" title={error} /> : null}
          {type === 'zalo' ? (
            // An Official Account is a business setup on Zalo Developers: the form says so first, offers the personal channel (a QR
            // sign-in) for someone who only wants alerts on their own Zalo, and lists where each value comes from, in order.
            <div role="note" aria-label={t('channels.f.zalo.guideTitle')} className="grid gap-2 rounded-md border border-rule bg-sunken p-3 text-meta">
              <p className="font-medium">{t('channels.f.zalo.guideTitle')}</p>
              <p>{t('channels.f.zalo.guideWho')}</p>
              {onSwitch && !opened.configured ? <Button size="sm" className="w-fit" onClick={() => onSwitch('zalo-personal')}>{t('channels.f.zalo.usePersonal')}</Button> : null}
              <ol className="list-decimal grid gap-1 pl-5">
                {(['s1', 's2', 's3', 's4', 's5'] as const).map((k) => <li key={k}>{t(`channels.f.zalo.steps.${k}`)}</li>)}
              </ol>
              <a className="w-fit text-accent underline underline-offset-4" href={ZALO_OA_DOC} target="_blank" rel="noopener noreferrer">{t('channels.f.zalo.doc')}</a>
            </div>
          ) : null}
          {type === 'zalo-personal' ? null : FIELDS[type].filter(shown).map((k) => {
            const id = `ch-${type}-${k}`
            const label = type === 'email' ? t(emailKeys(prov, k, 'label')) : t(`channels.f.${type}.${k}.label`)
            if (k === 'provider') {
              const steps = t(`channels.f.email.provider.steps.${prov.id}`, { returnObjects: true, defaultValue: {} }) as Record<string, string>
              return (
                <div key={k} className="grid gap-2">
                  <Field label={label} hint={t('channels.f.email.provider.hint')} htmlFor={id} error={fieldErr[k]}>
                    <Select id={id} value={prov.id} {...aria(id, k)} onChange={(e) => pickProvider(e.target.value)}>
                      {(['oauth', 'password', 'service'] as const).map((g) => (
                        <optgroup key={g} label={t(`channels.f.email.provider.group.${g}`)}>
                          {/* a hidden preset stays listed only for the channel already saved with it */}
                          {EMAIL_PROVIDERS.filter((p) => p.group === g && (!p.hidden || p.id === prov.id)).map((p) => <option key={p.id} value={p.id}>{t(`channels.f.email.provider.name.${p.id}`)}</option>)}
                        </optgroup>
                      ))}
                    </Select>
                  </Field>
                  {prov.doc ? (
                    <div role="note" aria-label={t(`channels.f.email.provider.name.${prov.id}`)}>
                      <Notice tone="accent" title={t(`channels.f.email.provider.help.${prov.id}`)} className="mb-0" info={(
                        <>
                          <p>{t(`channels.f.email.provider.helpInfo.${prov.id}`)}</p>
                          {Object.keys(steps).length ? <ol className="list-decimal pl-5">{Object.entries(steps).map(([s, text]) => <li key={s}>{text}</li>)}</ol> : null}
                        </>
                      )}>
                        <div className="grid gap-1.5">
                          <a className="w-fit text-accent underline underline-offset-4" href={prov.doc} target="_blank" rel="noopener noreferrer">{t('channels.f.email.provider.doc', { name: t(`channels.f.email.provider.name.${prov.id}`) })}</a>
                        </div>
                      </Notice>
                    </div>
                  ) : null}
                </div>
              )
            }
            if (k === 'security') {
              return (
                <Field key={k} label={label} htmlFor={id} error={fieldErr[k]}>
                  <Select id={id} value={fields[k] ?? 'starttls'} aria-invalid={fieldErr[k] ? true : undefined} aria-describedby={fieldErr[k] ? `${id}-error` : undefined} onChange={(e) => {
                    const v = e.target.value
                    fixed('security'); fixed('port') // a port/encryption mismatch is shown under the port
                    // The default port follows the encryption type: 465 = implicit SSL/TLS, 587 = STARTTLS or no encryption (unchanged if the user has already set another port).
                    setFields((f) => ({ ...f, security: v, port: v === 'ssl' && f.port === '587' ? '465' : v !== 'ssl' && f.port === '465' ? '587' : f.port ?? '' }))
                  }}>
                    {(['starttls', 'ssl', 'none'] as const).map((o) => <option key={o} value={o}>{t(`channels.f.email.security.${o}`)}</option>)}
                  </Select>
                </Field>
              )
            }
            const hint = type === 'webhook' && k === 'url' && channel.fields.url ? t('channels.urlSaved', { url: channel.fields.url }) : type === 'email' ? t(emailKeys(prov, k, 'hint')) : t(`channels.f.${type}.${k}.hint`)
            const info = infoOf(type === 'email' ? emailKeys(prov, k, 'hint') : [`channels.f.${type}.${k}.hint`])
            const input = (
              <Field key={k} label={label} hint={hint} info={info} htmlFor={id} error={fieldErr[k]}>
                <Input id={id} value={fields[k] ?? ''} type={k === 'port' ? 'number' : 'text'} readOnly={type === 'email' && ((k === 'host' && !!OAUTH_HOST[prov.id]) || (k === 'username' && isUserSignin(prov.auth)))} onChange={(e) => set(k, e.target.value)} autoComplete="off" {...aria(id, k)} />
              </Field>
            )
            // Telegram's Chat ID can be picked from the chats the bot has seen
            return type === 'telegram' && k === 'chat_id' ? (
              <div key={k} className="grid gap-2">
                {input}
                <TelegramFind token={secret} hasSaved={!!channel.secret_last4} chatId={(fields.chat_id ?? '').trim()} onPick={(v) => set('chat_id', v)} onTokenError={(m) => showErrors({ secret: m })} />
              </div>
            ) : input
          })}
          {type === 'email' && prov.auth === 'password' && isMicrosoftSmtp(fields.host) ? <Notice tone="warn" role="note" className="mb-0" title={t('channels.f.email.msBasicEnds')} /> : null}
          {type === 'zalo' ? (
            <div className="grid gap-3">
              <div role="note" aria-label={t('channels.f.zalo.helpTitle')}>
                <Notice tone="accent" title={t('channels.f.zalo.help')} info={t('channels.f.zalo.helpInfo')} className="mb-0" />
              </div>
              <Field label={t('channels.f.zalo.secret_key.label')} hint={zaloGrant ? t('channels.keepSaved') : t('channels.f.zalo.secret_key.hint')} info={t('channels.f.zalo.secret_key.info')} htmlFor="ch-zalo-secret_key" error={fieldErr.secret_key}>
                <Input id="ch-zalo-secret_key" type="password" value={zaloKey} onChange={(e) => { setZaloKey(e.target.value); fixed('secret_key') }} autoComplete="new-password" {...aria('ch-zalo-secret_key', 'secret_key')} />
              </Field>
              <Field label={t('channels.f.zalo.refresh_token.label')} hint={zaloGrant ? t('channels.secretSaved', { last4: channel.secret_last4 }) : t('channels.f.zalo.refresh_token.hint')} info={t('channels.f.zalo.refresh_token.info')} htmlFor="ch-zalo-refresh_token" error={fieldErr.refresh_token}>
                <Input id="ch-zalo-refresh_token" type="password" value={zaloRefresh} onChange={(e) => { setZaloRefresh(e.target.value); fixed('refresh_token') }} autoComplete="new-password" {...aria('ch-zalo-refresh_token', 'refresh_token')} />
              </Field>
            </div>
          ) : null}
          {type === 'zalo-personal' ? (
            <div className="grid gap-3">
              <ZaloWarning />
              <ZaloSignIn channel={channel} onSigned={onZaloSigned} />
              <ZaloRecipient value={target} onChange={(v) => { setTarget(v); fixed('user_id') }} canLook={zaloLook} error={fieldErr.user_id || undefined} />
            </div>
          ) : type === 'email' && isUserSignin(prov.auth) ? (
            <EmailSignin key={prov.id} prov={prov} fields={fields} saved={keepsSecret ? channel.fields.username ?? null : null} error={fieldErr.secret}
              onSignedIn={(id, mailbox) => { setSignin(id); if (id) { setFields((f) => ({ ...f, username: mailbox })); fixed('secret'); fixed('username') } }}
              onFieldError={(f, m) => showErrors({ [f]: m })} />
          ) : type === 'email' && prov.auth === 'google_oauth' ? (
            <Field label={t(emailKeys(prov, 'secret', 'label'))} hint={secretHint} info={secretInfo} htmlFor="ch-email-secret" error={fieldErr.secret}>
              <Input id="ch-email-secret" type="file" accept=".json,application/json" onChange={(e) => void chooseKey(e.target.files?.[0])} {...aria('ch-email-secret', 'secret')} />
            </Field>
          ) : (
            <Field label={type === 'email' ? t(emailKeys(prov, 'secret', 'label')) : t(`channels.f.${type}.secret.label`)} hint={secretHint} info={secretInfo} htmlFor={`ch-${type}-secret`} error={fieldErr.secret}>
              <div className="flex gap-2">
                <Input id={`ch-${type}-secret`} type="password" value={secret} onChange={(e) => { setSecret(e.target.value); fixed('secret') }} autoComplete="new-password" {...aria(`ch-${type}-secret`, 'secret')} />
                {type === 'webhook' ? <Button onClick={() => { setSecret(randomKey()); fixed('secret') }}>{t('channels.generate')}</Button> : null}
              </div>
            </Field>
          )}
          {showApprovals ? (<fieldset className="grid gap-3 rounded-md border border-rule bg-sunken p-3">
            <legend className="flex items-center gap-1 px-1 text-sm font-medium">{t('approve.title')}
              <InfoTip topic={t('approve.title')}>{APPROVAL_CHANNELS.includes(type) ? (
                <>
                  <p>{t(`approve.hintInfo.${type}`)}</p>
                  {type === 'email' ? <ul className="list-disc pl-5">{(['p1', 'p2', 'p3', 'p4'] as const).map((k) => <li key={k}>{t(`approve.email.${k}`)}</li>)}</ul> : null}
                </>
              ) : t('approve.linkOnlyInfo')}</InfoTip>
            </legend>
            {APPROVAL_CHANNELS.includes(type) ? (
              <>
                <div className="flex items-center gap-3">
                  {/* approvals can be turned off here, not on, and the approvers are shown, not changed */}
                  <Switch id={`ch-${type}-appr`} checked={approvals} disabled={approvalsFrozen && !approvals} onCheckedChange={setApprovals} />
                  <Label htmlFor={`ch-${type}-appr`}>{t('approve.switch')}</Label>
                </div>
                <p className="text-meta text-muted">{t(`approve.hint.${type}`)}</p>
                <fieldset disabled={approvalsFrozen} className="m-0 grid min-w-0 gap-3 border-0 p-0">
                {approvals ? (
                  <div className="grid gap-2" role="group" aria-label={t('approve.listTitle')}>
                    <div className="flex items-center gap-1">
                      <span className="text-sm font-medium">{t('approve.listTitle')}</span>
                      <InfoTip topic={t('approve.listTitle')}>{t('approve.viewersInfo')}</InfoTip>
                    </div>
                    {approvers.length === 0 ? <p className="text-meta text-muted">{t('approve.empty')}</p> : null}
                    {approvers.map((a) => {
                      const u = eligible.find((x) => x.id === a.user_id)
                      const who = u?.email ?? a.user_id
                      return (
                        <div key={a.user_id} className="grid items-end gap-2 sm:grid-cols-[1fr_1.4fr_auto]">
                          <div className="grid text-sm"><span className="font-medium">{u?.name ?? a.user_id}</span><span className="text-caption text-muted">{u ? `${u.email}, ${t(`common:role.${u.role}`)}` : ''}</span></div>
                          {type === 'zalo-personal'
                            ? <LinkApproverField approver={a} saved={channel.configured ? channel : null} canLook={zaloLook} onChange={(n) => setApprovers((l) => l.map((x) => (x.user_id === a.user_id ? n : x)))} />
                            : (
                              <div className="grid gap-2">
                                <Field label={t(`approve.address.${type}`)} htmlFor={`ap-${type}-${a.user_id}`}>
                                  <Input id={`ap-${type}-${a.user_id}`} value={a.address} placeholder={t(`approve.placeholder.${type}`)} autoComplete="off" onChange={(e) => setApprovers((l) => l.map((x) => (x.user_id === a.user_id ? { ...x, address: e.target.value } : x)))} />
                                </Field>
                                {/* A Telegram approver confirms the link the bot sends them, signed in as themselves */}
                                {type === 'telegram' ? (channel.configured ? <ApproverLinkState kind="telegram" approver={a} saved={channel} /> : a.address ? <p className="text-meta text-muted">{t('tg.unsaved')}</p> : null) : null}
                              </div>
                            )}
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
                  </div>
                ) : null}
                {type === 'slack' && approvals ? (
                  <>
                    <Field label={t('channels.f.slack.channel_id.label')} hint={t('channels.f.slack.channel_id.hint')} info={t('channels.f.slack.channel_id.info')} htmlFor="ch-slack-channel_id" error={fieldErr.channel_id}>
                      <Input id="ch-slack-channel_id" value={fields.channel_id ?? ''} onChange={(e) => set('channel_id', e.target.value)} autoComplete="off" {...aria('ch-slack-channel_id', 'channel_id')} />
                    </Field>
                    <Field label={t('channels.f.slack.app_token.label')} hint={channel.approval_last4.app_token ? t('channels.secretSaved', { last4: channel.approval_last4.app_token }) : t('channels.f.slack.app_token.hint')} info={t('channels.f.slack.app_token.info')} htmlFor="ch-slack-app_token" error={fieldErr.app_token}>
                      <Input id="ch-slack-app_token" type="password" value={appToken} onChange={(e) => { setAppToken(e.target.value); fixed('app_token') }} autoComplete="new-password" {...aria('ch-slack-app_token', 'app_token')} />
                    </Field>
                    <Field label={t('channels.f.slack.bot_token.label')} hint={channel.approval_last4.bot_token ? t('channels.secretSaved', { last4: channel.approval_last4.bot_token }) : t('channels.f.slack.bot_token.hint')} info={t('channels.f.slack.bot_token.info')} htmlFor="ch-slack-bot_token" error={fieldErr.bot_token}>
                      <Input id="ch-slack-bot_token" type="password" value={botToken} onChange={(e) => { setBotToken(e.target.value); fixed('bot_token') }} autoComplete="new-password" {...aria('ch-slack-bot_token', 'bot_token')} />
                    </Field>
                  </>
                ) : null}
                </fieldset>
              </>
            ) : <p className="text-meta text-muted">{t('approve.linkOnly')}</p>}
          </fieldset>) : null}
          {/* Findings are chosen by their status (the words of every screen), incidents by their severity: each choice says what it sends */}
          <Field label={t('channels.minSeverity')} hint={t('channels.minSeverityHint')} htmlFor={`ch-${type}-min`}>
            <Select id={`ch-${type}-min`} value={min} onChange={(e) => setMin(e.target.value as RouteSeverity)} aria-describedby={`ch-${type}-min-hint ch-${type}-min-sends`}>
              {ROUTE_SEVERITIES.map((s) => <option key={s} value={s}>{t(`channels.level.${s}.option`)}</option>)}
            </Select>
            <p id={`ch-${type}-min-sends`} className="text-meta" data-testid="min-sends">{t(`channels.level.${min}.sends`)}</p>
          </Field>
          <div className="flex items-center gap-3">
            <Switch id={`ch-${type}-on`} checked={enabled} onCheckedChange={setEnabled} />
            <Label htmlFor={`ch-${type}-on`}>{t('channels.enabled')}</Label>
          </div>
          <DialogFooter>
            <Button onClick={onClose}>{t('common:cancel')}</Button>
            <Button disabled={busy} busy={busy && thenTesting} busyLabel={t('common:busy.saving')} onClick={(e) => submit(e, true)}><Send />{t('channels.saveTest')}</Button>
            <Button type="submit" variant="primary" disabled={busy} busy={busy && !thenTesting} busyLabel={t('common:busy.saving')}>{t('channels.save')}</Button>
          </DialogFooter>
        </form>
        <Dialog open={warn !== null} onOpenChange={(o) => { if (!o) setWarn(null) }}>
          <DialogContent title={t('channels.turnOffTitle')} description={t('channels.emailCodes', { count: codeUsers })}>
            <DialogFooter>
              <Button onClick={() => setWarn(null)}>{t('channels.keepEditing')}</Button>
              <Button variant="danger" busy={busy} busyLabel={t('common:busy.saving')} onClick={(e) => { const test = warn === true; setWarn(null); submit(e, test, true) }}>{t('channels.turnOffConfirm')}</Button>
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
  const min = (r: Channel) => (r.configured ? t(`channels.levelShort.${r.min_severity}`) : '')
  const status = (r: Channel) => <Chip tone={!r.configured ? 'off' : r.enabled ? 'ok' : 'off'}>{t(`channels.state.${!r.configured ? 'none' : r.enabled ? 'on' : 'off'}`)}</Chip>
  // A test waits for the far end (up to 45 s, testTimeout): the row says so, and a failure shows its reason as text, not only as a hover title.
  const lastTest = (r: Channel) => {
    if (!r.configured) return null
    if (test.isPending && test.variables === r.type) return <BusyNote busy>{t('channels.testWaiting')}</BusyNote>
    if (!r.last_test) return <span className="text-meta text-muted">{t('channels.testNever')}</span>
    if (r.last_test.ok) return <span className="text-meta text-ok">{t('channels.testOk', { time: fmtDateTime(r.last_test.at) })}</span>
    return (
      <span className="grid min-w-[12rem] max-w-72 gap-0.5">
        <span className="text-meta font-medium text-danger">{t('channels.testFail', { time: fmtDateTime(r.last_test.at) })}</span>
        <span className="text-caption">{r.last_test.detail}</span>
        {r.enabled ? <span className="text-caption text-muted">{t('channels.onButFailed')}</span> : null}
      </span>
    )
  }
  const actions = (r: Channel, stacked = false) => {
    const name = t(`ch.${r.type}`)
    return (
      <div className={stacked ? 'grid justify-items-start gap-1' : 'flex flex-wrap gap-1'}>
        <Button id={`channel-${r.type}`} size="sm" variant={r.configured ? 'secondary' : 'primary'} disabled={!isAdmin} title={need} onClick={() => setEditing(r)}>{r.configured ? t('channels.edit') : t('channels.configure')} <span className="sr-only">{name}</span></Button>
        {r.configured ? (
          <>
            <Button size="sm" disabled={!isAdmin || test.isPending} busy={test.isPending && test.variables === r.type} busyLabel={t('common:busy.sending')} title={need}
              onClick={() => runTest(r.type)}>{t('channels.test')} <span className="sr-only">{name}</span></Button>
            <Button size="sm" variant="ghost" disabled={!isAdmin} title={need} onClick={() => setRemoving(r)}>{t('channels.remove')} <span className="sr-only">{name}</span></Button>
          </>
        ) : null}
      </div>
    )
  }
  // Three columns, so the table fits the ~730 px content column of a 1280 px screen (app sidebar + settings nav): where it sends and
  // from which severity under the channel's name, the last test under its status, the actions stacked.
  const columns: ColumnDef<Channel>[] = [
    { id: 'channel', header: t('channels.col.channel'), accessorFn: (r) => r.type, cell: ({ row: { original: r } }) => (
      <span className="grid gap-0.5">
        {chName(r)}
        {r.configured ? <span className="max-w-[18rem] break-words text-caption text-muted">{dest(r)}</span> : null}
        {r.configured ? <span className="text-caption text-muted">{min(r)}</span> : null}
      </span>
    ) },
    { id: 'status', header: t('channels.col.status'), accessorFn: (r) => (r.configured ? (r.enabled ? 0 : 1) : 2), cell: ({ row: { original: r } }) => (
      <div className="grid justify-items-start gap-1">{status(r)}{lastTest(r)}</div>
    ) },
    { id: 'actions', header: t('channels.col.actions'), enableSorting: false, cell: ({ row }) => actions(row.original, true) },
  ]
  // Under 768 px each channel is a card with its actions in it (the table's pattern, as Feeds does).
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
      {/* #850: the place deep links name (docs/UI.md §0): /settings/channels#channels focuses the first channel's button */}
      <div id="channels"><DataTable urlKey="notify-channels" caption={t('channels.caption')} data={channels} columns={columns} mobileRow={mobileRow}
        summary={t('channels.summary', { count: channels.length, on: channels.filter((c) => c.configured && c.enabled).length })} /></div>
      {editing ? <ChannelDialog key={editing.type} channel={editing} codeUsers={codeUsers} onClose={() => setEditing(null)} onSaved={(thenTest) => { setEditing(null); if (thenTest) runTest(editing.type) }}
        onSwitch={(ty) => setEditing(channels.find((c) => c.type === ty) ?? null)} /> : null}
      <Dialog open={removing !== null} onOpenChange={(o) => { if (!o) setRemoving(null) }}>
        {removing ? (
          <DialogContent title={t('channels.removeTitle', { name: t(`ch.${removing.type}`) })} description={t('channels.removeBody')}>
            {removing.type === 'email' && codeUsers > 0 ? <Notice tone="danger" role="alert" className="mb-0" title={t('channels.emailCodes', { count: codeUsers })} /> : null}
            <DialogFooter>
              <Button onClick={() => setRemoving(null)}>{t('common:cancel')}</Button>
              <Button variant="danger" busy={remove.isPending} busyLabel={t('common:busy.deleting')} onClick={() => remove.mutate(removing.type, { onSuccess: () => { toast.success(t('channels.removed', { name: t(`ch.${removing.type}`) })); setRemoving(null) }, onError: (e) => toast.error(errMsg(e)) })}>{t('common:delete')}</Button>
            </DialogFooter>
          </DialogContent>
        ) : null}
      </Dialog>
    </>
  )
}

/** Where an anchor of this page lives: the quiet hours and grouping are on the Settings tab, the channels on the Channels tab. */
const tabOfAnchor = (id: string): Tab | null => (id === 'quiet-hours' || id === 'grouping' || id === 'alert-rules' || id === 'triggers' || id === 'daily-summary' || id.startsWith('trigger-') ? 'settings' : id === 'channels' || id.startsWith('channel-') ? 'channels' : null)
type Tab = 'channels' | 'settings'

/** A link to an anchor of the other tab (an old bookmark, /settings/channels#quiet-hours) opens that tab and keeps the anchor, so the
 *  field is still found and focused; the send history, once a section of this page, is a page of its own now. */
function AnchorRedirect() {
  const { search, hash } = useLocation()
  const id = decodeURIComponent(hash.slice(1))
  if (id === 'history') return <Navigate replace to="/settings/channels/history" />
  const want = tabOfAnchor(id)
  if (!want) return null
  const p = new URLSearchParams(search)
  const shown: Tab = p.get('tab') === 'settings' ? 'settings' : 'channels'
  if (shown === want) return null
  if (want === 'channels') p.delete('tab')
  else p.set('tab', want)
  const qs = p.toString()
  return <Navigate replace to={{ search: qs ? `?${qs}` : '', hash }} />
}

export default function ChannelsSettings() {
  const { t } = useTranslation('notify')
  const q = useChannels()
  // The send history is a page of its own (filters, pages): the header links to it, next to the page it belongs to
  const history = (
    <Button asChild size="sm">
      <Link to="/settings/channels/history"><HistoryIcon aria-hidden />{t('channels.history')}</Link>
    </Button>
  )
  return (
    <RequireModule module="notify">
      <AnchorRedirect />
      <PageHeader title={t('common:shell.channels')} meta={t('channels.description')} info={t('channels.descriptionInfo')} stories={['S-NOT-1', 'S-NOT-2', 'S-RESP-2']} actions={history} />
        <Notice tone="accent" title={t('channels.privacy')} info={t('channels.privacyInfo')} />
        <QueryState query={q}>
          {(d) => (
            <PageTabs label={t('channels.tabs.label')} tabs={[
              { id: 'channels', label: t('channels.tabs.channels'), panel: <Channels channels={d.channels} codeUsers={d.email_code_users} /> },
              { id: 'settings', label: t('channels.tabs.settings'), panel: <AlertSettings quiet={d.quiet} grouping={d.grouping} triggers={d.triggers} /> },
            ]} />
          )}
        </QueryState>
    </RequireModule>
  )
}
