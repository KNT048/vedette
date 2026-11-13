import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Dialog, DialogClose, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input, Select } from '@/components/ui/input'
import { Segmented } from '@/components/ui/segmented'
import { ApiError } from '@/lib/api'
import { blockedFeedHost, checkFeedUrl, defaultParser, everyLabel, FORMATS } from './defaults'
import { useDeleteCustomFeed, usePatchFeed, useSaveCustomFeed } from './api'
import { ParserEditor } from './ParserEditor'
import type { Feed, FeedAuthType, FeedFormat, FeedKind, Parser } from './types'

const INTERVALS = [1, 3, 6, 12, 24, 72, 168]
const intervalOptions = (cur: number) => [...new Set([...INTERVALS, cur])].sort((a, b) => a - b)
const FIELD_OF: Record<string, 'name' | 'url' | 'auth' | 'parser'> = { invalid_name: 'name', duplicate_name: 'name', invalid_url: 'url', blocked_host: 'url', duplicate_url: 'url', invalid_auth: 'auth', bad_config: 'parser', invalid_format: 'parser' }
const serverField = (e: unknown) => (e instanceof ApiError ? FIELD_OF[e.code] : undefined)

function Interval({ id, value, onChange }: { id: string; value: number; onChange: (n: number) => void }) {
  const { t } = useTranslation('feeds')
  return (
    <Field label={t('dialog.schedule')} htmlFor={id}>
      <Select id={id} value={value} onChange={(e) => onChange(Number(e.target.value))}>{intervalOptions(value).map((n) => <option key={n} value={n}>{everyLabel(t, n)}</option>)}</Select>
    </Field>
  )
}

/** Built-in feed: schedule and mirror address; "Reset to default" restores the original address. */
export function BuiltinDialog({ feed, onClose }: { feed: Feed; onClose: () => void }) {
  const { t } = useTranslation('feeds')
  const patch = usePatchFeed()
  const [hours, setHours] = useState(feed.interval_hours)
  const [url, setUrl] = useState(feed.url)
  const [err, setErr] = useState<string>()
  const urlErr = err ?? (serverField(patch.error) === 'url' ? (patch.error as Error).message : undefined)
  function submit(e: React.FormEvent) {
    e.preventDefault()
    const c = (checkFeedUrl(url) === 'ok' && blockedFeedHost(url)) || checkFeedUrl(url)
    if (c !== 'ok') { setErr(t(`dialog.err.${c}`)); document.getElementById('bf-url')?.focus(); return }
    patch.mutate({ id: feed.id, interval_hours: hours, url: url.trim() }, { onSuccess: () => { toast.success(t('dialog.saved', { name: feed.name })); onClose() }, onError: () => document.getElementById('bf-url')?.focus() })
  }
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('dialog.builtinTitle', { name: feed.name })} description={t('dialog.builtinBody')}>
        <form noValidate onSubmit={submit} className="grid gap-4" aria-label={t('dialog.builtinTitle', { name: feed.name })}>
          <Interval id="bf-hours" value={hours} onChange={setHours} />
          <Field label={t('dialog.address')} htmlFor="bf-url" hint={t('dialog.mirrorHint')} error={urlErr}>
            <Input id="bf-url" value={url} onChange={(e) => { setUrl(e.target.value); setErr(undefined) }} inputMode="url" autoComplete="off" aria-invalid={urlErr ? true : undefined} aria-describedby={urlErr ? 'bf-url-error' : 'bf-url-hint'} />
          </Field>
          <div className="flex flex-wrap items-center gap-3 text-[13px] text-muted">
            <Button type="button" size="sm" disabled={url === feed.default_url} onClick={() => { setUrl(feed.default_url ?? ''); setErr(undefined) }}>{t('dialog.reset')}</Button>
            <span className="break-all">{t('dialog.defaultIs', { url: feed.default_url })}</span>
          </div>
          {patch.error && !serverField(patch.error) ? <p role="alert" className="text-sm text-danger">{(patch.error as Error).message}</p> : null}
          <DialogFooter>
            <DialogClose asChild><Button type="button">{t('common:cancel')}</Button></DialogClose>
            <Button type="submit" variant="primary" disabled={patch.isPending}>{t('common:save')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** Custom feed: name, type, address, auth (secret write-only), schedule and parsing rules. */
export function CustomDialog({ feed, onClose }: { feed: Feed | null; onClose: () => void }) {
  const { t } = useTranslation('feeds')
  const save = useSaveCustomFeed()
  const [name, setName] = useState(feed?.name ?? '')
  const [kind, setKind] = useState<FeedKind>(feed?.kind ?? 'ioc')
  const [url, setUrl] = useState(feed?.url ?? '')
  const [hours, setHours] = useState(feed?.interval_hours ?? 6)
  const [auth, setAuth] = useState<FeedAuthType>(feed?.auth.type ?? 'none')
  // Switching the sign-in type drops what was typed for the other type: back on the saved type, the saved values return.
  const saved = (a: FeedAuthType) => (feed?.auth.type === a ? { header: feed.auth.header_name ?? 'X-Api-Key', user: feed.auth.username ?? '' } : { header: 'X-Api-Key', user: '' })
  const [header, setHeader] = useState(saved(feed?.auth.type ?? 'none').header)
  const [user, setUser] = useState(saved(feed?.auth.type ?? 'none').user)
  const [secret, setSecret] = useState('')
  const [parser, setParser] = useState<Parser>(feed?.parser ?? defaultParser('ioc', 'json'))
  const [errs, setErrs] = useState<Partial<Record<'name' | 'url' | 'auth' | 'parser', string>>>({})
  const last4 = feed?.auth.secret_last4 ?? null
  const hadSecret = !!last4 && feed?.auth.type === auth && auth !== 'none'
  const err = (k: 'name' | 'url' | 'auth' | 'parser') => errs[k] ?? (serverField(save.error) === k ? (save.error as Error).message : undefined)
  const clear = (k: 'name' | 'url' | 'auth' | 'parser') => { setErrs((x) => ({ ...x, [k]: undefined })); save.reset() }

  function pickKind(k: FeedKind) {
    setKind(k)
    const f: FeedFormat = FORMATS[k].includes(parser.format) ? parser.format : FORMATS[k][0]!
    setParser(defaultParser(k, f))
  }
  // Errors can sit far above the button (phone): move focus to the first wrong field, which also scrolls it into view (as HoneypotPage does).
  const focusField = (k: 'name' | 'url' | 'auth' | 'parser' | 'other') => {
    const authId = auth === 'header' && !/^[A-Za-z0-9-]{1,80}$/.test(header) ? 'cf-header' : auth === 'basic' && !user.trim() ? 'cf-user' : 'cf-secret'
    const id = { name: 'cf-name', url: 'cf-url', auth: authId, parser: `pe-${kind === 'ioc' ? 'indicator' : 'cve'}-src`, other: 'cf-error' }[k]
    const go = () => (document.getElementById(id) ?? document.getElementById('pe-format'))?.focus()
    if (k === 'other') setTimeout(go, 0) // the message is drawn after the answer arrives
    else go()
  }
  function submit(e: React.FormEvent) {
    e.preventDefault()
    const n: typeof errs = {}
    if (!name.trim()) n.name = t('dialog.err.name')
    const c = checkFeedUrl(url)
    if (c !== 'ok') n.url = t(`dialog.err.${c}`)
    else if (blockedFeedHost(url)) n.url = t(`dialog.err.${blockedFeedHost(url) as 'blocked' | 'own'}`) // D-420 (1), D-446: the server refuses it too (blocked_host)
    if (auth === 'header' && !/^[A-Za-z0-9-]{1,80}$/.test(header)) n.auth = t('dialog.err.header')
    else if (auth === 'basic' && !user.trim()) n.auth = t('dialog.err.user')
    else if (auth !== 'none' && !secret && !hadSecret) n.auth = t('dialog.err.secret')
    else if (secret && (secret.length < 8 || /\s/.test(secret))) n.auth = t('dialog.err.secretShape')
    if (!parser.fields[kind === 'ioc' ? 'indicator' : 'cve']?.source.trim() && (parser.format === 'json' || parser.format === 'csv' || parser.format === 'rss')) n.parser = t('dialog.err.required', { field: t(`parser.field.${kind === 'ioc' ? 'indicator' : 'cve'}`) })
    setErrs(n)
    const first = (['name', 'url', 'auth', 'parser'] as const).find((k) => n[k])
    if (first) { focusField(first); return }
    save.mutate({ id: feed?.id, name: name.trim(), kind, url: url.trim(), enabled: feed?.enabled ?? true, interval_hours: hours,
      auth: { type: auth, header_name: auth === 'header' ? header : null, username: auth === 'basic' ? user.trim() : null, secret: secret || undefined }, parser },
    { onSuccess: () => { toast.success(feed ? t('dialog.saved', { name: name.trim() }) : t('dialog.added', { name: name.trim() })); onClose() }, onError: (er) => focusField(serverField(er) ?? 'other') })
  }
  // The sign-in error shows under the field that is wrong, not always under the secret.
  const authErr = err('auth')
  const badHeader = !!authErr && auth === 'header' && !/^[A-Za-z0-9-]{1,80}$/.test(header)
  const badUser = !!authErr && auth === 'basic' && !user.trim()
  const aria = (k: 'name' | 'url' | 'auth') => ({ 'aria-invalid': err(k) ? true : undefined, 'aria-describedby': err(k) ? `cf-${k}-error` : undefined })
  const title = feed ? t('dialog.editTitle', { name: feed.name }) : t('dialog.addTitle')
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent wide title={title} description={t('dialog.customBody')}>
        <form noValidate onSubmit={submit} className="grid gap-4" aria-label={title}>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label={t('dialog.name')} htmlFor="cf-name" hint={t('dialog.nameHint')} error={err('name')}>
              <Input id="cf-name" value={name} maxLength={60} onChange={(e) => { setName(e.target.value); clear('name') }} autoComplete="off" {...aria('name')} />
            </Field>
            <div className="grid gap-1.5">
              <span id="cf-kind-label" className="text-sm font-medium">{t('dialog.type')}</span>
              <Segmented<FeedKind> label={t('dialog.type')} value={kind} onChange={pickKind} options={[{ value: 'ioc', label: t('kind.ioc') }, { value: 'vulnerabilities', label: t('kind.vulnerabilities') }]} />
              <p className="text-[13px] text-muted">{t(`dialog.typeHint.${kind}`)}</p>
            </div>
            <Field label={t('dialog.address')} htmlFor="cf-url" hint={t('dialog.urlHint')} error={err('url')} className="sm:col-span-2">
              <Input id="cf-url" value={url} onChange={(e) => { setUrl(e.target.value); clear('url') }} inputMode="url" autoComplete="off" placeholder="https://" {...aria('url')} />
            </Field>
            <Interval id="cf-hours" value={hours} onChange={setHours} />
            <Field label={t('dialog.auth')} htmlFor="cf-auth">
              <Select id="cf-auth" value={auth} onChange={(e) => { const a = e.target.value as FeedAuthType; setAuth(a); setSecret(''); setHeader(saved(a).header); setUser(saved(a).user); clear('auth') }}>{(['none', 'header', 'bearer', 'basic'] as const).map((a) => <option key={a} value={a}>{t(`dialog.authType.${a}`)}</option>)}</Select>
            </Field>
            {auth === 'header' ? <Field label={t('dialog.headerName')} htmlFor="cf-header" error={badHeader ? authErr : undefined}><Input id="cf-header" aria-invalid={badHeader ? true : undefined} value={header} onChange={(e) => { setHeader(e.target.value); clear('auth') }} autoComplete="off" spellCheck={false} /></Field> : null}
            {auth === 'basic' ? <Field label={t('dialog.username')} htmlFor="cf-user" error={badUser ? authErr : undefined}><Input id="cf-user" aria-invalid={badUser ? true : undefined} value={user} onChange={(e) => { setUser(e.target.value); clear('auth') }} autoComplete="off" /></Field> : null}
            {auth !== 'none' ? (
              <Field label={auth === 'basic' ? t('dialog.password') : t('dialog.secret')} htmlFor="cf-secret" error={badHeader || badUser ? undefined : authErr} hint={hadSecret ? t('dialog.secretSaved', { last4 }) : t('dialog.secretHint')}>
                <Input id="cf-secret" type="password" value={secret} onChange={(e) => { setSecret(e.target.value); clear('auth') }} autoComplete="off" placeholder={hadSecret ? `••••${last4}` : ''} {...(badHeader || badUser ? {} : aria('auth'))} />
              </Field>
            ) : null}
          </div>
          <ParserEditor kind={kind} parser={parser} onChange={(p) => { setParser(p); clear('parser') }} onFormat={(f) => { setParser(defaultParser(kind, f)); clear('parser') }} />
          {err('parser') ? <p role="alert" className="text-[13px] text-danger">{err('parser')}</p> : null}
          {save.error && !serverField(save.error) ? <p role="alert" id="cf-error" tabIndex={-1} className="text-sm text-danger outline-none">{(save.error as Error).message}</p> : null}
          <DialogFooter>
            <DialogClose asChild><Button type="button">{t('common:cancel')}</Button></DialogClose>
            <Button type="submit" variant="primary" disabled={save.isPending}>{save.isPending ? t('dialog.saving') : feed ? t('common:save') : t('dialog.addConfirm')}</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export function DeleteDialog({ feed, onClose }: { feed: Feed; onClose: () => void }) {
  const { t } = useTranslation('feeds')
  const del = useDeleteCustomFeed()
  return (
    <Dialog open onOpenChange={(o) => { if (!o) onClose() }}>
      <DialogContent title={t('dialog.deleteTitle', { name: feed.name })} description={t('dialog.deleteBody')}>
        {del.error ? <p role="alert" className="text-sm text-danger">{(del.error as Error).message}</p> : null}
        <DialogFooter>
          <DialogClose asChild><Button type="button">{t('common:cancel')}</Button></DialogClose>
          <Button type="button" variant="danger" disabled={del.isPending} onClick={() => del.mutate(feed.id, { onSuccess: () => { toast.success(t('dialog.deleted', { name: feed.name })); onClose() } })}>{t('common:delete')}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
