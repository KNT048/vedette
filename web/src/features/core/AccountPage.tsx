import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Link } from 'react-router'
import { ApiError } from '@/lib/api'
import { useCan } from '@/lib/session'
import { toast } from 'sonner'
import { PageHeader, Section, KeyValue } from '@/components/common/PageHeader'
import { DataTable, type ColumnDef } from '@/components/common/DataTable'
import { CodeBlock } from '@/components/common/CodeBlock'
import { Chip } from '@/components/common/StatusChip'
import { QueryState } from '@/components/common/States'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent, DialogFooter } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/input'
import { fmtDateTime, fmtRelative } from '@/lib/format'
import { useAccount, useAccountMutations } from './api'
import { PreviewCode, errMsg } from './parts'
import { useCountdown } from './useCountdown'
import { QrCode } from './QrCode'
import { MIN_PASSWORD } from './util'
import type { Account, AccountSession, TotpStart } from './types'

function Profile({ a }: { a: Account }) {
  const { t } = useTranslation('core')
  const m = useAccountMutations()
  const [name, setName] = useState(a.user.name)
  const [error, setError] = useState<string | null>(null)
  async function save(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    if (!name.trim()) { setError(t('account.profile.nameError')); return }
    try { await m.rename.mutateAsync(name.trim()); toast.success(t('common:saved')) } catch (err) { setError(errMsg(err, t)) }
  }
  return (
    <Section title={t('account.profile.title')}>
      <form onSubmit={(e) => void save(e)} className="grid max-w-md gap-4" noValidate>
        <Field label={t('account.profile.name')} htmlFor="acc-name" error={error ?? undefined}><Input id="acc-name" value={name} maxLength={80} aria-invalid={!!error} onChange={(e) => setName(e.target.value)} /></Field>
        <KeyValue items={[{ label: t('account.profile.email'), value: a.user.email }, { label: t('account.profile.role'), value: t(`common:role.${a.user.role}`) }, { label: t('account.profile.lastLogin'), value: fmtDateTime(a.user.last_login) }]} />
        <div><Button type="submit" variant="primary" disabled={m.rename.isPending || name.trim() === a.user.name}>{t('common:save')}</Button></div>
      </form>
    </Section>
  )
}

function Password() {
  const { t } = useTranslation('core')
  const m = useAccountMutations()
  const [v, setV] = useState({ current: '', next: '', again: '' })
  const [err, setErr] = useState<{ current?: string; next?: string; again?: string }>({})
  async function save(e: React.FormEvent) {
    e.preventDefault()
    const n: typeof err = {}
    if (!v.current) n.current = t('account.password.currentError')
    if (v.next.length < MIN_PASSWORD) n.next = t('account.password.shortError', { min: MIN_PASSWORD })
    else if (v.next !== v.again) n.again = t('account.password.mismatch')
    setErr(n)
    if (n.current || n.next || n.again) return
    try {
      await m.password.mutateAsync({ current: v.current, next: v.next })
      setV({ current: '', next: '', again: '' })
      toast.success(t('account.password.done'))
    } catch (e2) { setErr({ current: errMsg(e2, t) }) }
  }
  return (
    <Section title={t('account.password.title')} description={t('account.password.desc', { min: MIN_PASSWORD })}>
      <form onSubmit={(e) => void save(e)} className="grid max-w-md gap-4" noValidate>
        <Field label={t('account.password.current')} htmlFor="pw-current" error={err.current}><Input id="pw-current" type="password" autoComplete="current-password" value={v.current} aria-invalid={!!err.current} onChange={(e) => setV({ ...v, current: e.target.value })} /></Field>
        <Field label={t('account.password.next')} htmlFor="pw-next" error={err.next}><Input id="pw-next" type="password" autoComplete="new-password" value={v.next} aria-invalid={!!err.next} onChange={(e) => setV({ ...v, next: e.target.value })} /></Field>
        <Field label={t('account.password.again')} htmlFor="pw-again" error={err.again}><Input id="pw-again" type="password" autoComplete="new-password" value={v.again} aria-invalid={!!err.again} onChange={(e) => setV({ ...v, again: e.target.value })} /></Field>
        <div><Button type="submit" variant="primary" disabled={m.password.isPending}>{t('account.password.submit')}</Button></div>
      </form>
    </Section>
  )
}

type Setup = { kind: 'app'; start: TotpStart } | { kind: 'email'; sentTo: string; preview?: string }

function TwoFactor({ a }: { a: Account }) {
  const { t } = useTranslation('core')
  const m = useAccountMutations()
  const isAdmin = useCan('admin')
  const [setup, setSetup] = useState<Setup | null>(null)
  const [code, setCode] = useState('')
  const [codeErr, setCodeErr] = useState<string | null>(null)
  const [askOff, setAskOff] = useState(false)
  const [pw, setPw] = useState('')
  const [pwErr, setPwErr] = useState<string | null>(null)
  // D-76: the current password, asked once on the choice screen and sent with either start call (and with "send a new code").
  const [startPw, setStartPw] = useState('')
  const [startPwErr, setStartPwErr] = useState<string | null>(null)
  const cooldown = useCountdown()
  const method = a.user.twofa_method
  const email = a.twofa_email

  async function startApp() {
    setStartPwErr(null)
    try { setSetup({ kind: 'app', start: await m.start2fa.mutateAsync(startPw) }); setCode(''); setCodeErr(null) } catch (e) { setStartPwErr(errMsg(e, t)) }
  }
  async function sendEmail() {
    try {
      setStartPwErr(null)
      const r = await m.startEmail2fa.mutateAsync(startPw)
      setSetup({ kind: 'email', sentTo: r.sent_to, preview: (r as { preview_code?: string }).preview_code }); setCode(''); setCodeErr(null); cooldown.start(r.resend_after)
    } catch (e) {
      // 429 resend_too_soon: the code already sent is still valid, so keep the form and just show the wait
      if (e instanceof ApiError && e.code === 'resend_too_soon') cooldown.start(Number(e.details.retry_after ?? 60))
      if (setup) setCodeErr(errMsg(e, t)); else setStartPwErr(errMsg(e, t))
    }
  }
  async function confirm(e: React.FormEvent) {
    e.preventDefault()
    setCodeErr(null)
    try {
      if (setup?.kind === 'email') await m.confirmEmail2fa.mutateAsync(code.trim()); else await m.confirm2fa.mutateAsync(code.trim())
      setSetup(null); setStartPw('')
      toast.success(t('account.twofa.enabled'))
    } catch (err) { setCodeErr(errMsg(err, t)) }
  }
  async function off() {
    setPwErr(null)
    try { await m.disable2fa.mutateAsync(pw); setAskOff(false); setPw(''); toast.success(t('account.twofa.disabled')) } catch (err) { setPwErr(errMsg(err, t)) }
  }
  const busy = m.confirm2fa.isPending || m.confirmEmail2fa.isPending
  const reason = email.reason === 'module_off' ? t('account.twofa.email.moduleOff') : t('account.twofa.email.notReady')
  return (
    <Section title={t('account.twofa.title')} description={t('account.twofa.desc')} actions={method ? <Chip tone="ok">{t('account.twofa.onWith', { method: t(`account.twofa.method.${method}`) })}</Chip> : <Chip tone="off">{t('account.twofa.off')}</Chip>}>
      {method ? (
        <div className="grid max-w-xl gap-4">
          <p className="text-sm">{method === 'email' ? t('account.twofa.emailActive', { to: email.sent_to }) : t('account.twofa.appActive')}</p>
          <div><Button variant="danger" onClick={() => { setPw(''); setPwErr(null); setAskOff(true) }}>{t('account.twofa.turnOff')}</Button></div>
        </div>
      ) : setup ? (
        <form onSubmit={(e) => void confirm(e)} className="grid max-w-xl gap-4" noValidate>
          {setup.kind === 'app' ? (
            <>
              <p className="text-sm">{t('account.twofa.app.scan')}</p>
              <QrCode value={setup.start.otpauth} label={t('account.twofa.app.qrLabel')} />
              <CodeBlock label={t('account.twofa.key')} code={setup.start.secret} />
              <CodeBlock label={t('account.twofa.uri')} code={setup.start.otpauth} />
              <p className="text-sm">{t('account.twofa.app.enter')}</p>
            </>
          ) : (
            <>
              <p className="text-sm" role="status">{t('account.twofa.email.sent', { to: setup.sentTo })}</p>
              <PreviewCode code={setup.preview} />
            </>
          )}
          <Field label={t('account.twofa.code')} hint={setup.kind === 'app' ? t('account.twofa.codeHint') : t('account.twofa.email.codeHint')} htmlFor="totp-code" error={codeErr ?? undefined}>
            <Input id="totp-code" inputMode="numeric" autoComplete="one-time-code" maxLength={7} value={code} aria-invalid={!!codeErr} onChange={(e) => setCode(e.target.value)} className="max-w-40" />
          </Field>
          <div className="flex flex-wrap gap-2">
            <Button type="submit" variant="primary" disabled={busy}>{t('account.twofa.confirm')}</Button>
            {setup.kind === 'email' ? <Button disabled={cooldown.left > 0 || m.startEmail2fa.isPending} onClick={() => void sendEmail()}>{cooldown.left > 0 ? t('account.twofa.email.resendIn', { s: cooldown.left }) : t('account.twofa.email.resend')}</Button> : null}
            <Button onClick={() => setSetup(null)}>{t('common:cancel')}</Button>
          </div>
        </form>
      ) : (
        <div className="grid gap-4">
          <Field label={t('account.twofa.startPassword')} hint={t('account.twofa.startPasswordHint')} htmlFor="twofa-start-pw" error={startPwErr ?? undefined}>
            <Input id="twofa-start-pw" type="password" autoComplete="current-password" value={startPw} aria-invalid={!!startPwErr} onChange={(e) => setStartPw(e.target.value)} className="max-w-sm" />
          </Field>
          <div className="grid gap-4 md:grid-cols-2">
          <div className="grid content-start gap-3 rounded-md border border-rule bg-surface p-4">
            <h3 className="text-sm font-semibold">{t('account.twofa.method.app')}</h3>
            <p className="text-[13px] text-muted">{t('account.twofa.app.desc')}</p>
            <div><Button variant="primary" onClick={() => void startApp()} disabled={!startPw || m.start2fa.isPending}>{t('account.twofa.app.setup')}</Button></div>
          </div>
          <div className="grid content-start gap-3 rounded-md border border-rule bg-surface p-4">
            <h3 className="text-sm font-semibold">{t('account.twofa.method.email')}</h3>
            <p className="text-[13px] text-muted">{t('account.twofa.email.desc', { to: email.sent_to })}</p>
            {email.available ? null : (
              <p id="twofa-email-why" className="text-[13px]">
                {reason}{' '}
                {isAdmin
                  ? <Link className="text-accent underline-offset-4 hover:underline" to={email.reason === 'module_off' ? '/settings/modules' : '/settings/channels'}>{email.reason === 'module_off' ? t('account.twofa.email.openModules') : t('account.twofa.email.openChannels')}</Link>
                  : t('account.twofa.email.askAdmin')}
              </p>
            )}
            <div><Button variant="primary" disabled={!startPw || !email.available || m.startEmail2fa.isPending} aria-describedby={email.available ? undefined : 'twofa-email-why'} onClick={() => void sendEmail()}>{t('account.twofa.email.setup')}</Button></div>
          </div>
          </div>
        </div>
      )}
      <Dialog open={askOff} onOpenChange={setAskOff}>
        <DialogContent title={t('account.twofa.offAsk.title')} description={t('account.twofa.offAsk.body')}>
          <Field label={t('account.twofa.offAsk.password')} htmlFor="twofa-off-pw" error={pwErr ?? undefined}><Input id="twofa-off-pw" type="password" autoComplete="current-password" value={pw} aria-invalid={!!pwErr} onChange={(e) => setPw(e.target.value)} /></Field>
          <DialogFooter><Button onClick={() => setAskOff(false)}>{t('common:cancel')}</Button><Button variant="danger" disabled={!pw || m.disable2fa.isPending} onClick={() => void off()}>{t('account.twofa.offAsk.confirm')}</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </Section>
  )
}

/** D-195, D-196: an SSO account has no Vedette password and no Vedette two-step sign-in; the identity provider handles both. */
function SsoNote() {
  const { t } = useTranslation('core')
  return (
    <Section title={t('account.sso.title')}>
      <p className="max-w-prose text-sm">{t('account.sso.body')}</p>
    </Section>
  )
}

function Sessions({ a }: { a: Account }) {
  const { t } = useTranslation('core')
  const m = useAccountMutations()
  const columns: ColumnDef<AccountSession>[] = [
    { id: 'device', header: t('account.sessions.device'), accessorFn: (s) => s.device, cell: ({ row }) => <span className="font-medium">{row.original.device}{row.original.current ? <span className="ml-2"><Chip tone="accent">{t('account.sessions.current')}</Chip></span> : null}</span> },
    { id: 'ip', header: t('account.sessions.ip'), accessorFn: (s) => s.ip },
    { id: 'started', header: t('account.sessions.started'), accessorFn: (s) => s.started_at, cell: ({ row }) => fmtDateTime(row.original.started_at) },
    { id: 'last', header: t('account.sessions.last'), accessorFn: (s) => s.last_seen, cell: ({ row }) => fmtRelative(row.original.last_seen) },
    { id: 'end', header: t('account.sessions.end'), enableSorting: false, accessorFn: () => '', cell: ({ row }) => (row.original.current ? <span className="text-muted">–</span> : (
      <Button size="sm" aria-label={t('account.sessions.endOf', { device: row.original.device })} disabled={m.revoke.isPending} onClick={() => void m.revoke.mutateAsync(row.original.id).then(() => toast.success(t('account.sessions.ended'))).catch((e) => toast.error(errMsg(e, t)))}>{t('account.sessions.endBtn')}</Button>
    )) },
  ]
  const others = a.sessions.filter((s) => !s.current).length
  return (
    <Section title={t('account.sessions.title')} description={t('account.sessions.desc')} actions={others ? <Button onClick={() => void m.revokeOthers.mutateAsync().then(() => toast.success(t('account.sessions.endedAll'))).catch((e) => toast.error(errMsg(e, t)))}>{t('account.sessions.endOthers')}</Button> : undefined}>
      <DataTable data={a.sessions} columns={columns} caption={t('account.sessions.title')} />
    </Section>
  )
}

export default function AccountPage() {
  const { t } = useTranslation('core')
  const q = useAccount()
  return (
    <>
      <PageHeader title={q.data ? t('account.title', { name: q.data.user.name }) : t('account.titleLoading')} meta={t('account.meta')} stories={['S-CORE-3']} />
      <QueryState query={q}>{(a) => <><Profile a={a} />{a.user.sso ? <SsoNote /> : <><Password /><TwoFactor a={a} /></>}<Sessions a={a} /></>}</QueryState>
    </>
  )
}
