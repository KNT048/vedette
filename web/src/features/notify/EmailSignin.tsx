// The user sign-in of the email channel (S-NOT-1, D-480): Microsoft's device code (the box polls at Microsoft's interval) or Google's
// consent page with the customer's own Desktop client, whose loopback address the admin pastes back. The refresh token stays on the
// box: the dialog only keeps the sign-in id, which the save sends.
import { useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { LoaderCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/input'
import { ApiError } from '@/lib/api'
import { useCheckEmailSignin, useStartEmailSignin } from './api'
import type { EmailProvider } from './emailProviders'
import type { EmailSignin as Signin } from './types'

/** Where a refusal of the sign-in routes go: the field its code names, else under the sign-in. */
const SIGNIN_FIELD: Record<string, string> = { bad_tenant_id: 'tenant_id', bad_client_id: 'client_id' }

export function EmailSignin({ prov, fields, saved, error, onSignedIn, onFieldError }: {
  prov: EmailProvider
  fields: Record<string, string>
  /** The mailbox the saved channel is signed in as, when the saved sign-in fits these settings. */
  saved: string | null
  error?: string
  onSignedIn: (id: string | null, mailbox: string) => void
  onFieldError: (field: string, message: string) => void
}) {
  const { t } = useTranslation('notify')
  const start = useStartEmailSignin()
  const check = useCheckEmailSignin()
  const [s, setS] = useState<Signin | null>(null)
  const [clientSecret, setClientSecret] = useState('')
  const [pasted, setPasted] = useState('')
  const [err, setErr] = useState<string | null>(null)
  const google = prov.auth === 'google_user'
  const who = t(google ? 'signin.google' : 'signin.microsoft')
  const busy = start.isPending || check.isPending

  const fail = (e: unknown) => {
    const field = e instanceof ApiError ? SIGNIN_FIELD[e.code] : undefined
    const msg = e instanceof ApiError ? e.message : String(e)
    if (field) onFieldError(field, msg)
    else setErr(msg)
  }
  const got = (v: Signin) => {
    setS(v)
    if (v.status === 'signed_in' && v.mailbox) onSignedIn(v.id, v.mailbox)
  }
  const begin = () => {
    setErr(null)
    onSignedIn(null, '')
    start.mutate({ provider: prov.id as Signin['provider'], client_id: (fields.client_id ?? '').trim(), ...(google ? { client_secret: clientSecret.trim() } : { tenant_id: (fields.tenant_id ?? '').trim() }) }, { onSuccess: got, onError: fail })
  }
  const poll = (url?: string) => { if (s) { setErr(null); check.mutate({ id: s.id, url }, { onSuccess: got, onError: fail }) } }

  // A device sign-in is checked at Microsoft's interval while it waits (the box never asks Microsoft sooner).
  const pollRef = useRef(poll)
  useEffect(() => { pollRef.current = poll })
  useEffect(() => {
    if (s?.flow !== 'device' || s.status !== 'waiting') return
    const h = setTimeout(() => pollRef.current(), Math.max(s.interval ?? 5, 5) * 1000)
    return () => clearTimeout(h)
  }, [s])

  const status = s ? t(`signin.status.${s.status}`, { mailbox: s.mailbox, who }) : saved ? t('signin.saved', { mailbox: saved }) : t('signin.none', { who })
  return (
    <div className="grid gap-3 rounded-md border border-rule p-3">
      <span className="text-sm font-medium">{t('signin.title', { who })}</span>
      {google ? (
        <Field label={t('signin.clientSecret')} hint={t('signin.clientSecretHint')} htmlFor="ch-email-client_secret">
          <Input id="ch-email-client_secret" type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} autoComplete="new-password" />
        </Field>
      ) : null}
      <p role="status" className="text-[13px]">{status}</p>
      {s?.flow === 'device' && s.status === 'waiting' ? (
        <div className="grid gap-1.5 text-[13px]">
          <p>{t('signin.deviceOpen')} <a className="text-accent underline underline-offset-4" href={s.verification_uri} target="_blank" rel="noopener noreferrer">{s.verification_uri}</a></p>
          <p>{t('signin.deviceCode')} <code aria-label={t('signin.codeLabel')} className="rounded bg-sunken px-2 py-1 font-mono text-base tracking-widest">{s.user_code}</code></p>
          <div><Button size="sm" disabled={busy} onClick={() => poll()}>{check.isPending ? <LoaderCircle className="size-4 animate-spin motion-reduce:animate-none" aria-hidden /> : null}{t('signin.checkNow')}</Button></div>
        </div>
      ) : null}
      {s?.flow === 'paste' && s.status === 'waiting' ? (
        <div className="grid gap-2 text-[13px]">
          <ol className="list-decimal pl-5">
            <li><a className="text-accent underline underline-offset-4" href={s.consent_url} target="_blank" rel="noopener noreferrer">{t('signin.pasteOpen')}</a></li>
            <li>{t('signin.pasteStep2')}</li>
            <li>{t('signin.pasteStep3')}</li>
          </ol>
          <Field label={t('signin.pasteLabel')} htmlFor="ch-email-pasted">
            <Input id="ch-email-pasted" value={pasted} onChange={(e) => setPasted(e.target.value)} placeholder="http://127.0.0.1:…/?state=…&code=…" autoComplete="off" />
          </Field>
          <div><Button size="sm" disabled={busy || !pasted.trim()} onClick={() => poll(pasted)}>{t('signin.finish')}</Button></div>
        </div>
      ) : null}
      {err || error ? <p role="alert" className="text-[13px] text-danger [overflow-wrap:anywhere]">{err ?? error}</p> : null}
      <div>
        <Button id="ch-email-secret" disabled={busy} onClick={begin}>
          {start.isPending ? <LoaderCircle className="size-4 animate-spin motion-reduce:animate-none" aria-hidden /> : null}
          {s || saved ? t('signin.again', { who }) : t('signin.start', { who })}
        </Button>
      </div>
    </div>
  )
}
