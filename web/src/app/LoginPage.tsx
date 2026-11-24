import { useEffect, useState, type FormEvent } from 'react'
import { useNavigate, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '@/lib/api'
import { useSetup } from './RequireSession'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/input'
import { StandalonePage } from '@/components/common/StandalonePage'
import { Card } from '@/components/common/Card'
import { useAuthOptions } from '@/features/core/api'
import { PreviewCode } from '@/features/core/parts'
import { useCountdown } from '@/features/core/useCountdown'
import { saveSsoFlow, safeNext } from '@/features/core/ssoFlow'
import type { LoginResult, OidcStart } from '@/features/core/types'

export default function LoginPage() {
  const { t } = useTranslation()
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [needCode, setNeedCode] = useState(false)
  // Second step: an authenticator app or a code sent by email; with email, the user is told where the code was sent.
  const [second, setSecond] = useState<{ method: 'app' | 'email'; sentTo?: string; preview?: string; resent?: boolean }>({ method: 'app' })
  const cooldown = useCountdown()
  // Which request is waiting on the box: signing in, sending a new code, or starting single sign-on (one at a time).
  const [wait, setWait] = useState<'signIn' | 'resend' | 'sso' | null>(null)
  const busy = wait !== null
  const [ssoError, setSsoError] = useState<string | null>(null)
  // Back from the identity provider through the browser cache: the page comes back as it was left, still "busy".
  useEffect(() => {
    const back = (e: PageTransitionEvent) => { if (e.persisted) setWait(null) }
    window.addEventListener('pageshow', back)
    return () => window.removeEventListener('pageshow', back)
  }, [])
  // Hint the sample accounts only when running on sample data (a clean install does not have these accounts).
  const setup = useSetup()
  const mock = import.meta.env.VITE_API_MOCK !== 'off' && setup.data?.data_mode === 'sample'
  const sso = useAuthOptions().data?.oidc === true

  async function submit(e: FormEvent) {
    e.preventDefault()
    setWait('signIn')
    setError(null)
    try {
      const r = await api.post<LoginResult>('/auth/login', needCode ? { email, password, code } : { email, password })
      // The password was right and the account has two-step sign-in: a normal step (200, no session yet), not an error.
      if (!r.ok && r.twofa) {
        const d = r.twofa
        setNeedCode(true)
        setSecond({ method: d.method, sentTo: d.sent_to, preview: d.preview_code })
        if (d.method === 'email') cooldown.start(d.resend_after ?? 60)
        return
      }
      qc.removeQueries({ queryKey: ['me'] }) // /me was cached as "not signed in"; drop it entirely so the target page waits for fresh data instead of bouncing back to /login
      await qc.invalidateQueries()
      navigate(safeNext(params.get('next')), { replace: true })
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t('error.unknown'))
    } finally {
      setWait(null)
    }
  }

  async function resend() {
    setWait('resend')
    setError(null)
    try {
      const r = await api.post<{ sent_to: string; resend_after: number; preview_code?: string }>('/auth/login/resend-code', { email, password })
      setSecond({ method: 'email', sentTo: r.sent_to, preview: r.preview_code, resent: true })
      setCode('')
      cooldown.start(r.resend_after)
    } catch (err) {
      if (err instanceof ApiError && err.code === 'resend_too_soon') cooldown.start(Number(err.details.retry_after ?? 60))
      setError(err instanceof ApiError ? err.message : t('error.unknown'))
    } finally {
      setWait(null)
    }
  }

  // The box returns the identity provider's address and a binding; the binding stays in this tab's session storage until
  // /sso/callback posts it back, so a sign-in can only finish in the tab that started it. No cookie is added.
  async function signInSso() {
    setWait('sso')
    setSsoError(null)
    try {
      const r = await api.post<OidcStart>('/auth/oidc/start')
      saveSsoFlow({ binding: r.binding, next: safeNext(params.get('next')) })
      window.location.assign(r.authorize_url)
    } catch (err) {
      setSsoError(err instanceof ApiError ? err.message : t('error.unknown'))
      setWait(null)
    }
  }

  return (
    <StandalonePage subtitle={t('login.subtitle')} footer={mock ? t('login.demoHint') : undefined}>
      <Card>
          <form onSubmit={(e) => void submit(e)} className="grid gap-4" noValidate>
            <Field label={t('login.email')} htmlFor="email">
              <Input id="email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} aria-invalid={!!error} />
            </Field>
            <Field label={t('login.password')} htmlFor="password" error={needCode ? undefined : (error ?? undefined)}>
              <Input id="password" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} aria-invalid={!!error && !needCode} aria-describedby={error && !needCode ? 'password-error' : undefined} />
            </Field>
            {needCode ? (
              <>
                <Field label={t('core:login.code')} hint={second.method === 'email' ? t('core:login.codeHintEmail', { to: second.sentTo }) : t('core:login.codeHint')} htmlFor="code" error={error ?? undefined}>
                  <Input id="code" inputMode="numeric" autoComplete="one-time-code" autoFocus maxLength={7} value={code} onChange={(e) => setCode(e.target.value)} aria-invalid={!!error} />
                </Field>
                {second.method === 'email' ? (
                  <>
                    <PreviewCode code={second.preview} />
                    {second.resent ? <p role="status" className="text-meta">{t('core:login.resent', { to: second.sentTo })}</p> : null}
                    <Button disabled={busy || cooldown.left > 0} busy={wait === 'resend'} busyLabel={t('busy.sending')} onClick={() => void resend()}>{cooldown.left > 0 ? t('core:login.resendIn', { s: cooldown.left }) : t('core:login.resend')}</Button>
                  </>
                ) : null}
              </>
            ) : null}
            <Button type="submit" variant="primary" disabled={busy || !email || !password || (needCode && !code)} busy={wait === 'signIn'} busyLabel={t('busy.signingIn')}>{t('login.signIn')}</Button>
            {sso ? <Button onClick={() => void signInSso()} disabled={busy} busy={wait === 'sso'} busyLabel={t('core:login.ssoStarting')}>{t('core:login.sso')}</Button> : null}
            {ssoError ? <p role="alert" className="text-meta text-danger">{ssoError}</p> : null}
          </form>
      </Card>
    </StandalonePage>
  )
}
