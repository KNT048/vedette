import { useEffect, useState, type FormEvent } from 'react'
import { useNavigate, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '@/lib/api'
import { useSetup } from './RequireSession'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/input'
import { useAuthOptions } from '@/features/core/api'
import { PreviewCode } from '@/features/core/parts'
import { useCountdown } from '@/features/core/useCountdown'
import { saveSsoFlow, safeNext } from '@/features/core/ssoFlow'
import type { OidcStart } from '@/features/core/types'

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
  // Bước hai: ứng dụng xác thực hay mã gửi qua email (D-35); với email thì biết mã đã gửi tới đâu.
  const [second, setSecond] = useState<{ method: 'app' | 'email'; sentTo?: string; preview?: string; resent?: boolean }>({ method: 'app' })
  const cooldown = useCountdown()
  const [busy, setBusy] = useState(false)
  const [ssoError, setSsoError] = useState<string | null>(null)
  const [ssoBusy, setSsoBusy] = useState(false)
  // Back from the identity provider through the browser cache: the page comes back as it was left, still "busy".
  useEffect(() => {
    const back = (e: PageTransitionEvent) => { if (e.persisted) { setBusy(false); setSsoBusy(false) } }
    window.addEventListener('pageshow', back)
    return () => window.removeEventListener('pageshow', back)
  }, [])
  // Gợi ý tài khoản mẫu chỉ khi đang chạy dữ liệu mẫu (cài sạch không có các tài khoản này).
  const setup = useSetup()
  const mock = import.meta.env.VITE_API_MOCK !== 'off' && setup.data?.data_mode === 'sample'
  const sso = useAuthOptions().data?.oidc === true

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await api.post('/auth/login', needCode ? { email, password, code } : { email, password })
      qc.removeQueries({ queryKey: ['me'] }) // /me đã được lưu là "chưa đăng nhập"; bỏ hẳn để trang đích chờ dữ liệu mới thay vì bật về /login
      await qc.invalidateQueries()
      navigate(safeNext(params.get('next')), { replace: true })
    } catch (err) {
      if (err instanceof ApiError && err.code === 'twofa_required') {
        const d = err.details
        setNeedCode(true); setError(null)
        setSecond({ method: d.method === 'email' ? 'email' : 'app', sentTo: d.sent_to as string | undefined, preview: d.preview_code as string | undefined })
        if (d.method === 'email') cooldown.start(Number(d.resend_after ?? 60))
      } else setError(err instanceof ApiError ? err.message : t('error.unknown'))
    } finally {
      setBusy(false)
    }
  }

  async function resend() {
    setBusy(true)
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
      setBusy(false)
    }
  }

  // D-194: the box returns the identity provider's address and a binding; the binding stays in this tab's session storage until
  // /sso/callback posts it back, so a sign-in can only finish in the tab that started it. No cookie is added.
  async function signInSso() {
    setBusy(true)
    setSsoBusy(true)
    setSsoError(null)
    try {
      const r = await api.post<OidcStart>('/auth/oidc/start')
      saveSsoFlow({ binding: r.binding, next: safeNext(params.get('next')) })
      window.location.assign(r.authorize_url)
    } catch (err) {
      setSsoError(err instanceof ApiError ? err.message : t('error.unknown'))
      setBusy(false)
      setSsoBusy(false)
    }
  }

  return (
    <main className="grid min-h-dvh place-items-center bg-paper px-4">
      <div className="w-full max-w-sm">
        <h1 className="text-2xl font-semibold tracking-[-0.01em]">Vedette</h1>
        <p className="mt-1 text-sm text-muted">{t('login.subtitle')}</p>
        <form onSubmit={(e) => void submit(e)} className="mt-6 grid gap-4 rounded-md border border-rule bg-surface p-5" noValidate>
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
                  {second.resent ? <p role="status" className="text-[13px]">{t('core:login.resent', { to: second.sentTo })}</p> : null}
                  <Button disabled={busy || cooldown.left > 0} onClick={() => void resend()}>{cooldown.left > 0 ? t('core:login.resendIn', { s: cooldown.left }) : t('core:login.resend')}</Button>
                </>
              ) : null}
            </>
          ) : null}
          <Button type="submit" variant="primary" disabled={busy || !email || !password || (needCode && !code)}>{busy && !ssoBusy ? t('login.signingIn') : t('login.signIn')}</Button>
          {sso ? <Button onClick={() => void signInSso()} disabled={busy}>{ssoBusy ? t('core:login.ssoStarting') : t('core:login.sso')}</Button> : null}
          {ssoError ? <p role="alert" className="text-[13px] text-danger">{ssoError}</p> : null}
        </form>
        {mock ? <p className="mt-4 text-[13px] text-muted">{t('login.demoHint')}</p> : null}
      </div>
    </main>
  )
}
