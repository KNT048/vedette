import { useState, type FormEvent } from 'react'
import { Navigate, useNavigate, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '@/lib/api'
import { useMe } from '@/lib/session'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/input'
import { Loading } from '@/components/common/States'
import { MIN_PASSWORD } from './util'

/** D-180 (S-CORE-3): the screen of a user who signed in with a password an administrator set. Same rules as My account → Change password. */
export default function ChangePasswordPage() {
  const { t } = useTranslation('core')
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const me = useMe()
  const [v, setV] = useState({ current: '', next: '', again: '' })
  const [err, setErr] = useState<{ current?: string; next?: string; again?: string }>({})
  const [busy, setBusy] = useState(false)
  const next = params.get('next')
  const dest = next && next.startsWith('/') && !next.startsWith('//') ? next : '/'

  if (me.isPending) return <div className="p-8"><Loading /></div>
  if (!me.data) return <Navigate to={`/login?next=${encodeURIComponent(`/change-password?next=${encodeURIComponent(dest)}`)}`} replace />
  if (!me.data.password_change_required) return <Navigate to={dest} replace />

  async function submit(e: FormEvent) {
    e.preventDefault()
    const n: typeof err = {}
    if (!v.current) n.current = t('changePassword.currentError')
    if (v.next.length < MIN_PASSWORD) n.next = t('account.password.shortError', { min: MIN_PASSWORD })
    else if (v.next === v.current) n.next = t('changePassword.sameError')
    else if (v.next !== v.again) n.again = t('account.password.mismatch')
    setErr(n)
    if (n.current || n.next || n.again) return
    setBusy(true)
    try {
      await api.post('/core/account/password', { current: v.current, next: v.next })
      qc.removeQueries({ queryKey: ['me'] })
      await qc.invalidateQueries()
      navigate(dest, { replace: true })
    } catch (e2) {
      const msg = e2 instanceof ApiError ? e2.message : t('common:error.unknown')
      if (e2 instanceof ApiError && (e2.code === 'weak_password' || e2.code === 'same_password')) setErr({ next: msg })
      else setErr({ current: msg })
    } finally {
      setBusy(false)
    }
  }
  async function signOut() {
    try { await api.post('/auth/logout') } finally { qc.clear(); navigate('/login', { replace: true }) }
  }

  return (
    <main className="grid min-h-dvh place-items-center bg-paper px-4">
      <div className="w-full max-w-sm">
        <h1 className="text-2xl font-semibold tracking-[-0.01em]">{t('changePassword.title')}</h1>
        <p className="mt-1 text-sm text-muted">{t('changePassword.desc', { min: MIN_PASSWORD })}</p>
        <form onSubmit={(e) => void submit(e)} className="mt-6 grid gap-4 rounded-md border border-rule bg-surface p-5" noValidate>
          <Field label={t('changePassword.current')} htmlFor="cp-current" error={err.current}><Input id="cp-current" type="password" autoComplete="current-password" autoFocus value={v.current} aria-invalid={!!err.current} onChange={(e) => setV({ ...v, current: e.target.value })} /></Field>
          <Field label={t('account.password.next')} htmlFor="cp-next" error={err.next}><Input id="cp-next" type="password" autoComplete="new-password" value={v.next} aria-invalid={!!err.next} onChange={(e) => setV({ ...v, next: e.target.value })} /></Field>
          <Field label={t('account.password.again')} htmlFor="cp-again" error={err.again}><Input id="cp-again" type="password" autoComplete="new-password" value={v.again} aria-invalid={!!err.again} onChange={(e) => setV({ ...v, again: e.target.value })} /></Field>
          <Button type="submit" variant="primary" disabled={busy}>{t('changePassword.submit')}</Button>
          <Button onClick={() => void signOut()} disabled={busy}>{t('layout.logout', { ns: 'common' })}</Button>
        </form>
      </div>
    </main>
  )
}
