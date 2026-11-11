import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router'
import { useTranslation } from 'react-i18next'
import { useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '@/lib/api'
import { Loading } from '@/components/common/States'
import { takeSsoFlow } from './ssoFlow'

/**
 * D-194 (S-CORE-3): the identity provider sends the browser here with ?code&state (or ?error). The page posts them with the
 * binding this tab kept, and the box signs the person in. A link that someone else sent has no binding in this tab, so the box
 * refuses it (and writes the attempt to the audit log).
 */
export default function SsoCallbackPage() {
  const { t } = useTranslation('core')
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [error, setError] = useState<string | null>(null)
  const once = useRef(false)

  useEffect(() => {
    if (once.current) return // StrictMode runs effects twice; the code works only once
    once.current = true
    const flow = takeSsoFlow()
    const idpError = params.get('error')
    const code = params.get('code')
    const state = params.get('state')
    // The query string holds a one-time code: take it out of the address bar and history at once.
    navigate('/sso/callback', { replace: true })
    if (idpError) { setError(t('sso.idpError', { error: idpError.slice(0, 80) })); return }
    if (!code || !state) { setError(t('sso.missing')); return }
    api.post('/auth/oidc/callback', { code, state, binding: flow?.binding ?? '' })
      .then(async () => {
        qc.removeQueries({ queryKey: ['me'] })
        await qc.invalidateQueries()
        navigate(flow?.next ?? '/', { replace: true })
      })
      .catch((err: unknown) => setError(err instanceof ApiError ? err.message : t('common:error.unknown')))
  }, [params, navigate, qc, t])

  return (
    <main className="grid min-h-dvh place-items-center bg-paper px-4">
      <div className="w-full max-w-sm">
        <h1 className="text-2xl font-semibold tracking-[-0.01em]">{error ? t('sso.failed') : t('sso.title')}</h1>
        {error ? (
          <div className="mt-4 grid gap-4 rounded-md border border-rule bg-surface p-5">
            <p role="alert" className="text-sm">{error}</p>
            <Link to="/login" className="text-sm font-medium text-accent underline underline-offset-2">{t('sso.back')}</Link>
          </div>
        ) : (
          <div className="mt-4" role="status"><p className="mb-3 text-sm text-muted">{t('sso.working')}</p><Loading /></div>
        )}
      </div>
    </main>
  )
}
